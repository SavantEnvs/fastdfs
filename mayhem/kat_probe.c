/* Known-answer probe for mayhem/test.sh: runs fixed inputs through real FastDFS client-library code
 * (file-id decoding, slave filename generation, anti-steal token, tracker/storage response parsing
 * over a socketpair, mime-types / storage-ids / server-address parsing) and prints the decoded values
 * for the test to compare against independently computed expectations. Built with normal flags. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "quiet_log.h"
#include "fdfs_global.h"
#include "fdfs_http_shared.h"
#include "mime_file_parser.h"
#include "fdfs_server_id_func.h"
#include "fdfs_shared_func.h"
#include "tracker_client.h"
#include "storage_client.h"
#include "storage_client1.h"
#include "mock_conn.h"

#define FILE_ID "group1/M00/00/00/wKgBZWVT8QAAAAAAAAAEABorPE0123.jpg"
#define REMOTE_NAME "M00/00/00/wKgBZWVT8QAAAAAAAAAEABorPE0123.jpg"

static void pack_long(char *dest, int64_t value)
{
    long2buff(value, dest);
}

int main(void)
{
    FDFSFileInfo info;
    int rc;

    mayhem_quiet_log_init();
    rc = fdfs_get_file_info_ex1(FILE_ID, false, &info, 0);
    printf("file_info rc=%d ip=%s ts=%ld size=%lld crc=%x type=%d\n", rc,
            info.source_ip_addr, (long)info.create_timestamp,
            (long long)info.file_size, (unsigned)info.crc32, info.file_type);

    {
        char out[128];
        int out_len = 0;
        rc = fdfs_gen_slave_filename(REMOTE_NAME, "-150x150", "png", out, &out_len);
        printf("slave rc=%d len=%d name=%s\n", rc, out_len, out);
    }

    printf("check_filename good=%d lowercase=%d nested=%d short=%d\n",
            fdfs_check_data_filename("1A/FF/wKgBZWVT8QAAAAAAAAAEABorPE0123.jpg", 38),
            fdfs_check_data_filename("1a/FF/wKgBZWVT8QAAAAAAAAAEABorPE0123.jpg", 38),
            fdfs_check_data_filename("1A/FF/dir/file.jpg", 18),
            fdfs_check_data_filename("1A/FF", 5));

    {
        BufferInfo secret;
        char token[64] = "";
        char secret_text[] = "secret";
        secret.buff = secret_text;
        secret.length = 6;
        rc = fdfs_http_gen_token(&secret, REMOTE_NAME, 1700000000, token);
        printf("token rc=%d value=%s check_ok=%d check_bad=%d\n", rc, token,
                fdfs_http_check_token(&secret, REMOTE_NAME, 1700000000, token, 2000000000),
                fdfs_http_check_token(&secret, REMOTE_NAME, 1700000000,
                    "00000000000000000000000000000000", 2000000000));
    }

    {
        ConnectionInfo tracker;
        MockPeer peer;
        TrackerGroupStat body[2];
        FDFSGroupStat groups[4];
        int count = -1;

        memset(body, 0, sizeof(body));
        strcpy(body[0].group_name, "group1");
        pack_long(body[0].sz_total_mb, 102400);
        pack_long(body[0].sz_free_mb, 51200);
        pack_long(body[0].sz_storage_count, 3);
        pack_long(body[0].sz_storage_port, 23000);
        strcpy(body[1].group_name, "group2");
        pack_long(body[1].sz_total_mb, 2048);
        pack_long(body[1].sz_free_mb, 1024);
        pack_long(body[1].sz_storage_count, 1);
        pack_long(body[1].sz_storage_port, 23001);

        memset(groups, 0, sizeof(groups));
        mock_conn_open(&tracker, &peer, (const uint8_t *)body, sizeof(body), 0);
        rc = tracker_list_groups(&tracker, groups, 4, &count);
        mock_conn_close(&tracker, &peer);
        printf("list_groups rc=%d count=%d g0=%s:%lld:%lld:%d:%d g1=%s:%lld:%lld:%d:%d\n",
                rc, count,
                groups[0].group_name, (long long)groups[0].total_mb,
                (long long)groups[0].free_mb, groups[0].storage_count, groups[0].storage_port,
                groups[1].group_name, (long long)groups[1].total_mb,
                (long long)groups[1].free_mb, groups[1].storage_count, groups[1].storage_port);
    }

    {
        ConnectionInfo tracker, storage;
        MockPeer peer;
        static const char meta_body[] = "width\x02" "1024\x01" "height\x02" "768";
        FDFSMetaData *meta_list = NULL;
        int meta_count = 0;

        mock_conn_init_closed(&tracker);
        mock_conn_open(&storage, &peer, (const uint8_t *)meta_body, sizeof(meta_body) - 1, 0);
        rc = storage_get_metadata(&tracker, &storage, "group1", REMOTE_NAME, &meta_list, &meta_count);
        mock_conn_close(&storage, &peer);
        printf("metadata rc=%d count=%d m0=%s=%s m1=%s=%s\n", rc, meta_count,
                meta_count > 0 ? meta_list[0].name : "", meta_count > 0 ? meta_list[0].value : "",
                meta_count > 1 ? meta_list[1].name : "", meta_count > 1 ? meta_list[1].value : "");
        free(meta_list);
    }

    {
        ConnectionInfo tracker, storage;
        MockPeer peer;
        char *buff = NULL;
        int64_t file_size = 0;

        mock_conn_init_closed(&tracker);
        mock_conn_open(&storage, &peer, (const uint8_t *)"hello fastdfs", 13, 0);
        rc = storage_download_file_to_buff(&tracker, &storage, "group1", REMOTE_NAME, &buff, &file_size);
        mock_conn_close(&storage, &peer);
        printf("download rc=%d size=%lld data=%.*s\n", rc, (long long)file_size,
                buff != NULL ? (int)file_size : 0, buff != NULL ? buff : "");
        free(buff);

        mock_conn_open(&storage, &peer, (const uint8_t *)"", 0, 2);
        rc = storage_file_exist(&tracker, &storage, "group1", REMOTE_NAME);
        mock_conn_close(&storage, &peer);
        printf("file_exist_status2 rc=%d\n", rc);
    }

    {
        char path[] = "/tmp/fdfs-kat-XXXXXX";
        int fd = mkstemp(path);
        static const char mime[] = "# comment\ntext/html html htm\nimage/png png\n";
        FDFSHTTPParams params;
        char content_type[64];

        memset(&params, 0, sizeof(params));
        snprintf(params.default_content_type, sizeof(params.default_content_type), "x/default");
        if (fd >= 0) {
            (void)!write(fd, mime, sizeof(mime) - 1);
            close(fd);
        }
        rc = load_mime_types_from_file(&params.content_type_hash, path);
        fdfs_http_get_content_type_by_extname(&params, "htm", 3, content_type, sizeof(content_type));
        printf("mime rc=%d htm=%s", rc, content_type);
        fdfs_http_get_content_type_by_extname(&params, "png", 3, content_type, sizeof(content_type));
        printf(" png=%s", content_type);
        fdfs_http_get_content_type_by_extname(&params, "zzz", 3, content_type, sizeof(content_type));
        printf(" zzz=%s\n", content_type);
        unlink(path);
    }

    {
        char ids[] = "100001 group1 192.168.1.101\n100002 group1 192.168.1.102:23001\n";
        FDFSStorageIdInfo *item;

        rc = fdfs_load_storage_ids(ids, "kat");
        item = fdfs_get_storage_by_id("100002");
        printf("storage_ids rc=%d count=%d id2=%s group=%s\n", rc, g_storage_ids_by_id.count,
                item != NULL ? item->ip_addrs.ips[0].address : "none",
                item != NULL ? item->group_name : "none");
    }

    {
        TrackerServerInfo server;
        char text[] = "192.168.1.5:23000";
        memset(&server, 0, sizeof(server));
        rc = fdfs_parse_server_info_ex(text, 22122, &server, false);
        printf("server_info rc=%d count=%d ip=%s port=%d\n", rc, server.count,
                server.connections[0].ip_addr, server.connections[0].port);
    }
    return 0;
}
