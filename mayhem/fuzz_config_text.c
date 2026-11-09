/* Fuzzes FastDFS's text-format parsers: the storage-ids file, the HTTP mime-types file, and the
 * "host:port" / multi-IP server address strings used in tracker/storage configuration.
 * Input: byte 0 selects the parser, the rest is the text to parse. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "quiet_log.h"
#include <unistd.h>
#include "fdfs_http_shared.h"
#include "mime_file_parser.h"
#include "fdfs_server_id_func.h"
#include "fdfs_shared_func.h"
/* Compiled into this translation unit (and left out of the link) so the file-static
 * g_storage_ids_by_ip_port, which fdfs_load_storage_ids fills, can be reset between inputs. */
#include "fdfs_server_id_func.c"

#define MAX_TEXT 4096

static void free_storage_ids(void)
{
    free(g_storage_ids_by_id.ids);
    g_storage_ids_by_id.ids = NULL;
    g_storage_ids_by_id.count = 0;
    free(g_storage_ids_by_ip.maps);
    g_storage_ids_by_ip.maps = NULL;
    g_storage_ids_by_ip.count = 0;
    free(g_storage_ids_by_ip_port.maps);
    g_storage_ids_by_ip_port.maps = NULL;
    g_storage_ids_by_ip_port.count = 0;
}

static int write_temp_file(char *path, size_t path_size, const uint8_t *data, size_t size)
{
    const char *tmpdir = getenv("TMPDIR");
    int fd;

    snprintf(path, path_size, "%s/fdfs-mime-XXXXXX",
            (tmpdir != NULL && *tmpdir != '\0') ? tmpdir : "/tmp");
    fd = mkstemp(path);
    if (fd < 0) {
        return -1;
    }
    if (size > 0 && write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);
    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    mayhem_quiet_log_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char text[MAX_TEXT + 1];
    size_t len;

    if (size < 1 || size > MAX_TEXT) {
        return -1;
    }
    len = size - 1;
    memcpy(text, data + 1, len);
    text[len] = '\0';

    switch (data[0] & 3) {
    case 0:
        if (fdfs_load_storage_ids(text, "storage_ids.conf") == 0) {
            fdfs_get_storage_by_id("100001");
            fdfs_get_storage_id_by_ip_port("192.168.1.101", 23000);
        }
        free_storage_ids();
        break;
    case 1: {
        char path[256];
        FDFSHTTPParams params;
        char content_type[64];

        if (write_temp_file(path, sizeof(path), data + 1, len) != 0) {
            return -1;
        }
        memset(&params, 0, sizeof(params));
        snprintf(params.default_content_type, sizeof(params.default_content_type),
                "application/octet-stream");
        if (load_mime_types_from_file(&params.content_type_hash, path) == 0) {
            fdfs_http_get_content_type_by_extname(&params, "jpg", 3,
                    content_type, sizeof(content_type));
            fdfs_http_get_content_type_by_extname(&params, "html", 4,
                    content_type, sizeof(content_type));
        }
        fc_hash_destroy(&params.content_type_hash);
        unlink(path);
        break;
    }
    case 2: {
        TrackerServerInfo server;
        char buff[256];
        memset(&server, 0, sizeof(server));
        if (fdfs_parse_server_info_ex(text, 22122, &server, false) == 0) {
            fdfs_server_info_to_string(&server, buff, sizeof(buff));
        }
        break;
    }
    default: {
        FDFSMultiIP ips;
        char error_info[128];
        char buff[256];
        memset(&ips, 0, sizeof(ips));
        if (fdfs_parse_multi_ips_ex(text, &ips, error_info, sizeof(error_info), false) == 0) {
            fdfs_multi_ips_to_string(&ips, buff, sizeof(buff));
        }
        break;
    }
    }
    return 0;
}
