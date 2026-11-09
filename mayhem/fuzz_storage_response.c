/* Fuzzes the FastDFS storage client's response parsers (download, metadata, upload, file-info, ...).
 * The harness frames a storage response header around the fuzz bytes and pre-loads it into a
 * socketpair; the real client API then reads and decodes it. Input: byte 0 selects the client call,
 * byte 1 the response status, the rest is the response body. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "quiet_log.h"
#include "storage_client.h"
#include "mock_conn.h"

#define GROUP "group1"
#define FILENAME "M00/00/00/wKgBZVbN3QSAH8woAAAAFAMbhGU825.txt"
#define APPENDER "M00/00/00/wKgBZVbN3QSAH8woAAAAFAMbhGU826.txt"

static int sink_callback(void *arg, const int64_t file_size,
        const char *data, const int current_size)
{
    volatile char first;
    (void)arg;
    (void)file_size;
    if (current_size > 0) {
        first = data[current_size - 1];
        (void)first;
    }
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
    ConnectionInfo tracker;
    ConnectionInfo storage;
    MockPeer peer;
    int status;
    char group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
    char remote_filename[256];

    if (size < 2) {
        return -1;
    }
    status = ((data[1] & 7) == 7) ? (data[1] >> 3) : 0;
    if (mock_conn_open(&storage, &peer, data + 2, size - 2, status) != 0) {
        return -1;
    }
    mock_conn_init_closed(&tracker);
    group_name[0] = '\0';
    remote_filename[0] = '\0';

    switch (data[0] % 13) {
    case 0: {
        FDFSMetaData *meta_list = NULL;
        int meta_count = 0;
        storage_get_metadata(&tracker, &storage, GROUP, FILENAME,
                &meta_list, &meta_count);
        free(meta_list);
        break;
    }
    case 1: {
        FDFSFileInfo info;
        memset(&info, 0, sizeof(info));
        storage_query_file_info_ex(&tracker, &storage, GROUP, FILENAME,
                &info, FDFS_QUERY_FINFO_FLAGS_NOT_CALC_CRC32);
        break;
    }
    case 2: {
        char *buff = NULL;
        int64_t file_size = 0;
        storage_download_file_to_buff(&tracker, &storage, GROUP, FILENAME,
                &buff, &file_size);
        free(buff);
        break;
    }
    case 3: {
        int64_t file_size = 0;
        char *callback_holder = (char *)sink_callback;
        storage_do_download_file_ex(&tracker, &storage,
                FDFS_DOWNLOAD_TO_CALLBACK, GROUP, FILENAME, 0, 0,
                &callback_holder, NULL, &file_size);
        break;
    }
    case 4: {
        static const char content[] = "mayhem upload content";
        storage_upload_by_filebuff(&tracker, &storage, 0, content,
                sizeof(content) - 1, "txt", NULL, 0, group_name,
                remote_filename);
        break;
    }
    case 5: {
        static const char content[] = "mayhem appender content";
        storage_upload_appender_by_filebuff(&tracker, &storage, 0, content,
                sizeof(content) - 1, "txt", NULL, 0, group_name,
                remote_filename);
        break;
    }
    case 6: {
        static const char content[] = "mayhem slave content";
        strcpy(group_name, GROUP);
        storage_upload_slave_by_filebuff(&tracker, &storage, content,
                sizeof(content) - 1, FILENAME, "-m", "txt", NULL, 0,
                group_name, remote_filename);
        break;
    }
    case 7:
        storage_append_by_filebuff(&tracker, &storage, "tail", 4, GROUP,
                APPENDER);
        break;
    case 8:
        storage_truncate_file(&tracker, &storage, GROUP, APPENDER, 3);
        break;
    case 9:
        storage_delete_file(&tracker, &storage, GROUP, FILENAME);
        break;
    case 10: {
        char new_group[FDFS_GROUP_NAME_MAX_LEN + 1];
        char new_filename[256];
        new_group[0] = '\0';
        new_filename[0] = '\0';
        storage_regenerate_appender_filename(&tracker, &storage, GROUP,
                APPENDER, new_group, new_filename);
        break;
    }
    case 11: {
        FDFSMetaData meta;
        memset(&meta, 0, sizeof(meta));
        strcpy(meta.name, "width");
        strcpy(meta.value, "1024");
        storage_set_metadata(&tracker, &storage, GROUP, FILENAME, &meta, 1,
                STORAGE_SET_METADATA_FLAG_OVERWRITE);
        break;
    }
    default:
        storage_file_exist(&tracker, &storage, GROUP, FILENAME);
        break;
    }

    mock_conn_close(&storage, &peer);
    return 0;
}
