/* Fuzzes the FastDFS tracker client's response parsers. The harness frames a tracker response header
 * around the fuzz bytes and pre-loads it into a socketpair; the real client API then reads and decodes
 * it. Input: byte 0 selects the client call, byte 1 the response status, the rest is the response body. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "quiet_log.h"
#include "tracker_client.h"
#include "mock_conn.h"

#define MAX_ITEMS 8

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
    MockPeer peer;
    int status;

    if (size < 2) {
        return -1;
    }
    status = ((data[1] & 7) == 7) ? (data[1] >> 3) : 0;
    if (mock_conn_open(&tracker, &peer, data + 2, size - 2, status) != 0) {
        return -1;
    }

    switch (data[0] % 14) {
    case 0: {
        FDFSGroupStat groups[MAX_ITEMS];
        int count = 0;
        tracker_list_groups(&tracker, groups, MAX_ITEMS, &count);
        break;
    }
    case 1: {
        FDFSGroupStat group;
        tracker_list_one_group(&tracker, "group1", &group);
        break;
    }
    case 2: {
        FDFSStorageInfo storages[MAX_ITEMS];
        int count = 0;
        tracker_list_servers(&tracker, "group1", NULL, storages, MAX_ITEMS, &count);
        break;
    }
    case 3: {
        char ip[64];
        int port = 0;
        tracker_get_leader(&tracker, ip, sizeof(ip), &port);
        break;
    }
    case 4: {
        TrackerStatFilter filter;
        FDFSTrackerStat trackers[MAX_ITEMS];
        int count = 0;
        memset(&filter, 0, sizeof(filter));
        tracker_cluster_stat(&tracker, &filter, trackers, MAX_ITEMS, &count);
        break;
    }
    case 5: {
        StorageStatFilter filter;
        FDFSStorageClusterStat storages[MAX_ITEMS];
        bool use_id = false, use_trunk = false;
        int count = 0;
        memset(&filter, 0, sizeof(filter));
        storage_cluster_stat(&tracker, &filter, &use_id, &use_trunk,
                storages, MAX_ITEMS, &count);
        break;
    }
    case 6: {
        VolumnStatFilter filter;
        FDFSStorageVolumnStat volumns[MAX_ITEMS];
        bool use_trunk = false;
        int count = 0;
        memset(&filter, 0, sizeof(filter));
        storage_volumn_stat(&tracker, &filter, &use_trunk, volumns,
                MAX_ITEMS, &count);
        break;
    }
    case 7: {
        ConnectionInfo storage;
        char group_name[FDFS_GROUP_NAME_MAX_LEN + 1];
        int path_index = 0;
        memset(&storage, 0, sizeof(storage));
        group_name[0] = '\0';
        tracker_query_storage_store_without_group(&tracker, &storage,
                group_name, &path_index);
        break;
    }
    case 8: {
        ConnectionInfo storage;
        int path_index = 0;
        memset(&storage, 0, sizeof(storage));
        tracker_query_storage_store_with_group(&tracker, "group1",
                &storage, &path_index);
        break;
    }
    case 9: {
        ConnectionInfo storages[MAX_ITEMS];
        int count = 0, path_index = 0;
        memset(storages, 0, sizeof(storages));
        tracker_query_storage_store_list_with_group(&tracker, "group1",
                storages, MAX_ITEMS, &count, &path_index);
        break;
    }
    case 10: {
        ConnectionInfo storage;
        memset(&storage, 0, sizeof(storage));
        tracker_query_storage_fetch(&tracker, &storage, "group1",
                "M00/00/00/wKgBZVbN3QSAH8woAAAAFAMbhGU825.txt");
        break;
    }
    case 11: {
        ConnectionInfo storages[MAX_ITEMS];
        char group_name[FDFS_GROUP_NAME_MAX_LEN + 1] = "group1";
        int count = 0;
        memset(storages, 0, sizeof(storages));
        tracker_query_storage_list(&tracker, storages, MAX_ITEMS, &count,
                group_name, "M00/00/00/wKgBZVbN3QSAH8woAAAAFAMbhGU825.txt");
        break;
    }
    case 12: {
        FDFSStorageBrief brief;
        memset(&brief, 0, sizeof(brief));
        tracker_get_storage_status(&tracker, "group1", "192.168.1.101",
                23000, &brief);
        break;
    }
    default: {
        char storage_id[FDFS_STORAGE_ID_MAX_SIZE];
        memset(storage_id, 0, sizeof(storage_id));
        tracker_get_storage_id(&tracker, "group1", "192.168.1.101",
                23000, storage_id);
        break;
    }
    }

    mock_conn_close(&tracker, &peer);
    return 0;
}
