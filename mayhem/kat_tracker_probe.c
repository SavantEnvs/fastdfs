/* Known-answer probe for the tracker server, run by mayhem/test.sh. It sets up the same in-process
 * tracker as the fuzz target (tracker_env.h: group1 with storages .101/.102, group2 with .103, every
 * one joined, reporting disk usage and heartbeating through the dispatcher), sends real requests,
 * and prints the decoded responses for the test to compare with expectations worked out from what
 * was reported. Built with normal flags. */
#include "tracker_env.h"

static void connect_as(EnvConn *conn, const char *ip)
{
    env.closed = 0;
    env_conn_init(conn, ip);
}

static void pack_group(char *dest, const char *group)
{
    memset(dest, 0, FDFS_GROUP_NAME_MAX_LEN);
    memcpy(dest, group, strlen(group));
}

int main(void)
{
    EnvConn peer;
    EnvConn storage;
    char body[512];
    int rc;

    if (env_init() != 0) {
        puts("env_init failed");
        return 1;
    }

    connect_as(&peer, "198.51.100.7");
    rc = env_request(&peer, FDFS_PROTO_CMD_ACTIVE_TEST, NULL, 0);
    printf("tracker_active_test rc=%d cmd=%d len=%d\n", rc,
            ((TrackerHeader *)peer.buff)->cmd, env_response_length(&peer));

    rc = env_request(&peer, TRACKER_PROTO_CMD_SERVER_LIST_ALL_GROUPS, NULL, 0);
    {
        const TrackerGroupStat *g = (const TrackerGroupStat *)env_response_body(&peer);
        int count = env_response_length(&peer) / (int)sizeof(TrackerGroupStat);

        printf("tracker_list_groups rc=%d count=%d", rc, count);
        for (int i = 0; i < count; i++) {
            printf(" g%d=%s:%lld:%lld:%lld:%lld:%lld", i, g[i].group_name,
                    (long long)buff2long(g[i].sz_total_mb), (long long)buff2long(g[i].sz_free_mb),
                    (long long)buff2long(g[i].sz_storage_count),
                    (long long)buff2long(g[i].sz_writable_server_count),
                    (long long)buff2long(g[i].sz_storage_port));
        }
        printf("\n");
    }

    pack_group(body, "group1");
    rc = env_request(&peer, TRACKER_PROTO_CMD_SERVER_LIST_STORAGE, body, FDFS_GROUP_NAME_MAX_LEN);
    {
        const TrackerStorageStatIPv6 *s = (const TrackerStorageStatIPv6 *)env_response_body(&peer);
        int count = env_response_length(&peer) / (int)sizeof(TrackerStorageStatIPv6);

        printf("tracker_list_storage rc=%d count=%d", rc, count);
        for (int i = 0; i < count; i++) {
            printf(" s%d=%s:%d:%lld:%lld", i, s[i].ip_addr, s[i].status,
                    (long long)buff2long(s[i].sz_total_mb), (long long)buff2long(s[i].sz_free_mb));
        }
        printf("\n");
    }

    pack_group(body, "group2");
    rc = env_request(&peer, TRACKER_PROTO_CMD_SERVICE_QUERY_STORE_WITH_GROUP_ONE, body,
            FDFS_GROUP_NAME_MAX_LEN);
    {
        const char *r = env_response_body(&peer);
        printf("tracker_query_store rc=%d group=%s ip=%s port=%lld path=%d\n", rc, r,
                r + FDFS_GROUP_NAME_MAX_LEN,
                (long long)buff2long(r + FDFS_GROUP_NAME_MAX_LEN + IPV6_ADDRESS_SIZE - 1),
                r[FDFS_GROUP_NAME_MAX_LEN + IPV6_ADDRESS_SIZE - 1 + FDFS_PROTO_PKG_LEN_SIZE]);
    }

    pack_group(body, "group1");
    strcpy(body + FDFS_GROUP_NAME_MAX_LEN, "M00/00/00/wKgBZWVT8QAAAAAAAAAEABorPE0123.jpg");
    rc = env_request(&peer, TRACKER_PROTO_CMD_SERVICE_QUERY_FETCH_ONE, body,
            FDFS_GROUP_NAME_MAX_LEN + 43);
    {
        const char *r = env_response_body(&peer);
        printf("tracker_query_fetch rc=%d group=%s ip=%s port=%lld\n", rc, r,
                r + FDFS_GROUP_NAME_MAX_LEN,
                (long long)buff2long(r + FDFS_GROUP_NAME_MAX_LEN + IPV6_ADDRESS_SIZE - 1));
    }

    /* The statistics handlers read the connection's network context (buffer limit); a task without a
     * handler would crash them. Storage cluster stat: unfiltered, status = ACTIVE, status != ACTIVE. */
    {
        StorageStatFilter filter;
        const StorageClusterStatRespHeader *h;
        const StorageClusterStatRespBodyPart *part;
        int total, active, not_active;

        memset(&filter, 0, sizeof(filter));
        rc = env_request(&peer, TRACKER_PROTO_CMD_SERVER_STORAGE_CLUSTER_STAT, &filter,
                sizeof(filter));
        h = (const StorageClusterStatRespHeader *)env_response_body(&peer);
        part = (const StorageClusterStatRespBodyPart *)(h + 1);
        total = buff2int(h->count);
        printf("tracker_cluster_stat rc=%d count=%d first=%s:%s:%d", rc, total, part[0].id,
                part[0].host, part[0].status);
        filter.filter_by = FDFS_STORAGE_STAT_FILTER_BY_STATUS;
        filter.op_type = '=';
        filter.status = FDFS_STORAGE_STATUS_ACTIVE;
        env_request(&peer, TRACKER_PROTO_CMD_SERVER_STORAGE_CLUSTER_STAT, &filter, sizeof(filter));
        active = buff2int(((const StorageClusterStatRespHeader *)env_response_body(&peer))->count);
        filter.op_type = '!';
        env_request(&peer, TRACKER_PROTO_CMD_SERVER_STORAGE_CLUSTER_STAT, &filter, sizeof(filter));
        not_active = buff2int(
                ((const StorageClusterStatRespHeader *)env_response_body(&peer))->count);
        printf(" active=%d not_active=%d\n", active, not_active);
    }

    /* Per-group volume statistics: disk reserved space is the configured 1024 MB. */
    {
        VolumnStatFilter filter;
        const StorageVolumnStatRespHeader *h;
        const StorageVolumnStatRespBodyPart *part;
        int count;

        memset(&filter, 0, sizeof(filter));
        rc = env_request(&peer, TRACKER_PROTO_CMD_SERVER_STORAGE_VOLUMN_STAT, &filter,
                sizeof(filter));
        h = (const StorageVolumnStatRespHeader *)env_response_body(&peer);
        part = (const StorageVolumnStatRespBodyPart *)(h + 1);
        count = buff2int(h->count);
        printf("tracker_volumn_stat rc=%d count=%d", rc, count);
        for (int i = 0; i < count; i++) {
            printf(" v%d=%s:%lld:%lld:%lld:%lld:%d", i, part[i].group_name,
                    (long long)buff2long(part[i].sz_total_mb),
                    (long long)buff2long(part[i].sz_free_mb),
                    (long long)buff2long(part[i].sz_reserved_mb),
                    (long long)buff2long(part[i].sz_avail_mb), part[i].is_disk_available);
        }
        printf("\n");
    }

    pack_group(body, "nogroup");
    rc = env_request(&peer, TRACKER_PROTO_CMD_SERVER_LIST_ONE_GROUP, body, FDFS_GROUP_NAME_MAX_LEN);
    printf("tracker_errors list_missing=%d", rc);
    rc = env_request(&peer, TRACKER_PROTO_CMD_STORAGE_BEAT, NULL, 0);
    printf(" beat_not_joined=%d", rc);
    rc = env_request(&peer, 99, NULL, 0);
    printf(" unknown_cmd=%d", rc);
    pack_group(body, "group2");
    rc = env_request(&peer, TRACKER_PROTO_CMD_SERVER_DELETE_GROUP, body, FDFS_GROUP_NAME_MAX_LEN);
    printf(" delete_group_stranger=%d\n", rc);

    /* A new storage joins group3; the group and its storage become visible, with status ONLINE until
     * its first heartbeat. */
    connect_as(&storage, "192.168.1.150");
    {
        int len;
        const TrackerStorageJoinBodyResp *resp;

        env_join_body(body, &len, "group3", 23100, "127.0.0.1");
        rc = env_request(&storage, TRACKER_PROTO_CMD_STORAGE_JOIN, body, len);
        resp = (const TrackerStorageJoinBodyResp *)env_response_body(&storage);
        printf("tracker_join rc=%d my_status=%d resp_len=%d", rc, resp->my_status,
                env_response_length(&storage));
    }
    rc = env_request(&peer, TRACKER_PROTO_CMD_SERVER_LIST_ALL_GROUPS, NULL, 0);
    printf(" groups_after=%d", env_response_length(&peer) / (int)sizeof(TrackerGroupStat));
    rc = env_request(&storage, TRACKER_PROTO_CMD_STORAGE_BEAT, NULL, 0);
    printf(" beat=%d\n", rc);

    /* The next input starts from the original state: group3 is gone. */
    env_conn_destroy(&storage);
    if (env_reset() != 0) {
        puts("env_reset failed");
        return 1;
    }
    rc = env_request(&peer, TRACKER_PROTO_CMD_SERVER_LIST_ALL_GROUPS, NULL, 0);
    printf("tracker_reset rc=%d groups=%d\n", rc,
            env_response_length(&peer) / (int)sizeof(TrackerGroupStat));

    /* Logged-in storage: a storage's own change log request returns the fixed log content. */
    env_open_connection(&storage, 0);
    rc = env_request(&storage, TRACKER_PROTO_CMD_STORAGE_CHANGELOG_REQ, NULL, 0);
    printf("tracker_changelog rc=%d len=%d first=%.33s\n", rc, env_response_length(&storage),
            env_response_body(&storage));
    env_conn_destroy(&storage);
    env_conn_destroy(&peer);
    return 0;
}
