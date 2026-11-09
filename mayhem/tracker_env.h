/* In-process FastDFS tracker server: the request dispatcher (tracker_deal_task) with the real tracker
 * state (groups, storages, cluster list) and no sockets or threads. Shared by the fuzz harness and the
 * known-answer probe, so both drive the same code.
 *
 * tracker_service.c and tracker_mem.c are compiled into the including translation unit (and left out
 * of the link) because the dispatcher and the group/storage tables are file-static. Four names are
 * redefined before they are included:
 *   sf_send_add_event, sf_task_finish_clean_up  libserverframe's network send / close, which need a
 *                                               live event loop; here the response simply stays in
 *                                               the task's buffer and a close is recorded.
 *   sleep, usleep                               "delay before freeing memory a concurrent reader
 *                                               might still hold"; there are no readers here.
 *
 * Each input starts from the same state: the group tables are destroyed and rebuilt, a fixed set of
 * storages joins through the dispatcher, and every global the handlers write is restored. */
#ifndef MAYHEM_TRACKER_ENV_H
#define MAYHEM_TRACKER_ENV_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#define sf_send_add_event mayhem_sf_send_add_event
#define sf_task_finish_clean_up mayhem_sf_task_finish_clean_up
#define sleep(seconds) mayhem_no_sleep()
#define usleep(useconds) mayhem_no_sleep()
static inline int mayhem_no_sleep(void) { return 0; }

#include "quiet_log.h"
#include "fastcommon/local_ip_func.h"
#include "fastcommon/fast_task_queue.h"
#include "tracker_service.c"
#include "tracker_mem.c"

#define ENV_BUFF_SIZE (64 * 1024)
#define ENV_MAX_PKG_SIZE ENV_BUFF_SIZE
#define ENV_NOW 1700000000
#define ENV_TRACKER_PORT 22122
#define ENV_STORAGE_PORT 23000
#define ENV_STORE_PATHS 2
#define ENV_STORAGE_COUNT 3

static const char *const env_storage_ips[ENV_STORAGE_COUNT] = {
    "192.168.1.101", "192.168.1.102", "192.168.1.103"
};
static const char *const env_storage_groups[ENV_STORAGE_COUNT] = {
    "group1", "group1", "group2"
};

static struct {
    char root[128];
    int sock_fd;
    int mem_fd;
    int64_t changelog_size;
    TrackerClusterServer cluster[2];
    TrackerClusterServer cluster_initial[2];
    int cwd_fd;
    TrackerClusterServer *cluster_ptrs[2];
    TrackerClientInfo logged_in[ENV_STORAGE_COUNT];
    struct {
        TrackerClusterGroup servers;
        int next_leader_index;
        int trunk_server_chg_count;
        int tracker_leader_chg_count;
        int storage_stat_chg_count;
        int storage_sync_time_chg_count;
        bool if_leader_self;
        TrackerStatus last_status;
    } saved;
    int closed;
} env;

typedef struct {
    struct fast_task_info task;
    TrackerClientInfo client;
    char *buff;
} EnvConn;

/* The network handler every real task carries (task->handler->fh->ctx is libserverframe's SF_CTX):
 * only the buffer limits are read by the tracker, so that is all the fake context sets. */
static SFContext env_sf_ctx;
static SFAddressFamilyHandler env_sf_fh;
static SFNetworkHandler env_sf_handler;

int sf_send_add_event(struct fast_task_info *task)
{
    (void)task;
    return 0;
}

void sf_task_finish_clean_up(struct fast_task_info *task)
{
    (void)task;
    env.closed = 1;
}

static void env_conn_init(EnvConn *conn, const char *client_ip)
{
    memset(conn, 0, sizeof(*conn));
    conn->buff = (char *)malloc(ENV_BUFF_SIZE);
    if (conn->buff == NULL) {
        abort();
    }
    conn->task.recv.holder.data = conn->buff;
    conn->task.recv.holder.size = ENV_BUFF_SIZE;
    conn->task.recv.ptr = &conn->task.recv.holder;
    conn->task.send.ptr = conn->task.recv.ptr;
    conn->task.arg = &conn->client;
    conn->task.handler = &env_sf_handler;
    conn->task.event.fd = env.sock_fd;
    snprintf(conn->task.client_ip, sizeof(conn->task.client_ip), "%s", client_ip);
}

static void env_conn_destroy(EnvConn *conn)
{
    free(conn->buff);
    conn->buff = NULL;
}

/* One request: frame it the way the network layer does (length from the header, bounded by the
 * maximum package size), hand it to the dispatcher, and leave the response in the task's buffer.
 * Returns 0 if the request was dispatched, -1 if the framing layer would have dropped it. */
static int env_dispatch(EnvConn *conn, const uint8_t *packet, size_t size)
{
    struct fast_task_info *task = &conn->task;

    if (size < sizeof(TrackerHeader) || size > ENV_MAX_PKG_SIZE) {
        return -1;
    }
    memcpy(conn->buff, packet, size);
    if (fdfs_set_body_length(task) != 0) {
        return -1;
    }
    task->recv.ptr->length += sizeof(TrackerHeader);
    if (task->recv.ptr->length != (int)size) {
        return -1;
    }
    tracker_deal_task(task, 0);
    return 0;
}

static int env_request(EnvConn *conn, int cmd, const void *body, size_t body_len)
{
    uint8_t packet[ENV_MAX_PKG_SIZE];
    TrackerHeader *header = (TrackerHeader *)packet;

    memset(header, 0, sizeof(*header));
    long2buff((int64_t)body_len, header->pkg_len);
    header->cmd = (char)cmd;
    if (body_len > 0) {
        memcpy(packet + sizeof(*header), body, body_len);
    }
    if (env_dispatch(conn, packet, sizeof(*header) + body_len) != 0) {
        return -1;
    }
    return ((TrackerHeader *)conn->buff)->status;
}

static __attribute__((unused)) const char *env_response_body(const EnvConn *conn)
{
    return conn->buff + sizeof(TrackerHeader);
}

static __attribute__((unused)) int env_response_length(const EnvConn *conn)
{
    return conn->task.send.ptr->length - (int)sizeof(TrackerHeader);
}

static void env_join_body(char *body, int *body_len, const char *group, int port,
        const char *current_tracker_ip)
{
    TrackerStorageJoinBody *join = (TrackerStorageJoinBody *)body;
    char *lines = body + sizeof(*join);
    int line_len;

    memset(body, 0, sizeof(*join));
    snprintf(join->group_name, sizeof(join->group_name), "%s", group);
    long2buff(port, join->storage_port);
    long2buff(ENV_STORE_PATHS, join->store_path_count);
    long2buff(256, join->subdir_count_per_path);
    long2buff(10, join->upload_priority);
    long2buff(ENV_NOW - 1000, join->join_time);
    long2buff(ENV_NOW - 500, join->up_time);
    snprintf(join->version, sizeof(join->version), "6.15.1");
    join->init_flag = 0;
    join->status = FDFS_STORAGE_STATUS_ACTIVE;
    snprintf(join->current_tracker_ip, sizeof(join->current_tracker_ip), "%s",
            current_tracker_ip);
    long2buff(1, join->tracker_count);
    line_len = snprintf(lines, 64, "127.0.0.1:%d\n", ENV_TRACKER_PORT);
    *body_len = (int)sizeof(*join) + line_len;
}

static void env_df_body(char *body, int *body_len, int64_t total_mb, int64_t free_mb)
{
    int i;

    for (i = 0; i < ENV_STORE_PATHS; i++) {
        TrackerStatReportReqBody *path = (TrackerStatReportReqBody *)body + i;
        long2buff(total_mb, path->sz_total_mb);
        long2buff(free_mb - i * 1024, path->sz_free_mb);
    }
    *body_len = (int)sizeof(TrackerStatReportReqBody) * ENV_STORE_PATHS;
}

static void env_remove_data_files(void)
{
    static const char *const names[] = {
        STORAGE_GROUPS_LIST_FILENAME_NEW_STR, STORAGE_SERVERS_LIST_FILENAME_NEW_STR,
        STORAGE_SYNC_TIMESTAMP_FILENAME_STR, "storage_groups_new.dat.tmp",
        "storage_servers_new.dat.tmp", "storage_sync_timestamp.dat.tmp"
    };
    char path[256];
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(path, sizeof(path), "%s/data/%s", env.root, names[i]);
        unlink(path);
    }
}

/* tracker_mem_destroy_groups releases the storages of the groups in use but not the group records
 * themselves; free those here so a long fuzzing session does not grow. */
static void env_destroy_groups(void)
{
    FDFSGroupInfo **records;
    int alloc_size = g_groups.alloc_size;
    int i, j;

    if (g_groups.groups == NULL) {
        return;
    }
    records = (FDFSGroupInfo **)malloc(sizeof(FDFSGroupInfo *) * alloc_size);
    if (records == NULL) {
        abort();
    }
    memcpy(records, g_groups.groups, sizeof(FDFSGroupInfo *) * alloc_size);
    tracker_mem_destroy_groups(&g_groups, false);
    for (i = 0; i < alloc_size; i++) {
        for (j = 0; j < i && records[j] != records[i]; j++) {
        }
        if (j == i) {
            free(records[i]);
        }
    }
    free(records);
}

static void env_restore_globals(void)
{
    g_current_time = ENV_NOW;
    g_tracker_servers = env.saved.servers;
    memcpy(env.cluster, env.cluster_initial, sizeof(env.cluster));
    g_next_leader_index = env.saved.next_leader_index;
    g_trunk_server_chg_count = env.saved.trunk_server_chg_count;
    g_tracker_leader_chg_count = env.saved.tracker_leader_chg_count;
    g_storage_stat_chg_count = env.saved.storage_stat_chg_count;
    g_storage_sync_time_chg_count = env.saved.storage_sync_time_chg_count;
    g_if_leader_self = env.saved.if_leader_self;
    g_tracker_last_status = env.saved.last_status;
    g_changelog_fsize = env.changelog_size;
    need_get_sys_files = false;
    get_sys_files_done = true;
    lock_by_client = 0;
    g_local_host_ip_count = 0;
    insert_into_local_host_ip("127.0.0.1");
}

/* Brings the tracker to the fixed starting state: group1 with two active storages, group2 with one,
 * all reported through the dispatcher (join, heartbeat, disk usage). */
static int env_reset(void)
{
    char body[sizeof(TrackerStorageJoinBody) + 64];
    int body_len;
    int i;

    env_destroy_groups();
    env_remove_data_files();
    /* Drop what the previous input appended to the change log. */
    if (ftruncate(env.mem_fd, 0) != 0 || lseek(env.mem_fd, 0, SEEK_SET) != 0) {
        return -1;
    }
    /* tracker_load_data changes the working directory into the data directory. */
    if (tracker_mem_init_groups(&g_groups) != 0 || fchdir(env.cwd_fd) != 0) {
        return -1;
    }
    env_restore_globals();
    for (i = 0; i < ENV_STORAGE_COUNT; i++) {
        EnvConn conn;
        char df[sizeof(TrackerStatReportReqBody) * ENV_STORE_PATHS];

        env_conn_init(&conn, env_storage_ips[i]);
        env_join_body(body, &body_len, env_storage_groups[i], ENV_STORAGE_PORT, "127.0.0.1");
        if (env_request(&conn, TRACKER_PROTO_CMD_STORAGE_JOIN, body, body_len) != 0) {
            env_conn_destroy(&conn);
            return -1;
        }
        env_df_body(df, &body_len, 102400, 51200);
        env_request(&conn, TRACKER_PROTO_CMD_STORAGE_REPORT_DISK_USAGE, df, body_len);
        env_request(&conn, TRACKER_PROTO_CMD_STORAGE_BEAT, NULL, 0);
        env.logged_in[i] = conn.client;
        env_conn_destroy(&conn);
    }
    tracker_save_sys_files();
    env_restore_globals();
    return 0;
}

static void env_write_changelog(void)
{
    char path[256];
    static const char text[] =
        "1699999000 group1 192.168.1.101 7 \n"
        "1699999100 group1 192.168.1.102 6 \n"
        "1699999200 group2 192.168.1.103 7 \n";
    int fd;

    snprintf(path, sizeof(path), "%s/data/%s", env.root, STORAGE_SERVERS_CHANGELOG_FILENAME_STR);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || write(fd, text, sizeof(text) - 1) != (ssize_t)(sizeof(text) - 1)) {
        abort();
    }
    close(fd);
    env.changelog_size = (int64_t)(sizeof(text) - 1);
}

static void env_cleanup(void)
{
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", env.root);
    if (system(cmd) != 0) {
        return;
    }
}

/* One-time setup: scratch base path, global configuration the config loader would have set, the two
 * tracker servers (this one, and a peer), and the tracker memory module. */
static int env_init(void)
{
    const char *dir = access("/dev/shm", W_OK) == 0 ? "/dev/shm" : NULL;
    char path[256];
    int i;

    mayhem_quiet_log_init();
    env.cwd_fd = open(".", O_RDONLY | O_DIRECTORY);
    if (env.cwd_fd < 0) {
        return -1;
    }
    if (dir == NULL) {
        dir = getenv("TMPDIR");
        if (dir == NULL || *dir == '\0') {
            dir = "/tmp";
        }
    }
    snprintf(env.root, sizeof(env.root), "%s/fdfs-tracker-XXXXXX", dir);
    if (mkdtemp(env.root) == NULL) {
        return -1;
    }
    atexit(env_cleanup);
    snprintf(path, sizeof(path), "%s/data", env.root);
    if (mkdir(path, 0755) != 0) {
        return -1;
    }

    snprintf(SF_G_BASE_PATH_STR, sizeof(SF_G_BASE_PATH_STR), "%s", env.root);
    SF_G_BASE_PATH_LEN = (int)strlen(env.root);
    g_sf_global_vars.up_time = ENV_NOW - 3600;
    g_sf_global_vars.net_buffer_cfg.network_timeout = 30;
    SF_G_INNER_PORT = ENV_TRACKER_PORT;
    SF_G_OUTER_PORT = ENV_TRACKER_PORT;
    g_current_time = ENV_NOW;

    g_groups.store_lookup = FDFS_STORE_LOOKUP_ROUND_ROBIN;
    g_groups.store_server = FDFS_STORE_SERVER_ROUND_ROBIN;
    g_groups.download_server = FDFS_DOWNLOAD_SERVER_ROUND_ROBIN;
    g_groups.store_path = FDFS_STORE_PATH_ROUND_ROBIN;
    g_storage_reserved_space.flag = TRACKER_STORAGE_RESERVED_SPACE_FLAG_MB;
    g_storage_reserved_space.rs.mb = 1024;
    g_use_storage_id = false;
    g_if_use_trunk_file = false;
    g_if_static_tracker_servers = true;
    g_check_active_interval = 120;

    env_sf_ctx.net_buffer_cfg.max_buff_size = ENV_BUFF_SIZE;
    env_sf_ctx.net_buffer_cfg.max_pkg_size = ENV_MAX_PKG_SIZE;
    env_sf_ctx.net_buffer_cfg.network_timeout = 30;
    env_sf_ctx.header_size = (int)sizeof(TrackerHeader);
    env_sf_fh.ctx = &env_sf_ctx;
    env_sf_handler.fh = &env_sf_fh;

    env.sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (env.sock_fd < 0) {
        return -1;
    }

    memset(env.cluster, 0, sizeof(env.cluster));
    for (i = 0; i < 2; i++) {
        char address[64];
        snprintf(address, sizeof(address), "%s:%d", i == 0 ? "127.0.0.1" : "10.0.0.2",
                ENV_TRACKER_PORT);
        if (fdfs_parse_server_info_ex(address, ENV_TRACKER_PORT, &env.cluster[i].server,
                    false) != 0) {
            return -1;
        }
        env.cluster[i].up_time = ENV_NOW - 3600;
        snprintf(env.cluster[i].version, sizeof(env.cluster[i].version), "6.15.1");
        env.cluster_ptrs[i] = &env.cluster[i];
    }
    g_tracker_servers.server_count = 2;
    g_tracker_servers.servers = env.cluster_ptrs;
    g_tracker_servers.myself = &env.cluster[0];
    g_tracker_servers.leader = &env.cluster[1];
    g_if_leader_self = false;
    g_next_leader_index = -1;
    memcpy(env.cluster_initial, env.cluster, sizeof(env.cluster));
    env.saved.servers = g_tracker_servers;
    env.saved.next_leader_index = g_next_leader_index;
    env.saved.trunk_server_chg_count = g_trunk_server_chg_count;
    env.saved.tracker_leader_chg_count = g_tracker_leader_chg_count;
    env.saved.storage_stat_chg_count = g_storage_stat_chg_count;
    env.saved.storage_sync_time_chg_count = g_storage_sync_time_chg_count;
    env.saved.if_leader_self = g_if_leader_self;
    env.saved.last_status = g_tracker_last_status;

    env_write_changelog();
    if (init_pthread_lock(&mem_thread_lock) != 0 || init_pthread_lock(&mem_file_lock) != 0
            || init_pthread_lock(&lb_thread_lock) != 0) {
        return -1;
    }
    /* Appends to the change log go to a memory file so a request cannot grow the on-disk one. */
    env.mem_fd = memfd_create("fdfs-changelog", 0);
    if (env.mem_fd < 0) {
        return -1;
    }
    changelog_fd = env.mem_fd;
    return env_reset();
}

/* Per-input connection: byte 0 picks who is talking, from a storage already logged in to a stranger. */
static void env_open_connection(EnvConn *conn, uint8_t selector)
{
    static const char *const strangers[] = {
        "192.168.1.101", "10.0.0.2", "203.0.113.9", "192.168.1.150", "127.0.0.1"
    };
    unsigned which = selector & 7;

    env.closed = 0;
    if (which < ENV_STORAGE_COUNT) {
        env_conn_init(conn, env_storage_ips[which]);
        conn->client = env.logged_in[which];
    } else {
        env_conn_init(conn, strangers[which - ENV_STORAGE_COUNT]);
    }
}

#endif
