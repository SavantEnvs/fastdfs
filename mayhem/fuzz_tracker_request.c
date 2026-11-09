/* Fuzzes the FastDFS tracker server's request dispatcher (tracker_deal_task) against the real
 * tracker state: storage joins, heartbeats, disk reports, sync negotiation, status changes, store /
 * fetch queries, group and storage listings, tracker-cluster commands, system-file transfer.
 *
 * Input: byte 0 picks the peer (a logged-in storage, a stranger, a tracker peer, ...); the rest is a
 * stream of requests, each a 10-byte TrackerHeader plus the body it announces, delivered on one
 * connection. Every input starts from the same tracker state (see tracker_env.h). */
#include "tracker_env.h"

static int env_ready;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    if (env_init() != 0) {
        abort();
    }
    env_ready = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    EnvConn conn;
    size_t offset = 1;

    if (size < 1 + sizeof(TrackerHeader)) {
        return -1;
    }
    if (!env_ready || env_reset() != 0) {
        abort();
    }
    env_open_connection(&conn, data[0]);
    while (!env.closed && size - offset >= sizeof(TrackerHeader)) {
        int64_t body_len = buff2long(((const TrackerHeader *)(data + offset))->pkg_len);
        size_t packet_len;

        if (body_len < 0 || (uint64_t)body_len > size - offset - sizeof(TrackerHeader)) {
            break;
        }
        packet_len = sizeof(TrackerHeader) + (size_t)body_len;
        if (env_dispatch(&conn, data + offset, packet_len) != 0) {
            break;
        }
        offset += packet_len;
    }
    env_conn_destroy(&conn);
    return 0;
}
