/* In-process mock of a tracker/storage peer: the response (header + body) is pre-loaded into a
 * socketpair, so the real client code reads it exactly as it would off the network. */
#ifndef MAYHEM_MOCK_CONN_H
#define MAYHEM_MOCK_CONN_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "fastcommon/connection_pool.h"
#include "fastcommon/shared_func.h"
#include "tracker_proto.h"

#define MOCK_MAX_BODY 60000

typedef struct {
    int peer_fd;
} MockPeer;

/* Returns 0 and fills *conn (connected to the mock peer), or -1 when the body is too large. */
static inline int mock_conn_open(ConnectionInfo *conn, MockPeer *peer,
        const uint8_t *body, size_t body_len, int status)
{
    int sv[2];
    TrackerHeader header;

    if (body_len > MOCK_MAX_BODY) {
        return -1;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        abort();
    }

    memset(&header, 0, sizeof(header));
    long2buff((int64_t)body_len, header.pkg_len);
    header.cmd = TRACKER_PROTO_CMD_RESP;
    header.status = (char)status;
    if (write(sv[1], &header, sizeof(header)) != (ssize_t)sizeof(header)) {
        abort();
    }
    if (body_len > 0 && write(sv[1], body, body_len) != (ssize_t)body_len) {
        abort();
    }
    shutdown(sv[1], SHUT_WR);

    memset(conn, 0, sizeof(*conn));
    conn->sock = sv[0];
    conn->port = 22122;
    snprintf(conn->ip_addr, sizeof(conn->ip_addr), "127.0.0.1");
    peer->peer_fd = sv[1];
    return 0;
}

static inline void mock_conn_close(ConnectionInfo *conn, MockPeer *peer)
{
    close(conn->sock);
    close(peer->peer_fd);
    conn->sock = -1;
}

static inline void mock_conn_init_closed(ConnectionInfo *conn)
{
    memset(conn, 0, sizeof(*conn));
    conn->sock = -1;
    snprintf(conn->ip_addr, sizeof(conn->ip_addr), "127.0.0.1");
    conn->port = 22122;
}

#endif
