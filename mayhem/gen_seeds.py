#!/usr/bin/env python3
"""Regenerates the starter seeds under mayhem/<target>/testsuite/ (deterministic; run from the repo root)."""
import base64
import os
import struct

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)))


def put(target, name, data):
    d = os.path.join(ROOT, target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def file_name(ip, ts, size, crc, rnd="123", ext="jpg"):
    raw = struct.pack(">IIQI", ip, ts, size, crc)
    return "M00/00/00/" + base64.urlsafe_b64encode(raw).decode().rstrip("=") + rnd + "." + ext


IP = (192 << 24) | (168 << 16) | (1 << 8) | 101
NORMAL = file_name(IP, 1700000000, 1024, 0x1A2B3C4D)
HIGHBIT = file_name(IP, 1700000000, (1 << 63) | 77, 0x1A2B3C4D)
APPENDER = file_name(IP, 1700000000, (1 << 60) | 5, 0)
SERVERID = file_name(100001, 1700000000, 1024, 7)
SLAVE_FILE = NORMAL[:-4] + "-150x150.jpg"


def pad(text, n):
    return text.encode().ljust(n, b"\0")


def long(v):
    return struct.pack(">q", v)


# fuzz_file_id: byte 0 selects the operation
t = "fuzz_file_id"
for i, name in enumerate([NORMAL, HIGHBIT, APPENDER, SERVERID, SLAVE_FILE]):
    put(t, f"file_info_{i}", b"\x00group1/" + name.encode())
put(t, "check_ok", b"\x011A/FF/" + NORMAL[10:].encode())
put(t, "check_nested", b"\x011A/FF/dir/file.jpg")
put(t, "slave_name", b"\x02" + NORMAL.encode() + b"\n-150x150\npng")
put(t, "slave_empty_prefix", b"\x02" + NORMAL.encode() + b"\n\npng")
put(t, "token", b"\x03" + NORMAL.encode() + b"\nsecret\nc853679bd2bc6689d89da7aa92504c17")

# fuzz_tracker_response: byte 0 = call, byte 1 = status selector, rest = body
t = "fuzz_tracker_response"


def group_stat(name, total, free, count, port):
    return pad(name, 17) + b"".join(long(v) for v in (total, free, 0, 0, count, port, 2, 2, 0, 1, 256, 0))


groups = group_stat("group1", 102400, 51200, 3, 23000) + group_stat("group2", 2048, 1024, 1, 23001)
put(t, "list_groups", b"\x00\x00" + groups)
put(t, "list_one_group", b"\x01\x00" + group_stat("group1", 102400, 51200, 3, 23000))
put(t, "list_groups_status", bytes([0, 0x17]))
fetch = pad("group1", 16) + pad("192.168.1.101", 15) + long(23000)
put(t, "query_store_no_group", b"\x07\x00" + fetch + b"\x00")
put(t, "query_store_with_group", b"\x08\x00" + fetch + b"\x01")
put(t, "query_store_list", b"\x09\x00" + fetch + b"\x00" + pad("192.168.1.102", 15))
put(t, "query_fetch", b"\x0a\x00" + fetch)
put(t, "query_list", b"\x0b\x00" + fetch + pad("192.168.1.102", 15))
put(t, "query_fetch_status", bytes([10, 0x17]))
put(t, "get_storage_id", b"\x0d\x00" + pad("100001", 16))

# fuzz_storage_response: byte 0 = call, byte 1 = status selector, rest = body
t = "fuzz_storage_response"
info = long(1024) + long(1700000000) + long(0x1A2B3C4D) + pad("192.168.1.101", 16)
upload = pad("group1", 16) + NORMAL[:-3].encode() + b"txt"
put(t, "get_metadata", b"\x00\x00width\x021024\x01height\x02768")
put(t, "query_file_info", b"\x01\x00" + info)
put(t, "download_buff", b"\x02\x00hello fastdfs")
put(t, "download_callback", b"\x03\x00hello fastdfs")
put(t, "upload", b"\x04\x00" + upload)
put(t, "upload_appender", b"\x05\x00" + upload)
put(t, "upload_slave", b"\x06\x00" + upload)
put(t, "append", b"\x07\x00")
put(t, "truncate", b"\x08\x00")
put(t, "delete", b"\x09\x00")
put(t, "regenerate_appender", b"\x0a\x00" + upload)
put(t, "set_metadata", b"\x0b\x00")
put(t, "file_exist", b"\x0c\x00" + info)
put(t, "delete_status_enoent", bytes([9, 0x17]))

# fuzz_config_text: byte 0 selects the parser
t = "fuzz_config_text"
put(t, "storage_ids", b"\x00# id group ip\n100001 group1 192.168.1.101\n100002 group1 192.168.1.102:23001\n")
put(t, "mime_types", b"\x01# mime\ntext/html html htm\nimage/jpeg jpg jpeg\nimage/png png\n")
put(t, "server_ipv4", b"\x02192.168.1.5:23000")
put(t, "server_ipv6", b"\x02[fe80::1]:22122")
put(t, "server_multi", b"\x0210.0.0.1,10.0.0.2:23000")
put(t, "multi_ips", b"\x03192.168.1.5,fe80::1")

# fuzz_tracker_request: byte 0 = peer (0-2 logged-in storage .101/.102/.103, 3 same ip not logged in,
# 4 tracker peer 10.0.0.2, 5 stranger, 6 unknown storage .150, 7 this tracker), then a stream of
# requests, each a 10-byte header (8-byte body length, command, status) and its body.
t = "fuzz_tracker_request"
G1 = pad("group1", 16)
G2 = pad("group2", 16)
FILE = b"M00/00/00/wKgBZWVT8QAAAAAAAAAEABorPE0123.jpg"


def req(cmd, body=b""):
    return long(len(body)) + bytes([cmd, 0]) + body


def join_body(group, port, status, init_flag=0, storage_id=b"", tracker_ip=b"127.0.0.1"):
    head = (pad(group, 17) + long(port) + long(2) + long(256) + long(10) + long(1699999000) +
            long(1699999500) + pad("6.15.1", 8) + bytes([init_flag, status]) + pad(storage_id.decode(), 16) +
            pad(tracker_ip.decode(), 46) + long(1) + b"\0" * 16)
    return head + b"127.0.0.1:22122\n"


def df_body(*pairs):
    return b"".join(long(total) + long(free) for total, free in pairs)


def seed(name, sel, *packets):
    put(t, name, bytes([sel]) + b"".join(packets))


seed("active_test", 3, req(111))
seed("list_all_groups", 3, req(91))
seed("list_one_group", 3, req(90, G1))
seed("list_one_group_missing", 3, req(90, pad("nogroup", 16)))
seed("list_storage", 3, req(92, G1), req(92, G1 + b"192.168.1.101"))
seed("query_store_without_group", 3, req(101), req(106))
seed("query_store_with_group", 3, req(104, G2), req(107, G1))
seed("query_fetch", 3, req(102, G1 + FILE), req(105, G1 + FILE), req(103, G1 + FILE))
seed("join_new_storage", 6,
     req(81, join_body("group3", 23100, 7)), req(84, df_body((50000, 40000), (50000, 30000))),
     req(83), req(92, pad("group3", 16)), req(91))
seed("join_new_group_init", 6, req(81, join_body("group1", 23000, 0, 1)), req(83), req(91))
seed("join_existing_group", 6, req(81, join_body("group2", 23000, 1)), req(83), req(92, G2))
seed("beat_stats", 0, req(83, b"".join(long(v) for v in range(1, 44)) + b"\0" * 4))
seed("beat_empty", 1, req(83), req(83))
seed("disk_usage", 0, req(84, df_body((204800, 100000), (204800, 90000))))
seed("sync_report", 0, req(89, pad("192.168.1.102", 16) + long(1699999900)))
seed("sync_src_dest", 2, req(86, pad("192.168.1.101", 16) + long(1699999900)), req(87), req(88))
seed("sync_dest_query", 0, req(79))
seed("sync_notify", 1, req(88, pad("192.168.1.101", 16) + long(1699999900)))
seed("change_status", 0, req(59, bytes([6])))
seed("replica_chg", 0, req(85, bytes([7, 0, 0, 0x59, 0xd8]) + pad("192.168.1.102", 16) + pad("192.168.1.102", 46)))
seed("report_status", 3, req(76, G1 + b"192.168.1.101" + b"\0" * 3 + bytes([7])))
seed("get_status", 3, req(71, G1 + b"192.168.1.101"))
seed("get_storage_id", 3, req(70, G1 + b"192.168.1.101"))
seed("get_my_ip", 0, req(60), req(60))
seed("get_group_name", 3, req(109, b"192.168.1.101"))
seed("fetch_storage_ids", 3, req(69))
seed("fetch_sync_key", 3, req(80, G1 + pad("192.168.1.101", 16)))
seed("parameter_req", 3, req(75))
seed("changelog_logged_in", 0, req(77))
seed("changelog_anonymous", 3, req(77, G1 + pad("192.168.1.102", 16)))
seed("report_ip_changed", 3, req(78, G1 + pad("192.168.1.101", 16) + pad("192.168.1.201", 46)))
seed("trunk_fid", 0, req(73, b"\0\0\0\x07"), req(72))
seed("trunk_free", 0, req(74, long(1024)))
seed("quit", 3, req(111), req(82), req(111))
seed("tracker_get_status", 4, req(64))
seed("tracker_leader", 4, req(95), req(96), req(97), req(98))
seed("tracker_join_ping", 4, req(58, b"\0" * 0), req(65))
seed("tracker_notify_commit", 4, req(66, b"10.0.0.2:22122"), req(67, b"10.0.0.2:22122"), req(95))
seed("tracker_reselect", 4, req(68, b"10.0.0.2:22122"))
seed("tracker_delete_storage", 4, req(93, G1 + b"192.168.1.102"), req(92, G1))
seed("tracker_delete_group", 4, req(108, G2), req(91))
seed("tracker_delete_storage_denied", 5, req(93, G1 + b"192.168.1.102"))
seed("tracker_set_trunk", 4, req(94, G1))
seed("tracker_sys_files", 4, req(61), req(63, bytes([0]) + long(0)), req(63, bytes([1]) + long(0)),
     req(63, bytes([2]) + long(0)), req(62))
seed("self_tracker", 7, req(111), req(91))
seed("unknown_command", 3, req(99), req(0))
