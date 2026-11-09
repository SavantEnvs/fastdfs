#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the known-answer probe built by mayhem/build.sh (normal flags, dynamically
# linked) and compare each decoded value with an independently computed expectation.
# The probe drives real FastDFS client code: file-id decoding, slave-filename generation, filename
# validation, the anti-steal token (md5, expectation from python hashlib), tracker/storage response
# parsing over a socketpair, and the mime-types / storage-ids / server-address parsers. A second probe,
# /mayhem/kat_tracker_probe, drives the tracker server's request dispatcher (tracker_deal_task) over a
# fixed set of joined storages and checks the decoded responses (group/storage lists, store/fetch
# routing, error codes, join of a new group, per-input reset, change log).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

for probe in /mayhem/kat_probe /mayhem/kat_tracker_probe; do
  if [ ! -x "$probe" ]; then
    echo "missing $probe — mayhem/build.sh should have built it" >&2
    emit_ctrf "fastdfs-kat" 0 1 0
    exit 1
  fi
done

actual="$(/mayhem/kat_probe 2>/dev/null; /mayhem/kat_tracker_probe 2>/dev/null)"

expected='file_info rc=0 ip=192.168.1.101 ts=1700000000 size=1024 crc=1a2b3c4d type=1
slave rc=0 len=52 name=M00/00/00/wKgBZWVT8QAAAAAAAAAEABorPE0123-150x150.png
check_filename good=0 lowercase=22 nested=22 short=22
token rc=0 value=c853679bd2bc6689d89da7aa92504c17 check_ok=0 check_bad=1
list_groups rc=0 count=2 g0=group1:102400:51200:3:23000 g1=group2:2048:1024:1:23001
metadata rc=0 count=2 m0=width=1024 m1=height=768
download rc=0 size=13 data=hello fastdfs
file_exist_status2 rc=2
mime rc=0 htm=text/html png=image/png zzz=x/default
storage_ids rc=0 count=2 id2=192.168.1.102 group=group1
server_info rc=0 count=1 ip=192.168.1.5 port=23000
tracker_active_test rc=0 cmd=100 len=0
tracker_list_groups rc=0 count=2 g0=group1:204800:101376:2:2:23000 g1=group2:204800:101376:1:1:23000
tracker_list_storage rc=0 count=2 s0=192.168.1.101:7:204800:101376 s1=192.168.1.102:7:204800:101376
tracker_query_store rc=0 group=group2 ip=192.168.1.103 port=23000 path=0
tracker_query_fetch rc=0 group=group1 ip=192.168.1.101 port=23000
tracker_cluster_stat rc=0 count=3 first=192.168.1.101:192.168.1.101:23000:7 active=3 not_active=0
tracker_volumn_stat rc=0 count=2 v0=group1:204800:101376:1024:100352:1 v1=group2:204800:101376:1024:100352:1
tracker_errors list_missing=2 beat_not_joined=13 unknown_cmd=22 delete_group_stranger=13
tracker_join rc=0 my_status=6 resp_len=17 groups_after=3 beat=0
tracker_reset rc=0 groups=2
tracker_changelog rc=0 len=105 first=1699999000 group1 192.168.1.101 7'

passed=0
failed=0
while IFS= read -r want; do
  name="${want%% *}"
  got="$(printf '%s\n' "$actual" | grep -m1 "^$name " || true)"
  if [ "$got" = "$want" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL $name" >&2
    echo "  want: $want" >&2
    echo "  got:  $got" >&2
  fi
done <<< "$expected"

emit_ctrf "fastdfs-kat" "$passed" "$failed" 0
