#!/bin/bash
API="curl -s -m 3 -H 'Authorization: Bearer eshield-demo-2024'"
echo 'timestamp,total_packets,total_dropped,blacklist_blocked,rate_limited,current_pps,current_dps,attack_events'
for i in $(seq 1 60); do
  ts=$(date +%s)
  stats=$(eval "$API http://127.0.0.1:8720/api/stats")
  tp=$(echo "$stats" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("total_packets",0))')
  td=$(echo "$stats" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("total_dropped",0))')
  bb=$(echo "$stats" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("blacklist_blocked",0))')
  rl=$(echo "$stats" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("rate_limited",0))')
  pps=$(echo "$stats" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("current_pps",0))')
  dps=$(echo "$stats" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("current_dps",0))')
  ae=$(eval "$API 'http://127.0.0.1:8720/api/attack-events?limit=1'" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("count",0))')
  echo "$ts,$tp,$td,$bb,$rl,$pps,$dps,$ae"
  sleep 5
done
