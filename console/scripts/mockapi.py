#!/usr/bin/env python3
"""Local mock of the eShield HTTP API + SPA host, used to verify console wiring.

Usage: python console/scripts/mockapi.py [port] [app_html]
"""
import json, sys, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8898
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "dist", "index.html")
if not os.path.exists(APP):
    APP = os.path.join(ROOT, "..", "eshield", "web", "app.html")
APP_BYTES = open(APP, "rb").read()

STATS = {
    "total_packets": 3284915204, "total_passed": 3271006118, "total_dropped": 13909086,
    "current_pps": 1482310, "current_dps": 86420, "blacklist_blocked": 9812443,
    "rate_limited": 1204880, "syn_flood_blocked": 1876442, "l7_blocked": 344902,
    "adaptive_blocked": 18220, "udp_flood_blocked": 12, "icmp_flood_blocked": 15,
    "geoip_blocked": 402188, "conn_track_blocked": 218336, "tcp_rst_sent": 0,
    "tcp_rst_fail": 0, "tcp_rst_attempt": 0, "tcp_dropped": 11920446,
    "udp_dropped": 1502331, "icmp_dropped": 486309, "other_dropped": 0,
    "top_attackers": [{"ip": "203.0.113.9", "count": 9812443}, {"ip": "198.51.100.7", "count": 1204880}],
    "top_ports": [{"port": 80, "count": 8120000}, {"port": 443, "count": 3040000}],
    "trust_trusted": 12402, "trust_neutral": 1204, "trust_suspicious": 388,
    "trust_malicious": 96, "danger_level": 2,
}
SERIES = [{"timestamp": 1791180000 + i * 60, "pps": 900000 + i * 1000, "dps": 20000 + i * 10,
           "timestamp_ns": (1791180000 + i * 60) * 1000000000} for i in range(60)]
MODULES = {"modules": [
    {"id": "syn_flood", "name": "SYN Flood 防护", "category": "DDoS", "description": "SYN cookie", "enabled": True, "stats_key": "syn_flood_blocked", "editable_fields": [{"id": "enabled", "type": "switch", "label": "启用防护", "value": True}]},
    {"id": "rate_limit", "name": "速率限制 / CC 防护", "category": "访问控制", "description": "令牌桶", "enabled": True, "stats_key": "rate_limited", "editable_fields": [{"id": "enabled", "type": "switch", "label": "启用限速", "value": True}, {"id": "threshold", "type": "number", "label": "阈值", "value": 200}]},
    {"id": "conn_track", "name": "连接跟踪 / CC 防御", "category": "智能防御", "description": "半连接", "enabled": False, "stats_key": "conn_track_blocked", "editable_fields": [{"id": "enabled", "type": "switch", "label": "启用连接跟踪", "value": False}]},
]}
EVENTS = {"events": [{"timestamp_ns": 1791180000000000000, "src_ip": "203.0.113.9", "protocol": 6, "rule_id": 1, "rule_name": "黑名单", "dst_port": 80},
                     {"timestamp_ns": 1791179999000000000, "src_ip": "198.51.100.7", "protocol": 17, "rule_id": 8, "rule_name": "UDP Flood", "dst_port": 53}], "count": 2}
PACKETS = {"entries": [{"timestamp_ns": 1791180000000000000, "src_ip": "203.0.113.9", "dst_ip": "172.23.83.42", "src_port": 40001, "dst_port": 80, "protocol": 6, "action": 1, "rule_id": 1, "packet_len": 74, "payload_bytes": 20, "payload_hex": "47 45 54 20 2f 61 70 69 20 48 54 54 50"}], "count": 1}
AUDIT = {"entries": [{"timestamp": "2026-10-06T10:00:00Z", "actor": "admin", "action": "BlockIp", "detail": {"ip": "203.0.113.9"}, "source_ip": "172.23.83.41"}], "total": 1}
BLACKLIST = {"entries": [{"ip": "203.0.113.9", "reason": "黑名单", "origin": "api", "created_ns": 1791180000000000000, "expires_ns": 0, "hits": 9812443}], "count": 1}
WHITELIST = {"entries": [{"cidr": "10.0.0.0/8", "note": "内网"}], "count": 1}
ACL = {"items": [{"protocol": "tcp", "dport": "3306", "action": "deny"}]}
L7 = {"patterns": [{"pattern": "GET /"}, {"pattern": "eval("}]}
PROJECTS = {"projects": [{"name": "web-public", "description": "Web", "protocol": "tcp", "dport": "80,443", "target_ips": ["172.23.83.42/32"], "enabled_modules": ["l7_scan"], "action": "defend"}]}
CONFIG = {"version": "0.4.6", "interface": "eth0", "web_bind": "0.0.0.0:8720", "store_path": "/var/lib/eshield/rules.redb",
          "rate_limit_enabled": True, "syn_proxy_enabled": True, "l7_scan_enabled": True, "udp_flood_enabled": True,
          "icmp_flood_enabled": True, "geoip_enabled": False, "geoip_default_action": 0, "conn_track_enabled": False,
          "conn_track_threshold": 100, "conn_track_window_ms": 10000, "trust_enabled": True, "tcp_reset_on_drop": False,
          "danger_level": 2, "protection_projects_enabled": True, "rate_limit": {"enabled": True, "threshold": 200, "tick_ms": 100, "decay_num": 7, "decay_den": 8, "block_duration_s": 300},
          "port_rate_limit": {"enabled": False, "threshold": 2000, "tick_ms": 100}}
HUB_STATUS = {"connected": True, "url": "wss://hub.eshield.local:9930"}
HUB_NODES = {"nodes": [{"node_name": "edge-api-01", "ip": "172.23.83.42", "version": "0.4.6", "status": "online", "policies": 18, "last_seen": "6s"}]}
IP_DETAIL = {"ip": "203.0.113.9", "blacklisted": True, "hit_count": 9812443, "trust_score": 3, "trust_level": 3,
             "drop_count": 9812443, "pass_count": 12, "top_ports": [{"port": 80, "count": 9812443}],
             "recent_samples": [{"timestamp_ns": 1791180000000000000, "src_ip": "203.0.113.9", "dst_ip": "172.23.83.42", "src_port": 40001, "dst_port": 80, "protocol": 6, "action": 1, "rule_id": 1, "packet_len": 74}]}
IP_SERIES = {"ip": "203.0.113.9", "series": [{"timestamp": 1791180000 + i * 60, "drop_count": 100 + i, "pass_count": 2} for i in range(10)]}

ROUTES = {"/api/stats": STATS, "/api/metrics/series": {"series": SERIES}, "/api/protection-modules": MODULES,
          "/api/attack-events": EVENTS, "/api/packets": PACKETS, "/api/audit": AUDIT, "/api/blacklist": BLACKLIST,
          "/api/whitelist": WHITELIST, "/api/port-acl": ACL, "/api/l7-patterns": L7, "/api/protection-projects": PROJECTS,
          "/api/config": CONFIG, "/api/hub/status": HUB_STATUS, "/api/hub/proxy/nodes": HUB_NODES,
          "/api/ip-detail": IP_DETAIL, "/api/ip-series": IP_SERIES}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/app.html", "/login"):
            return self._send(200, APP_BYTES, "text/html; charset=utf-8")
        if path == "/api/auth/check":
            return self._send(200, b"OK", "text/plain")
        if path in ROUTES:
            return self._send(200, ROUTES[path])
        return self._send(404, {"error": "not found"})
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0)); self.rfile.read(length)
        return self._send(200, {"ok": True})
    do_PATCH = do_POST
    do_DELETE = do_POST

if __name__ == "__main__":
    print(f"mock api on http://127.0.0.1:{PORT} serving {APP}")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
