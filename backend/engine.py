"""Minimal Snort-rule engine: parses Snort rule syntax and matches packet dicts."""
import re
from collections import defaultdict, deque

RULE_RE = re.compile(r'^alert\s+(\w+)\s+\S+\s+\S+\s+->\s+\S+\s+(\S+)\s+\((.*)\)\s*$')
DF_RE = re.compile(r'count\s+(\d+)\s*,\s*seconds\s+(\d+)')


def parse_rules(path):
    rules = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            m = RULE_RE.match(line) if line and not line.startswith("#") else None
            if not m:
                continue
            proto, dport, opts = m.groups()
            r = {"proto": proto, "dport": dport, "contents": [], "flags": None,
                 "nocase": False, "df": None, "priority": 3, "msg": "", "sid": 0, "classtype": ""}
            for opt in opts.split(";"):
                k, _, v = opt.strip().partition(":")
                v = v.strip().strip('"')
                if k == "msg": r["msg"] = v
                elif k == "content": r["contents"].append(v)
                elif k == "nocase": r["nocase"] = True
                elif k == "flags": r["flags"] = v
                elif k == "sid": r["sid"] = int(v)
                elif k == "priority": r["priority"] = int(v)
                elif k == "classtype": r["classtype"] = v
                elif k == "detection_filter":
                    d = DF_RE.search(v)
                    if d: r["df"] = (int(d.group(1)), int(d.group(2)))
            rules.append(r)
    return rules


class Engine:
    def __init__(self, rules_path):
        self.rules = parse_rules(rules_path)
        self.hist = defaultdict(deque)  # (sid, src) -> timestamps

    def _match(self, r, p):
        if r["proto"] not in ("ip", p["proto"]): return False
        if r["dport"] != "any" and str(p.get("dport")) != r["dport"]: return False
        if r["flags"] and p.get("flags") != r["flags"]: return False
        payload = p.get("payload", "")
        if r["nocase"]: payload = payload.lower()
        for c in r["contents"]:
            if (c.lower() if r["nocase"] else c) not in payload: return False
        return True

    def inspect(self, p):
        alerts = []
        for r in self.rules:
            if not self._match(r, p): continue
            if r["df"]:
                count, secs = r["df"]
                q = self.hist[(r["sid"], p["src"])]
                q.append(p["ts"])
                while q and p["ts"] - q[0] > secs: q.popleft()
                if len(q) < count: continue
                q.clear()
            alerts.append({"ts": p["ts"], "sid": r["sid"], "msg": r["msg"], "priority": r["priority"],
                           "classtype": r["classtype"], "proto": p["proto"].upper(), "src": p["src"],
                           "dst": p["dst"], "dport": p.get("dport")})
        return alerts
