"""Optional: follow a real Snort `alert_fast` file and feed alerts to the dashboard."""
import re, time, threading
LINE = re.compile(r'\[\*\*\] \[\d+:(\d+):\d+\] (.*?) \[\*\*\].*?\[Priority: (\d)\] \{(\w+)\} ([\d.]+)(?::\d+)? -> ([\d.]+)(?::(\d+))?')

def parse_line(line):
    m = LINE.search(line)
    if not m: return None
    sid, msg, pri, proto, src, dst, dport = m.groups()
    return {"ts": time.time(), "sid": int(sid), "msg": msg, "priority": int(pri), "classtype": "snort-live",
            "proto": proto, "src": src, "dst": dst, "dport": int(dport) if dport else None}

def follow(path, sink):
    def run():
        while True:
            try:
                with open(path, encoding="utf-8", errors="ignore") as f:
                    f.seek(0, 2)
                    while True:
                        line = f.readline()
                        if not line: time.sleep(0.5); continue
                        a = parse_line(line)
                        if a: sink(a)
            except FileNotFoundError:
                time.sleep(2)
    threading.Thread(target=run, daemon=True).start()
