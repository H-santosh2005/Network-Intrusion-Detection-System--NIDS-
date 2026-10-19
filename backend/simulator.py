"""Generates labelled traffic (benign + simulated attacks) for offline evaluation.
Everything is synthetic packet dicts: nothing is sent on the network."""
import random

def _pkt(ts, src, dst, proto="tcp", dport=80, flags="PA", payload=""):
    return {"ts": ts, "src": src, "dst": dst, "proto": proto, "dport": dport, "flags": flags, "payload": payload}

def generate(seed=7, attacks=100, evasive=8, benign=300):
    """Returns events: {'label': sid|None, 'evasive': bool, 'packets': [...]}. Time is virtual."""
    rnd = random.Random(seed)
    events, t = [], 0.0
    ip = lambda: f"10.0.{rnd.randint(0, 9)}.{rnd.randint(2, 250)}"
    server = "192.168.1.10"
    kinds = [1000001, 1000002, 1000003, 1000004, 1000005, 1000006]
    plan = [(k, False) for k in (kinds * 20)[:attacks - evasive]] + [(k, True) for k in [1000001, 1000004, 1000005, 1000006] * 2][:evasive]
    plan = [("attack",) + x for x in plan] + [("benign", None, False)] * benign
    rnd.shuffle(plan)
    for kind, sid, evade in plan:
        t += rnd.uniform(40, 60)  # gap so rate-based rules reset between events
        src, pk = ip(), []
        if kind == "benign":
            c = rnd.choice(["web", "dns", "ssh", "https"])
            if c == "web": pk = [_pkt(t, src, server, payload=f"GET /page{rnd.randint(1,50)}.html HTTP/1.1")]
            elif c == "dns": pk = [_pkt(t, src, server, "udp", 53, "", "query example.com")]
            elif c == "ssh": pk = [_pkt(t, src, server, dport=22, flags="S")]
            else: pk = [_pkt(t, src, server, dport=443, flags="S")]
            sid = None
        elif sid == 1000001:
            body = "GET /login?u=%27%20OR%201%3D1-- HTTP/1.1" if evade else "GET /login?u=admin' OR 1=1-- HTTP/1.1"
            pk = [_pkt(t, src, server, payload=body)]
        elif sid == 1000002: pk = [_pkt(t, src, server, payload="GET /s?q=<script>alert(1)</script> HTTP/1.1")]
        elif sid == 1000003: pk = [_pkt(t, src, server, payload="GET /../../etc/passwd HTTP/1.1")]
        elif sid == 1000004:  # evasive = slow scan, one probe every 2 s
            n, gap = (12, 2.0) if evade else (40, 0.05)
            pk = [_pkt(t + i * gap, src, server, dport=1000 + i, flags="S") for i in range(n)]
        elif sid == 1000005:  # evasive = low-and-slow brute force
            n, gap = (5, 8.0) if evade else (12, 0.5)
            pk = [_pkt(t + i * gap, src, server, dport=22, flags="S") for i in range(n)]
        elif sid == 1000006:  # evasive = rate kept below threshold
            n, gap = (15, 0.5) if evade else (40, 0.02)
            pk = [_pkt(t + i * gap, src, server, "icmp", None, "", "") for i in range(n)]
        t = pk[-1]["ts"]
        events.append({"label": sid, "evasive": bool(evade), "packets": pk})
    return events
