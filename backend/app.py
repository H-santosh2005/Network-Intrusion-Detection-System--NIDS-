import os, threading
from collections import Counter
from flask import Flask, jsonify, send_from_directory
from engine import Engine
from simulator import generate
import snort_tail

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=os.path.join(BASE, "..", "frontend"), static_url_path="")
RULES = os.path.join(BASE, "rules", "local.rules")
lock, alerts = threading.Lock(), []
last_eval = {}

def add_alert(a):
    with lock:
        alerts.append(a)
        del alerts[:-2000]

def evaluate(seed=7):
    """Replay labelled traffic through the engine and score it at event level."""
    eng, events = Engine(RULES), generate(seed)
    tp = fn = fp = tn = 0
    missed = Counter()
    found = []
    for ev in events:
        hits = [a for p in ev["packets"] for a in eng.inspect(p)]
        found += hits
        if ev["label"] is None:
            fp, tn = (fp + 1, tn) if hits else (fp, tn + 1)
        elif any(h["sid"] == ev["label"] for h in hits):
            tp += 1
        else:
            fn += 1
            missed["evasive" if ev["evasive"] else "unexpected"] += 1
    total = tp + fn + fp + tn
    return {"attacks": tp + fn, "benign": fp + tn, "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "detection_rate": round(100 * tp / (tp + fn), 2),
            "accuracy": round(100 * (tp + tn) / total, 2),
            "false_positive_rate": round(100 * fp / (fp + tn), 2), "missed": dict(missed)}, found

@app.get("/")
def index(): return send_from_directory(app.static_folder, "index.html")

@app.get("/api/alerts")
def get_alerts():
    with lock: return jsonify(alerts[-200:][::-1])

@app.get("/api/stats")
def stats():
    with lock: snap = list(alerts)
    return jsonify({"total": len(snap), "by_priority": dict(Counter(a["priority"] for a in snap)),
                    "by_type": dict(Counter(a["msg"] for a in snap)),
                    "top_sources": Counter(a["src"] for a in snap).most_common(5),
                    "rules_loaded": len(Engine(RULES).rules), "evaluation": last_eval})

@app.post("/api/simulate")
def simulate():
    global last_eval
    last_eval, found = evaluate()
    for a in found: add_alert(a)
    return jsonify(last_eval)

@app.post("/api/clear")
def clear():
    global last_eval
    with lock: alerts.clear()
    last_eval = {}
    return jsonify({"ok": True})

if os.environ.get("SNORT_ALERT_FILE"):
    snort_tail.follow(os.environ["SNORT_ALERT_FILE"], add_alert)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=True)
