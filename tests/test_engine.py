import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import app

def test_detection_rate_is_92():
    m, _ = app.evaluate()
    assert m["detection_rate"] == 92.0 and m["fp"] == 0

def test_api():
    c = app.app.test_client()
    assert c.post("/api/simulate").status_code == 200
    assert c.get("/api/alerts").json and c.get("/api/stats").json["rules_loaded"] == 6
