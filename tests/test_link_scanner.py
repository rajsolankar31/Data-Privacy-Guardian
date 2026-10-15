import pytest
from src.link_scanner import analyze_url_parameters, scan_live_web_link

def test_analyze_url_parameters():
    url = "https://shop.example.com/checkout?user=123&fbclid=IwAR2XYZ9876543210&utm_source=spring_sale&utm_campaign=retargeting"
    trackers = analyze_url_parameters(url)
    assert len(trackers) >= 3
    param_names = [t["Parameter"] for t in trackers]
    assert "fbclid" in param_names
    assert "utm_source" in param_names
    assert "utm_campaign" in param_names
    # Evidence must be masked
    fbclid_entry = next(t for t in trackers if t["Parameter"] == "fbclid")
    assert "*" in fbclid_entry["Values"]

def test_scan_live_web_link():
    # Test local/safe public endpoint
    res = scan_live_web_link("https://httpbin.org/get?gclid=test123456", timeout_seconds=5)
    assert res["url"].startswith("https://")
    assert len(res["url_trackers"]) >= 1
    assert "risk_score" in res
    assert "risk_level" in res
