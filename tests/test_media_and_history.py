import pytest
from src.media_scanner import scan_media_transcript, parse_srt_vtt
from src.audit_history import log_scan_event, get_scan_history

def test_parse_srt_vtt():
    srt_text = """
1
00:00:01,000 --> 00:00:04,500
Hello, my name is John Smith and my email is jsmith@domain.com.

2
00:00:05,000 --> 00:00:08,000
Call me back at 555-123-4567.
    """
    findings = scan_media_transcript(srt_text.encode("utf-8"), "meeting.srt")
    assert len(findings) >= 2
    categories = [f["Category"] for f in findings]
    assert "Email" in categories
    assert "Phone Number" in categories
    assert "00:00:01,000 - 00:00:04,500" in findings[0]["Spoken Timestamp"]

def test_audit_history():
    event = log_scan_event(
        source_name="test_dataset.csv",
        source_type="Tabular",
        total_findings=5,
        risk_score=25.5
    )
    assert event["source_name"] == "test_dataset.csv"
    history = get_scan_history()
    assert len(history) > 0
    assert history[0]["source_name"] == "test_dataset.csv"
