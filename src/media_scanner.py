import re
from typing import List, Dict, Any
from .document_scanner import mask_evidence
from .sensitive_detector import PATTERNS, CATEGORY_ROLE_MAP

def parse_srt_vtt(text: str) -> List[Dict[str, Any]]:
    """
    Parses SubRip (.srt) and WebVTT (.vtt) subtitle/transcript formats.
    Extracts timecodes (e.g. 00:01:20 --> 00:01:25) and spoken dialog lines.
    """
    blocks = []
    # Pattern to match timecodes like "00:00:10,500 --> 00:00:15,000" or "00:00:10.500 --> 00:00:15.000"
    timecode_pattern = re.compile(r"(\d{2}:\d{2}:\d{2}[,\.]\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}[,\.]\d{3})")

    lines = text.splitlines()
    current_timecode = "00:00:00"
    current_dialog = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if current_dialog:
                blocks.append({
                    "timestamp": current_timecode,
                    "text": " ".join(current_dialog)
                })
                current_dialog = []
            continue

        tc_match = timecode_pattern.search(stripped)
        if tc_match:
            if current_dialog:
                blocks.append({
                    "timestamp": current_timecode,
                    "text": " ".join(current_dialog)
                })
                current_dialog = []
            current_timecode = f"{tc_match.group(1)} - {tc_match.group(2)}"
        elif not stripped.isdigit() and stripped != "WEBVTT":
            current_dialog.append(stripped)

    if current_dialog:
        blocks.append({
            "timestamp": current_timecode,
            "text": " ".join(current_dialog)
        })

    return blocks


def scan_media_transcript(file_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
    """
    Scans media transcripts, subtitles (.srt, .vtt), or meeting notes for spoken PII,
    returning findings linked to exact spoken timestamps.
    """
    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = file_bytes.decode("latin-1", errors="ignore")

    blocks = parse_srt_vtt(text)
    if not blocks:
        # Fallback if plain text transcript without timestamps
        blocks = [{"timestamp": f"Line {i+1}", "text": line} for i, line in enumerate(text.splitlines()) if line.strip()]

    findings = []
    for b in blocks:
        spoken_text = b["text"]
        timestamp = b["timestamp"]

        for pat_name, pat_regex in PATTERNS.items():
            for match in pat_regex.finditer(spoken_text):
                matched_val = match.group(0)
                findings.append({
                    "Source Media": filename,
                    "Spoken Timestamp": timestamp,
                    "Spoken Content Snippet": spoken_text,
                    "Category": pat_name,
                    "Role": CATEGORY_ROLE_MAP.get(pat_name, "Direct Identifier"),
                    "Evidence": mask_evidence(matched_val),
                    "Confidence": "High",
                    "Recommended Action": f"Bleep/mute audio at timestamp [{timestamp}] or redact in transcript."
                })

    return findings
