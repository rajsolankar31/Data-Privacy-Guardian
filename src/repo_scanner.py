import os
import io
import re
from typing import List, Dict, Any
from .sensitive_detector import PATTERNS, CATEGORY_ROLE_MAP
from .document_scanner import SECRET_PATTERNS, mask_evidence

def scan_local_git_repo(repo_path: str, max_files: int = 200) -> List[Dict[str, Any]]:
    """
    Recursively scans a local repository or project directory for exposed credentials,
    unencrypted .env files, private keys, database strings, and PII.
    Ignores binary files and .git internals for maximum speed and efficiency.
    """
    findings = []
    ignored_dirs = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache", ".idea", ".vscode"}
    scanned_count = 0

    for root, dirs, files in os.walk(repo_path):
        # Prune ignored directories
        dirs[:] = [d for d in dirs if d not in ignored_dirs]

        for file in files:
            if scanned_count >= max_files:
                break

            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, repo_path)
            ext = os.path.splitext(file)[1].lower()

            # Skip binary files
            if ext in {".png", ".jpg", ".jpeg", ".db", ".sqlite", ".zip", ".tar", ".gz", ".exe", ".bin", ".pyc"}:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            scanned_count += 1
            lines = content.splitlines()

            for line_no, line in enumerate(lines, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                    # Check if secret even in commented lines because committed commented secrets still leak
                    pass

                # 1. Scan Secrets
                for secret_name, secret_rx in SECRET_PATTERNS.items():
                    for match in secret_rx.finditer(clean_line):
                        matched_val = match.group(0)
                        findings.append({
                            "Repository File": rel_path,
                            "Line": line_no,
                            "Category": "Authentication Secret",
                            "Role": "Exposed Credential",
                            "Detection Rule": secret_name,
                            "Evidence": mask_evidence(matched_val, keep_chars=3),
                            "Severity": "Critical",
                            "Remediation": "Purge from Git commit history using BFG Repo-Cleaner or git-filter-repo, rotate key immediately."
                        })

                # 2. Scan PII
                for pii_name, pii_rx in PATTERNS.items():
                    for match in pii_rx.finditer(clean_line):
                        matched_val = match.group(0)
                        findings.append({
                            "Repository File": rel_path,
                            "Line": line_no,
                            "Category": pii_name,
                            "Role": CATEGORY_ROLE_MAP.get(pii_name, "Direct Identifier"),
                            "Detection Rule": f"Regex ({pii_name})",
                            "Evidence": mask_evidence(matched_val, keep_chars=2),
                            "Severity": "High",
                            "Remediation": "Remove hardcoded personal identifiers from source files."
                        })

    return findings
