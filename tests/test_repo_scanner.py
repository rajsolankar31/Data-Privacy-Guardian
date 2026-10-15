import pytest
import os
from src.repo_scanner import scan_local_git_repo

def test_repo_scanner():
    repo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    findings = scan_local_git_repo(repo_dir, max_files=50)
    # The scan should run recursively without crashing, returning structured results
    assert isinstance(findings, list)
    if findings:
        sample = findings[0]
        assert "Repository File" in sample
        assert "Line" in sample
        assert "Evidence" in sample
        assert "Remediation" in sample
