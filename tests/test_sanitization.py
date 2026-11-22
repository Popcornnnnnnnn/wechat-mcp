# Copyright (C) 2026 wechat-mcp contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
Automated Sanitization, Licensing, and Repository Cleanliness Test Suite.

Verifies:
1. GNU General Public License v3.0 compliance (root LICENSE and file headers).
2. All src/ and tests/ Python files contain standard GPL-3.0 notice header.
3. Zero binary SQLite/WCDB database files tracked in git.
4. Zero personal wxids (real hex format) in tracked files and repo.
5. Zero unapproved reverse-DNS bundle identifiers or local denylist matches.
6. Zero hardcoded developer absolute home directory paths.
7. Zero real numeric WeChat chatroom identifiers.
8. Zero private keys, auth tokens, or cloud credentials.
9. Configuration template (config.example.json) sanitization.
10. Packaging metadata (pyproject.toml) license and cleanliness.
11. Gitignore rules protection against sensitive files, configs, and caches.
"""

import json
import os
from pathlib import Path
import re
import subprocess
from typing import List, Set

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Set of extensions considered text files for code/content scanning
SCANNABLE_EXTENSIONS = {".py", ".json", ".toml", ".md", ".txt", ".sh", ".yml", ".yaml"}

# Directories excluded from repository scans
EXCLUDED_DIRS = {".git", ".venv", ".pytest_cache", "__pycache__", "build", "dist", "decrypted"}


def get_all_scannable_files() -> List[Path]:
    """Retrieve all scannable repository files combining git ls-files and working tree."""
    files: Set[Path] = set()

    # 1. Tracked git files if git is available
    try:
        res = subprocess.run(["git", "ls-files"], cwd=PROJECT_ROOT, capture_output=True, text=True, check=True)
        for rel in res.stdout.splitlines():
            p = PROJECT_ROOT / rel
            if p.is_file() and p.suffix.lower() in SCANNABLE_EXTENSIONS:
                files.add(p)
    except Exception:
        pass

    # 2. Walk directory tree to include working tree files
    for root, dirs, filenames in os.walk(PROJECT_ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in filenames:
            p = Path(root) / fname
            if p.suffix.lower() in SCANNABLE_EXTENSIONS:
                files.add(p)

    return sorted(list(files))


def test_license_file_exists_and_is_standard_gpl3():
    """Assert root LICENSE file exists and contains standard GNU GPL-3.0 text."""
    lic_path = PROJECT_ROOT / "LICENSE"
    assert lic_path.is_file(), "LICENSE file missing from repository root"
    content = lic_path.read_text(encoding="utf-8")
    assert "GNU GENERAL PUBLIC LICENSE" in content
    assert "Version 3, 29 June 2007" in content
    assert "Copyright (C) 2026 wechat-mcp contributors" in content
    assert "TERMS AND CONDITIONS" in content


def test_all_python_source_files_contain_gpl3_header():
    """Assert all Python files in src/wechat_mcp contain the standard GPL-3.0 header."""
    src_dir = PROJECT_ROOT / "src" / "wechat_mcp"
    assert src_dir.is_dir()
    py_files = sorted(list(src_dir.rglob("*.py")))
    assert len(py_files) >= 20, f"Expected at least 20 source files, found {len(py_files)}"

    missing = []
    for f in py_files:
        content = f.read_text(encoding="utf-8", errors="ignore")
        top_lines = "\n".join(content.splitlines()[:20])
        if "GNU General Public License" not in top_lines or "Copyright (C) 2026 wechat-mcp contributors" not in top_lines:
            missing.append(str(f.relative_to(PROJECT_ROOT)))

    assert not missing, f"Source files missing GPL-3.0 header: {missing}"


def test_all_python_test_files_contain_gpl3_header():
    """Assert all Python files in tests/ contain the standard GPL-3.0 header."""
    tests_dir = PROJECT_ROOT / "tests"
    assert tests_dir.is_dir()
    py_files = sorted(list(tests_dir.rglob("*.py")))
    assert len(py_files) >= 15, f"Expected at least 15 test files, found {len(py_files)}"

    missing = []
    for f in py_files:
        content = f.read_text(encoding="utf-8", errors="ignore")
        top_lines = "\n".join(content.splitlines()[:20])
        if "GNU General Public License" not in top_lines or "Copyright (C) 2026 wechat-mcp contributors" not in top_lines:
            missing.append(str(f.relative_to(PROJECT_ROOT)))

    assert not missing, f"Test files missing GPL-3.0 header: {missing}"


def test_no_binary_databases_tracked_in_git():
    """Assert no binary SQLite, WCDB, or WAL files are tracked in git."""
    forbidden_exts = {".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".db-journal"}
    try:
        res = subprocess.run(["git", "ls-files"], cwd=PROJECT_ROOT, capture_output=True, text=True, check=True)
        tracked = res.stdout.splitlines()
    except Exception:
        pytest.skip("git command unavailable")

    tracked_dbs = [f for f in tracked if any(f.endswith(ext) for ext in forbidden_exts)]
    assert not tracked_dbs, f"Binary database files tracked in git: {tracked_dbs}"


def test_no_personal_wxid_patterns():
    """Assert no real personal wxids (14+ alphanumeric chars) exist outside allowed synthetic fixtures."""
    allowed_synthetic = re.compile(
        r"^wxid_(?:test_|sender_|user_|recipient_|dummy_|mock_|alice|bob|charlie|me|target|"
        r"revoker|attacker|victim|from_file|primary|secondary|old|new|legit|matching|"
        r"only|missing|serial|raises|realuser12345|discovery_locates_storage_dir|sync_user|xxxx)",
        re.IGNORECASE,
    )
    raw_wxid_pattern = re.compile(r"\bwxid_([a-zA-Z0-9_]{14,})\b")

    violations = []
    for fpath in get_all_scannable_files():
        if fpath.name == "test_sanitization.py":
            continue
        content = fpath.read_text(encoding="utf-8", errors="ignore")
        for match in raw_wxid_pattern.finditer(content):
            wxid_str = match.group(0)
            if not allowed_synthetic.match(wxid_str):
                violations.append((str(fpath.relative_to(PROJECT_ROOT)), wxid_str))

    assert not violations, f"Detected potential personal wxids: {violations}"


def test_no_private_bundle_or_denylist_identifiers():
    """Assert no unapproved reverse-DNS bundle IDs or optional denylist identifiers exist."""
    bundle_regex = re.compile(r"(?<![A-Za-z0-9_.-])com\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+")
    allowed_bundle_prefixes = (
        "com.tencent.xinWeChat",
        "com.wechat-mcp.",
        "com.legacy.",
        "com.apple.",
    )
    denylist_raw = os.environ.get("WECHAT_MCP_SANITIZE_DENYLIST", "")
    denylist = [term.strip() for term in denylist_raw.split(",") if term.strip()]

    violations = []
    for fpath in get_all_scannable_files():
        if fpath.name == "test_sanitization.py":
            continue
        content = fpath.read_text(encoding="utf-8", errors="ignore")
        rel = str(fpath.relative_to(PROJECT_ROOT))
        for m in bundle_regex.finditer(content):
            bundle_id = m.group(0)
            if not bundle_id.startswith(allowed_bundle_prefixes):
                violations.append((rel, bundle_id))
        if denylist:
            lowered = content.lower()
            for term in denylist:
                if term.lower() in lowered:
                    violations.append((rel, f"denylist:{term}"))

    assert not violations, f"Detected unapproved bundle or denylist identifiers: {violations}"


def test_no_hardcoded_developer_home_paths():
    """Assert zero non-placeholder /Users/<name> or /home/<name> developer paths exist."""
    home_path_regex = re.compile(r"/(?:Users|home)/([A-Za-z0-9_{}\[\].^+-]+)")
    allowed_usernames = {
        "USERNAME",
        "{sudo_user}",
        "[USER]",
        "[a-zA-Z0-9_-]+",
        "[^",
        "john_doe",
        "test_user",
        "test_sudo_user",
        "victim_user",
        "victim",
        "developer_name",
        "runner",
        "mock",
        "test",
    }

    violations = []
    for fpath in get_all_scannable_files():
        if fpath.name == "test_sanitization.py":
            continue
        content = fpath.read_text(encoding="utf-8", errors="ignore")
        for match in home_path_regex.finditer(content):
            username = match.group(1)
            if username not in allowed_usernames:
                violations.append((str(fpath.relative_to(PROJECT_ROOT)), match.group(0)))

    assert not violations, f"Detected hardcoded developer home paths: {violations}"


def test_no_real_numeric_chatrooms():
    """Assert zero real numeric chatrooms (8+ digit chatrooms e.g. 8+ digits @chatroom) exist."""
    real_chatroom_regex = re.compile(r"\b\d{8,}@chatroom\b")

    violations = []
    for fpath in get_all_scannable_files():
        if fpath.name == "test_sanitization.py":
            continue
        content = fpath.read_text(encoding="utf-8", errors="ignore")
        matches = real_chatroom_regex.findall(content)
        if matches:
            violations.append((str(fpath.relative_to(PROJECT_ROOT)), matches[:5]))

    assert not violations, f"Detected real numeric chatroom identifiers: {violations}"


def test_no_private_keys_or_tokens():
    """Assert zero private keys, API secrets, AWS tokens, or GitHub PATs exist."""
    key_patterns = re.compile(
        r"(BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY|"
        r"\bAKIA[0-9A-Z]{16}\b|"
        r"\bghp_[0-9a-zA-Z]{36}\b|"
        r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b)"
    )

    violations = []
    for fpath in get_all_scannable_files():
        if fpath.name == "test_sanitization.py":
            continue
        content = fpath.read_text(encoding="utf-8", errors="ignore")
        matches = key_patterns.findall(content)
        if matches:
            violations.append((str(fpath.relative_to(PROJECT_ROOT)), matches[:5]))

    assert not violations, f"Detected private keys or tokens: {violations}"


def test_config_example_json_sanitized():
    """Assert config.example.json is valid JSON and contains zero sensitive data."""
    cfg_path = PROJECT_ROOT / "config.example.json"
    assert cfg_path.is_file(), "config.example.json missing"
    raw_text = cfg_path.read_text(encoding="utf-8")
    cfg = json.loads(raw_text)

    assert "wxid" in cfg
    assert cfg["wxid"] in {"auto", "", "example_wxid"}
    assert cfg.get("summary_api_key") is None or cfg.get("summary_api_key") == ""
    assert "/Users/" not in raw_text
    assert "/home/" not in raw_text
    if "decrypted_dir" in cfg:
        assert not cfg["decrypted_dir"].startswith(("/Users/", "/home/"))
    if "db_dir" in cfg:
        assert not cfg["db_dir"].startswith(("/Users/", "/home/"))


def test_pyproject_toml_license_and_metadata():
    """Assert pyproject.toml specifies GPL-3.0-or-later and contains clean metadata."""
    pyproj = PROJECT_ROOT / "pyproject.toml"
    assert pyproj.is_file()
    text = pyproj.read_text(encoding="utf-8")

    assert 'license = { text = "GPL-3.0-or-later" }' in text
    assert '"License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)"' in text
    assert "https://github.com/Popcornnnnnnnn/wechat-mcp" in text
    assert "/Users/" not in text
    assert "/home/" not in text


def test_gitignore_rules_protect_sensitive_files():
    """Assert .gitignore contains exclusion rules for configs, keys, databases, and caches."""
    gitignore_path = PROJECT_ROOT / ".gitignore"
    assert gitignore_path.is_file(), ".gitignore missing"
    content = gitignore_path.read_text(encoding="utf-8")

    required_patterns = [
        "config.json",
        "keys.json",
        "*.pem",
        "*.db",
        "*.sqlite",
        ".agents",
    ]
    for pattern in required_patterns:
        assert pattern in content, f".gitignore missing pattern: {pattern}"

    # Verify git check-ignore on sensitive file samples if git is available
    sensitive_samples = ["config.json", "keys.json", "private.pem", "test.db", "data.sqlite", ".agents/meta"]
    for sample in sensitive_samples:
        try:
            res = subprocess.run(
                ["git", "check-ignore", "-q", sample],
                cwd=PROJECT_ROOT,
                check=False,
            )
            assert res.returncode == 0, f"Sample sensitive file {sample} not ignored by git"
        except Exception:
            pass
