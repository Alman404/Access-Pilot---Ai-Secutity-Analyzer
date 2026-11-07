"""Create a deliberately vulnerable sample repo (FAKE secrets only) and run the
real scanners against it. Used for local verification that scanning and
redaction work. Run from the backend directory:

    python selftest.py
"""

import json
import tempfile
from pathlib import Path

import scanner

SAMPLE = '''\
"""Deliberately vulnerable sample (self-test). FAKE secrets only."""
import sqlite3
import subprocess
import pickle


AWS_KEY = "AKIAJ5SUL3M4YDE6GT7Q"          # fake, but matches the AWS pattern
GITHUB_TOKEN = "ghp_9xKqRuePQyD0EeR2uNidbK7M3TpYqWz4f"  # fake, realistic shape


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    sql = "SELECT * FROM users WHERE id = '%s'" % user_id  # SQL injection
    return conn.execute(sql).fetchall()


def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True)  # command injection
    return result.stdout


def load_object(data):
    return pickle.loads(data)  # unsafe deserialization


def calc(x):
    return eval(f"{x} * 2")  # unsafe eval

def hash_md5(val):
    import hashlib
    return hashlib.md5(val).hexdigest()
'''

REQS = "# FAKE pinned requirements with known historical CVEs\nflask==2.0.0\nrequests==2.19.0\n"


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "sample_repo"
        repo.mkdir()
        (repo / "app.py").write_text(SAMPLE, encoding="utf-8")
        (repo / "requirements.txt").write_text(REQS, encoding="utf-8")

        print("== gitleaks ==")
        res = scanner.run_gitleaks(repo)
        print(json.dumps({"result": res["result"], "findings": len(res.get("findings", []))}, indent=2))
        if res.get("findings"):
            print("first:", res["findings"][0]["title"], "|", res["findings"][0]["evidence"][:80])

        print("== semgrep ==")
        res = scanner.run_semgrep(repo)
        print(json.dumps({"result": res["result"], "reason": res.get("reason"), "findings": len(res.get("findings", []))}, indent=2))
        for f in res.get("findings", [])[:8]:
            print(" ·", f["severity"], f["category"], f["file_path"], f["line_number"], "-", f["rule_id"])

        print("== pip-audit ==")
        res = scanner.run_pip_audit(repo, None)
        print(json.dumps({"result": res["result"], "reason": res.get("reason"), "findings": len(res.get("findings", []))}, indent=2))
        for f in res.get("findings", [])[:6]:
            print(" ·", f["title"], "|", f["evidence"][:100])

        print("== redaction check ==")
        leaky = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE" ; password = "SuperSecretPassword42!"'
        print(scanner.redact_text(leaky))
        assert "AKIAIOSFODNN7EXAMPLE" not in scanner.redact_text(leaky)
        assert "SuperSecretPassword42!" not in scanner.redact_text(leaky)
        print("redaction OK")


if __name__ == "__main__":
    main()
