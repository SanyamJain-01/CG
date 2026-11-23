"""Measure CG on labelled samples, end to end through its real API.

Each sample is a small Python file that either has one known vulnerability (its line ends with #!) or is a safe
lookalike using the same library correctly. All samples go into one ZIP, which is uploaded like any user upload;
the script then reads the findings back and scores them. Scanner results and the LLM's false-positive labels are
measured separately. Results are written to eval/EVAL_RESULTS.md.

    python3 eval/run_eval.py --url http://localhost:8080          # local stack (docker compose --profile app up)
    python3 eval/run_eval.py --url https://<your-app>.onrender.com --runs 3

Needs an account: set CG_EVAL_EMAIL and CG_EVAL_PASSWORD (registered automatically if new). Each run is one upload,
so it counts once against the 10-uploads-per-hour limit. Standard library only.
    python3 eval/run_eval.py --selftest                            # checks the scoring code, offline
"""
import argparse
import io
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from datetime import date, datetime
from pathlib import Path

# (name, code, vulnerable). In vulnerable samples the vulnerable line ends with "#!" (removed before upload).
CASES = [
    ("sqli_percent", '''
import sqlite3
def find(name):
    cur = sqlite3.connect("app.db").cursor()
    return cur.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()  #!
''', True),
    ("sqli_fstring", '''
import sqlite3
def delete(order_id):
    sqlite3.connect("app.db").execute(f"DELETE FROM orders WHERE id = {order_id}")  #!
''', True),
    ("sqli_format", '''
import sqlite3
def rename(user_id, new_name):
    sqlite3.connect("app.db").execute("UPDATE users SET name = '{}' WHERE id = {}".format(new_name, user_id))  #!
''', True),
    ("shell_true", '''
import subprocess
def run(cmd):
    return subprocess.run(cmd, shell=True)  #!
''', True),
    ("os_system", '''
import os
def ping(host):
    os.system("ping -c 1 " + host)  #!
''', True),
    ("eval_input", '''
def calculate(expr):
    return eval(expr)  #!
''', True),
    ("pickle_loads", '''
import pickle
def load(data):
    return pickle.loads(data)  #!
''', True),
    ("yaml_load", '''
import yaml
def parse(text):
    return yaml.load(text, Loader=yaml.Loader)  #!
''', True),
    ("hardcoded_token", '''
API_TOKEN = "ghp_{token}"  #!
def headers():
    return {"Authorization": "Bearer " + API_TOKEN}
''', True),
    ("md5_password", '''
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  #!
''', True),
    ("tls_off", '''
import requests
def fetch(url):
    return requests.get(url, verify=False, timeout=5).text  #!
''', True),
    ("flask_debug", '''
from flask import Flask
app = Flask(__name__)
if __name__ == "__main__":
    app.run(debug=True)  #!
''', True),
    ("safe_sql_params", '''
import sqlite3
def find(name):
    cur = sqlite3.connect("app.db").cursor()
    return cur.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
''', False),
    ("safe_sql_constant", '''
import sqlite3
def count():
    return sqlite3.connect("app.db").execute("SELECT COUNT(*) FROM users").fetchone()[0]
''', False),
    ("safe_subprocess_list", '''
import subprocess
def ping(host):
    return subprocess.run(["ping", "-c", "1", host], check=True)
''', False),
    ("safe_literal_eval", '''
import ast
def parse_list(text):
    return ast.literal_eval(text)
''', False),
    ("safe_json", '''
import json
def load(data):
    return json.loads(data)
''', False),
    ("safe_yaml", '''
import yaml
def parse(text):
    return yaml.safe_load(text)
''', False),
    ("safe_env_token", '''
import os
API_TOKEN = os.environ["API_TOKEN"]
def headers():
    return {"Authorization": "Bearer " + API_TOKEN}
''', False),
    ("safe_sha256", '''
import hashlib
def checksum(data):
    return hashlib.sha256(data).hexdigest()
''', False),
    ("safe_tls", '''
import requests
def fetch(url):
    return requests.get(url, timeout=5).text
''', False),
    ("safe_random_token", '''
import secrets
def new_session_id():
    return secrets.token_hex(16)
''', False),
]


def materialise(code):
    """(file text, vulnerable line numbers). The fake token is made at runtime so no secret-like string is committed."""
    lines = code.strip("\n").replace("{token}", secrets.token_hex(18)).splitlines()
    targets = {n for n, line in enumerate(lines, 1) if line.rstrip().endswith("#!")}
    text = "\n".join(line[:line.rfind("#!")].rstrip() if n in targets else line for n, line in enumerate(lines, 1))
    return text + "\n", targets


def build_zip():
    """ZIP bytes plus labels: {path: (vulnerable, target lines, line count)}."""
    buf, labels = io.BytesIO(), {}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, code, vulnerable in CASES:
            text, targets = materialise(code)
            path = f"samples/{name}.py"
            z.writestr(path, text)
            labels[path] = (vulnerable, targets, text.count("\n"))
    return buf.getvalue(), labels


# ---------- scoring (pure functions, covered by --selftest) ----------

def score(findings, labels):
    """findings: CG API items. Returns metrics for scanners alone and with the LLM's false-positive labels applied."""
    rows = []
    for f in findings:
        path, start, end = f["location"]["file"], f["location"]["startLine"], f["location"]["endLine"]
        vulnerable, targets, line_count = labels.get(path, (False, set(), 0))
        ai = f.get("aiExplanation")
        rows.append({"path": path, "start": start, "rule": f"{f['source']['tool']}/{f['source']['ruleId']}",
                     "real": any(start <= t <= end for t in targets),
                     "valid_line": path in labels and 1 <= start <= end <= line_count,
                     "explained": ai is not None,
                     "dismissed": bool(ai and ai["likelyFalsePositive"])})

    def stage(keep):
        kept = [r for r in rows if keep(r)]
        real = [r for r in kept if r["real"]]
        vulnerable = [p for p, (v, _, _) in labels.items() if v]
        safe = [p for p, (v, _, _) in labels.items() if not v]
        caught = {r["path"] for r in real}
        flagged_safe = {r["path"] for r in kept if r["path"] in safe}
        return {"recall": len(caught) / len(vulnerable) if vulnerable else 0.0,
                "precision": len(real) / len(kept) if kept else 0.0,
                "false_positive_rate": len(flagged_safe) / len(safe) if safe else 0.0,
                "noise": len(kept) - len(real),
                "missed": sorted(Path(p).stem for p in vulnerable if p not in caught)}

    noise = [r for r in rows if not r["real"]]
    return {"scanners": stage(lambda r: True),
            "with_llm": stage(lambda r: not r["dismissed"]),
            "findings": len(rows),
            "invalid_lines": sum(not r["valid_line"] for r in rows),
            "duplicates": sum(n - 1 for n in Counter((r["path"], r["start"]) for r in rows).values()),
            "explained": sum(r["explained"] for r in rows),
            "noise_dismissed": sum(r["dismissed"] for r in noise),
            "noise_total": len(noise),
            "real_dismissed": sum(r["dismissed"] for r in rows if r["real"]),
            "labels": {(r["path"], r["start"], r["rule"]): r["dismissed"] for r in rows if r["explained"]}}


def consistency(runs):
    """Share of findings explained in every run whose false-positive label was the same each time."""
    common = set.intersection(*(set(m["labels"]) for m in runs))
    if not common:
        return None
    same = sum(len({m["labels"][k] for m in runs}) == 1 for k in common)
    return same / len(common), len(common)


# ---------- talking to CG ----------

class Api:
    def __init__(self, base):
        self.base, self.token = base.rstrip("/"), None

    def call(self, method, path, body=None, content_type="application/json"):
        headers = {"Content-Type": content_type} if body is not None else {}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = json.dumps(body).encode() if content_type == "application/json" and body is not None else body
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=300) as r:  # a sleeping free-tier app can take minutes
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def wait_ready(self, limit_seconds=600):
        """Waits until /actuator/health says UP: a container that just started, or a sleeping free-tier app."""
        deadline = time.time() + limit_seconds
        while time.time() < deadline:
            try:
                if self.call("GET", "/actuator/health")[1].get("status") == "UP":
                    return
            except (urllib.error.URLError, ConnectionError, TimeoutError):
                pass  # not listening yet
            print("waiting for CG to start...")
            time.sleep(10)
        sys.exit(f"CG at {self.base} did not become healthy in {limit_seconds} s")

    def login(self, email, password):
        status, body = self.call("POST", "/api/auth/login", {"email": email, "password": password})
        if status == 401:
            self.call("POST", "/api/auth/register", {"email": email, "password": password})
            status, body = self.call("POST", "/api/auth/login", {"email": email, "password": password})
        if status != 200:
            sys.exit(f"login failed: HTTP {status} {body}")
        self.token = body["accessToken"]

    def upload(self, data):
        boundary = "cg-eval-" + secrets.token_hex(8)
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"eval.zip\"\r\n"
                f"Content-Type: application/zip\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
        status, scan = self.call("POST", "/api/scans", body, f"multipart/form-data; boundary={boundary}")
        if status != 202:
            sys.exit(f"upload failed: HTTP {status} {scan}")
        return scan["id"]

    def wait(self, scan_id, limit_seconds=900):
        deadline = time.time() + limit_seconds
        while time.time() < deadline:
            _, scan = self.call("GET", f"/api/scans/{scan_id}")
            if scan["status"] in ("SUCCEEDED", "FAILED"):
                return scan
            time.sleep(5)
        sys.exit(f"scan {scan_id} did not finish in {limit_seconds} s")


def seconds(scan):
    t = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
    return (t(scan["finishedAt"]) - t(scan["startedAt"])).total_seconds()


def run_once(api):
    data, labels = build_zip()
    scan = api.wait(api.upload(data))
    if scan["status"] != "SUCCEEDED":
        sys.exit(f"scan failed: {scan['errorCode']} {scan['errorDetail']}")
    _, body = api.call("GET", f"/api/scans/{scan['id']}/findings")
    m = score(body["items"], labels)
    m.update(seconds=seconds(scan), llm_status=scan["llmStatus"], tool_errors=scan["toolErrors"])
    return m


def report(runs, url):
    m = runs[0]
    s, l = m["scanners"], m["with_llm"]
    pct = lambda x: f"{x:.0%}"
    vulnerable = sum(c[2] for c in CASES)
    lines = [f"# CG evaluation ({date.today()})", "",
             f"{len(CASES)} labelled Python samples: {vulnerable} with one known vulnerability each, "
             f"{len(CASES) - vulnerable} safe lookalikes using the same libraries correctly. "
             f"Uploaded as one ZIP to `{url}` by `eval/run_eval.py`; {len(runs)} run(s). Numbers are from run 1.", "",
             "| | Scanners only | Scanners + LLM labels |", "|---|---|---|",
             f"| Vulnerable files caught (recall) | {pct(s['recall'])} | {pct(l['recall'])} |",
             f"| Findings that are real (precision) | {pct(s['precision'])} | {pct(l['precision'])} |",
             f"| Safe files with any finding (false-positive rate) | {pct(s['false_positive_rate'])} | "
             f"{pct(l['false_positive_rate'])} |",
             f"| Noise findings shown | {s['noise']} | {l['noise']} |", "",
             f"- Findings: {m['findings']}; with an AI explanation: {m['explained']}; LLM status: {m['llm_status']}.",
             f"- The LLM labelled **{m['noise_dismissed']} of {m['noise_total']}** noise findings as likely false "
             f"positives and wrongly dismissed **{m['real_dismissed']}** real vulnerabilities.",
             f"- Findings pointing at a missing file or an impossible line: {m['invalid_lines']}. "
             f"Duplicates on the same line: {m['duplicates']}.",
             f"- Missed vulnerabilities: {', '.join(l['missed']) or 'none'}.",
             "- Scan time (worker start to finish, all samples): " + ", ".join(f"{r['seconds']:.0f} s" for r in runs) + ".",
             f"- Tool errors: {m['tool_errors'] or 'none'}."]
    if len(runs) > 1:
        c = consistency(runs)
        lines.append(f"- LLM label consistency across runs: "
                     + (f"{c[0]:.0%} of {c[1]} findings explained in every run" if c else "not measurable"))
    if m["llm_status"] != "DONE":
        lines.append("\n**The LLM did not run, so the LLM column equals the scanner column.**")
    lines += ["", "Limits: small, textbook Python samples with one vulnerability each. This shows the pipeline works "
              "and what the LLM labels change, not how CG performs on large real-world code. LLM cost is not measured: "
              "CG does not record token usage."]
    return "\n".join(lines) + "\n"


def selftest():
    labels = {"samples/a.py": (True, {3}, 4), "samples/b.py": (False, set(), 3)}
    f = lambda path, start, fp=None, end=None: {
        "location": {"file": path, "startLine": start, "endLine": end or start},
        "source": {"tool": "semgrep", "ruleId": "r"},
        "aiExplanation": None if fp is None else {"likelyFalsePositive": fp}}
    m = score([f("samples/a.py", 3), f("samples/a.py", 1, fp=True), f("samples/b.py", 2, fp=False),
               f("samples/b.py", 99)], labels)
    assert m["scanners"]["recall"] == 1.0 and m["scanners"]["noise"] == 3
    assert m["scanners"]["precision"] == 0.25 and m["scanners"]["false_positive_rate"] == 1.0
    assert m["with_llm"]["noise"] == 2 and m["noise_dismissed"] == 1 and m["real_dismissed"] == 0
    assert m["invalid_lines"] == 1 and m["duplicates"] == 0 and m["explained"] == 2
    assert score([f("samples/a.py", 2, end=4)], labels)["scanners"]["recall"] == 1.0  # range covers the target
    assert score([f("samples/a.py", 3, fp=True)], labels)["with_llm"]["missed"] == ["a"]
    assert consistency([m, m]) == (1.0, 2)
    data, built = build_zip()
    assert len(built) == len(CASES) and zipfile.ZipFile(io.BytesIO(data)).testzip() is None
    assert all(len(t) == 1 for v, t, _ in built.values() if v) and all(not t for v, t, _ in built.values() if not v)
    print("selftest ok")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default="http://localhost:8080")
    p.add_argument("--runs", type=int, default=1)
    p.add_argument("--selftest", action="store_true")
    a = p.parse_args()
    if a.selftest:
        return selftest()
    email, password = os.environ.get("CG_EVAL_EMAIL"), os.environ.get("CG_EVAL_PASSWORD")
    if not email or not password:
        sys.exit("set CG_EVAL_EMAIL and CG_EVAL_PASSWORD (password: 12+ characters)")
    api = Api(a.url)
    api.wait_ready()
    api.login(email, password)
    runs = []
    for i in range(a.runs):
        runs.append(run_once(api))
        print(f"run {i + 1}: {runs[-1]['findings']} findings in {runs[-1]['seconds']:.0f} s")
    text = report(runs, a.url)
    out = Path(__file__).with_name("EVAL_RESULTS.md")
    out.write_text(text)
    print("\n" + text + f"\nwritten to {out}")


if __name__ == "__main__":
    main()
