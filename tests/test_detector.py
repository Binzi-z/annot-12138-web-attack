import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")
LABELS = os.path.join(ROOT, "labels.json")
DETECTOR = os.path.join(ROOT, "detector", "detector.py")

TS = "Oct 01 08:{m:02d}:{s:02d}"


def run(tmp_path, log=LOG):
    out = tmp_path / "out.json"
    r = subprocess.run(
        [sys.executable, "-I", DETECTOR, log, str(out)],
        capture_output=True, text=True,
    )
    return r, out


def write_log(tmp_path, lines):
    p = tmp_path / "case.log"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def nginx(ip, minute, sec, path, status=200):
    return f'{TS.format(m=minute, s=sec)} web01 nginx: {ip} - - "{path}" {status} 100 "Mozilla/5.0"'


def fail(ip, user, minute, sec):
    return f"{TS.format(m=minute, s=sec)} web01 sshd[1000]: Failed password for {user} from {ip} port 1 ssh2"


def accept(ip, user, minute, sec):
    return f"{TS.format(m=minute, s=sec)} web01 sshd[10000]: Accepted publickey for {user} from {ip} port 2 ssh2"


def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(LABELS, encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data["events"]) == 3


def test_detector_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "findings" in json.loads(out.read_text(encoding="utf-8"))


def test_findings_have_required_fields(tmp_path):
    _, out = run(tmp_path)
    data = json.loads(out.read_text(encoding="utf-8"))
    for f in data["findings"]:
        assert f["rule"] and f["line"] and f["entities"]["ip"]
        assert f["first_seen"] <= f["last_seen"]
        assert f["evidence"] and all("line" in e and "event" in e and "raw" in e
                                     for e in f["evidence"])


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    r, out = run(tmp_path, str(empty))
    assert r.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert data["needs_review"] == []
    assert data["benign_evaluations"] == []


def test_all_labelled_events_are_detected(tmp_path):
    _, out = run(tmp_path)
    data = json.loads(out.read_text(encoding="utf-8"))
    labels = json.load(open(LABELS, encoding="utf-8"))["events"]
    for label in labels:
        matches = [f for f in data["findings"]
                   if f["rule"] == label["kind"]
                   and f["entities"]["ip"] == label["ip"]]
        assert len(matches) == 1, f"label not hit exactly once: {label}"
        f = matches[0]
        if "user" in label:
            assert f["entities"]["user"] == label["user"]
        # finding must carry a multi-step event sequence
        assert len(f["evidence"]) >= (15 if label["kind"] == "brute_force_success" else 2)
        assert f["first_seen"] < f["last_seen"]


def test_no_finding_outside_labelled_entities(tmp_path):
    """Zero false positives on the intentionally unlabelled look-alikes."""
    _, out = run(tmp_path)
    data = json.loads(out.read_text(encoding="utf-8"))
    labelled_ips = {e["ip"] for e in json.load(open(LABELS, encoding="utf-8"))["events"]}
    assert len(data["findings"]) == 3
    assert {f["entities"]["ip"] for f in data["findings"]} == labelled_ips
    # the two benign look-alikes are explicitly explained, not silently dropped
    benign_ips = {b["entities"]["ip"] for b in data["benign_evaluations"]}
    assert {"10.20.1.77", "10.20.1.88"} <= benign_ips
    for b in data["benign_evaluations"]:
        assert b["reason"]


def test_brute_force_sequence_content(tmp_path):
    _, out = run(tmp_path)
    f = next(f for f in json.loads(out.read_text(encoding="utf-8"))["findings"]
             if f["rule"] == "brute_force_success")
    events = [e["event"] for e in f["evidence"]]
    assert sum(1 for e in events if e.startswith("ssh fail")) == 14
    assert events[-1].startswith("ssh accept")
    assert f["line_range"] == [849, 863]


def test_few_failures_then_success_is_benign(tmp_path):
    log = write_log(tmp_path, [
        fail("10.0.0.9", "ops", 0, 1),
        fail("10.0.0.9", "ops", 0, 2),
        accept("10.0.0.9", "ops", 0, 3),
    ])
    r, out = run(tmp_path, str(log))
    assert r.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert data["needs_review"] == []
    assert len(data["benign_evaluations"]) == 1


def test_two_denied_sensitive_probes_are_benign(tmp_path):
    log = write_log(tmp_path, [
        nginx("10.0.0.8", 0, 1, "/admin", 403),
        nginx("10.0.0.8", 0, 2, "/.env", 403),
    ])
    r, out = run(tmp_path, str(log))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert data["findings"] == []
    assert data["needs_review"] == []
    assert len(data["benign_evaluations"]) == 1


def test_medium_probe_volume_goes_to_review(tmp_path):
    lines = [nginx("10.0.0.7", 0, s, p, 404)
             for s, p in enumerate(["/admin", "/.env", "/backup.zip"])]
    r, out = run(tmp_path, str(write_log(tmp_path, lines)))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert data["findings"] == []
    assert len(data["needs_review"]) == 1
    item = data["needs_review"][0]
    assert item["rule"] == "web_scan"
    assert item["missing"]


def test_failed_only_burst_goes_to_review(tmp_path):
    lines = [fail("10.0.0.6", "root", 0, s) for s in range(6)]
    r, out = run(tmp_path, str(write_log(tmp_path, lines)))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert data["findings"] == []
    assert len(data["needs_review"]) == 1
    assert data["needs_review"][0]["rule"] == "brute_force_success"
    assert "outcome" in data["needs_review"][0]["missing"]


def test_upload_without_execution_goes_to_review(tmp_path):
    r, out = run(tmp_path, str(write_log(tmp_path, [nginx("10.0.0.5", 0, 1, "/upload.php", 200)])))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert data["findings"] == []
    assert len(data["needs_review"]) == 1
    assert data["needs_review"][0]["rule"] == "webshell"


def test_webshell_pattern_on_synthetic_log(tmp_path):
    log = write_log(tmp_path, [
        nginx("10.0.0.4", 0, 1, "/upload.php", 200),
        nginx("10.0.0.4", 0, 2, "/uploads/x.php?cmd=whoami", 200),
    ])
    r, out = run(tmp_path, str(log))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule"] == "webshell"
    assert data["findings"][0]["entities"]["ip"] == "10.0.0.4"


def test_slow_failures_outside_window_are_not_brute_force(tmp_path):
    # six failures spread ~3 minutes apart never share a 600s window
    lines = [fail("10.0.0.10", "root", 3 * i, 0) for i in range(6)]
    r, out = run(tmp_path, str(write_log(tmp_path, lines)))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert data["findings"] == []


def test_accept_before_failures_is_not_correlated(tmp_path):
    log = write_log(tmp_path, [
        accept("10.0.0.11", "root", 0, 1),
        *[fail("10.0.0.11", "root", 0, 2 + i) for i in range(6)],
    ])
    r, out = run(tmp_path, str(log))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert all(f["rule"] != "brute_force_success" for f in data["findings"])
    # no observed outcome *after* the failures -> review, not a success finding
    assert any(n["rule"] == "brute_force_success" for n in data["needs_review"])


def test_repeated_uploads_emit_one_finding_and_one_review(tmp_path):
    log = write_log(tmp_path, [
        nginx("10.0.0.12", 0, 1, "/upload.php", 200),
        nginx("10.0.0.12", 0, 2, "/upload.php", 200),
        nginx("10.0.0.12", 0, 3, "/uploads/shell.php?cmd=id", 200),
    ])
    r, out = run(tmp_path, str(log))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    ws_findings = [f for f in data["findings"] if f["rule"] == "webshell"]
    ws_reviews = [n for n in data["needs_review"] if n["rule"] == "webshell"]
    assert len(ws_findings) == 1
    assert len(ws_reviews) == 1


def test_unparsed_line_goes_to_review_with_missing_note(tmp_path):
    p = write_log(tmp_path, [
        "Oct 01 08:00:00 web01 unknown-daemon[9]: something unrecognised happened",
    ])
    r, out = run(tmp_path, str(p))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert data["findings"] == []
    review = next(n for n in data["needs_review"] if n["rule"] == "unparsed_log_line")
    assert review["missing"]
    assert review["evidence"][0]["line"] == 1


def test_denied_probes_spread_beyond_scan_window_stay_benign(tmp_path):
    # 6 sensitive probes but each ~6 minutes apart: never 5 inside 300s
    lines = [nginx("10.0.0.13", 6 * i, 0, p, 404)
             for i, p in enumerate(["/admin", "/.env", "/backup.zip",
                                    "/wp-login.php", "/phpmyadmin", "/.git/config"])]
    r, out = run(tmp_path, str(write_log(tmp_path, lines)))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0
    assert data["findings"] == []
    assert {b["entities"]["ip"] for b in data["benign_evaluations"]} == {"10.0.0.13"}
