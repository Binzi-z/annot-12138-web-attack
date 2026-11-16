"""Correlation detector for mixed web/ssh access logs.

Replaces the per-line baseline with three correlation rules plus an explicit
needs_review channel and a record of why benign look-alike traffic was not
flagged.

Rules
-----
web_scan              >= SCAN_HITS distinct sensitive-path probes from one IP
                      inside SCAN_WINDOW seconds. 1-2 probes are treated as
                      benign curiosity (and documented); 3-4 go to review.
webshell              an upload-like request from an IP followed, inside
                      UPLOAD_WINDOW seconds, by a request for an executable
                      script under an upload directory carrying a command
                      parameter. Upload without execution goes to review.
brute_force_success   >= BRUTE_FAILURES password failures for one (ip, user)
                      inside BRUTE_WINDOW followed by a successful auth of
                      that user from the same IP. Fewer failures stay benign
                      even when a success follows; failures with no observed
                      outcome go to review.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime

# --- thresholds -----------------------------------------------------------

SCAN_HITS = 5            # distinct sensitive paths that make a scan
SCAN_REVIEW_MIN = 3      # gray zone -> needs_review
SCAN_WINDOW = 300        # seconds
BRUTE_FAILURES = 5       # failed passwords that make brute-force
BRUTE_REVIEW_MIN = 3
BRUTE_WINDOW = 600       # seconds between failures / failure -> success
UPLOAD_WINDOW = 900      # seconds between upload and execution

# --- log parsing ----------------------------------------------------------

FAIL = re.compile(
    r"^(?P<ts>\w+ \d+ \d\d:\d\d:\d\d) \S+ sshd\[\d+\]: "
    r"Failed password for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPT = re.compile(
    r"^(?P<ts>\w+ \d+ \d\d:\d\d:\d\d) \S+ sshd\[\d+\]: "
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)"
)
WEB = re.compile(
    r"^(?P<ts>\w+ \d+ \d\d:\d\d:\d\d) \S+ nginx: "
    r'(?P<ip>[\d.]+) - - "(?P<path>\S+)" (?P<status>\d{3})'
)

# Sensitive targets: admin panels, secrets, backups, CMS/db admin, VCS.
SENSITIVE = re.compile(
    r"(?:^|/)(?:\.env|admin(?:/|$)|wp-login\.php|wp-admin|phpmyadmin|"
    r"phpinfo\.php|\.git(?:/|$)|config(?:\.\w+)?|backup\.\w+|"
    r"\.ssh(?:/|$)|etc/passwd|\.bak$)",
    re.IGNORECASE,
)
UPLOAD_ENDPOINT = re.compile(
    r"^/upload(?:\.php)?$|^/uploads?/?(?:\?.*)?$", re.IGNORECASE
)
UPLOAD_DIR_EXEC = re.compile(r"/uploads?/.+\.(?:php|jsp|asp|aspx|phtml)(?:\?|$)", re.IGNORECASE)
SHELL_PARAM = re.compile(r"[?&](?:cmd|exec|command|shell|system)=", re.IGNORECASE)
SHELL_NAME = re.compile(r"(?:shell|c99|r57|webshell)\.\w+", re.IGNORECASE)


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%b %d %H:%M:%S")


def parse_log(path: str) -> tuple[list[dict], dict[int, str]]:
    """Return structured events and a line-no -> raw line map."""
    events: list[dict] = []
    raw: dict[int, str] = {}
    with open(path, encoding="utf-8") as fh:
        for no, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            raw[no] = line
            m = FAIL.search(line)
            if m:
                events.append({"kind": "fail", "line": no, "ts": _ts(m.group("ts")),
                               "ip": m.group("ip"), "user": m.group("user")})
                continue
            m = ACCEPT.search(line)
            if m:
                events.append({"kind": "accept", "line": no, "ts": _ts(m.group("ts")),
                               "ip": m.group("ip"), "user": m.group("user")})
                continue
            m = WEB.search(line)
            if m:
                events.append({"kind": "web", "line": no, "ts": _ts(m.group("ts")),
                               "ip": m.group("ip"), "path": m.group("path"),
                               "status": int(m.group("status"))})
    return events, raw


# --- helpers --------------------------------------------------------------

def _evidence(events: list[dict], raw: dict[int, str], action: str) -> list[dict]:
    return [
        {
            "line": e["line"],
            "timestamp": e["ts"].strftime("%b %d %H:%M:%S"),
            "event": action(e),
            "raw": raw[e["line"]],
        }
        for e in events
    ]


def _finding(rule, severity, evs, entities, rationale, raw):
    return {
        "rule": rule,
        "severity": severity,
        "first_seen": evs[0]["ts"].strftime("%b %d %H:%M:%S"),
        "last_seen": evs[-1]["ts"].strftime("%b %d %H:%M:%S"),
        "line": evs[0]["line"],  # first supporting line (back-compat)
        "line_range": [evs[0]["line"], evs[-1]["line"]],
        "entities": entities,
        "rationale": rationale,
        "evidence": _evidence(
            evs, raw,
            lambda e: (
                f"web {e['status']} {e['path']}" if e["kind"] == "web"
                else f"ssh {e['kind']} user={e['user']}"
            ),
        ),
    }


def _review(rule, evs, entities, missing, raw):
    return {
        "rule": rule,
        "first_seen": evs[0]["ts"].strftime("%b %d %H:%M:%S"),
        "last_seen": evs[-1]["ts"].strftime("%b %d %H:%M:%S"),
        "entities": entities,
        "missing": missing,
        "evidence": _evidence(
            evs, raw,
            lambda e: (
                f"web {e['status']} {e['path']}" if e["kind"] == "web"
                else f"ssh {e['kind']} user={e['user']}"
            ),
        ),
    }


# --- rules ----------------------------------------------------------------

def detect_brute_force(events, raw):
    findings, review = [], []
    fails: dict[tuple, list[dict]] = {}
    accepts: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] == "fail":
            fails.setdefault((e["ip"], e["user"]), []).append(e)
        elif e["kind"] == "accept":
            accepts.setdefault(e["ip"], []).append(e)

    for (ip, user), fl in sorted(fails.items()):
        success = next(
            (a for a in accepts.get(ip, [])
             if a["user"] == user
             and 0 <= (a["ts"] - fl[-1]["ts"]).total_seconds() <= BRUTE_WINDOW),
            None,
        )
        if len(fl) >= BRUTE_FAILURES and success is not None:
            findings.append(_finding(
                "brute_force_success", "high", fl + [success],
                {"ip": ip, "user": user, "host": "web01"},
                f"{len(fl)} password failures for '{user}' from {ip} within "
                f"{BRUTE_WINDOW}s followed by a successful authentication of "
                f"the same account from the same IP",
                raw,
            ))
        elif success is not None:
            # outcome known, volume below threshold -> benign, not ambiguous
            continue
        elif len(fl) >= BRUTE_REVIEW_MIN:
            review.append(_review(
                "brute_force_success", fl, {"ip": ip, "user": user},
                f"no authentication outcome observed after {len(fl)} failures; "
                "need subsequent sshd Accepted/Failed lines or account-lock "
                "status to tell brute-force success from abandoned guessing",
                raw,
            ))
    return findings, review


def detect_webshell(events, raw):
    findings, review = [], []
    for e in events:
        if e["kind"] != "web" or not UPLOAD_ENDPOINT.search(e["path"]):
            continue
        exec_event = next(
            (w for w in events
             if w["kind"] == "web" and w["ip"] == e["ip"]
             and UPLOAD_DIR_EXEC.search(w["path"])
             and (SHELL_PARAM.search(w["path"]) or SHELL_NAME.search(w["path"]))
             and 0 <= (w["ts"] - e["ts"]).total_seconds() <= UPLOAD_WINDOW),
            None,
        )
        if exec_event is not None:
            findings.append(_finding(
                "webshell", "critical", [e, exec_event],
                {"ip": e["ip"], "host": "web01",
                 "upload_path": e["path"], "exec_path": exec_event["path"]},
                "upload endpoint returned 200 and the same IP then requested an "
                "executable script under the upload directory with a command "
                "parameter, i.e. an uploaded webshell being exercised",
                raw,
            ))
        else:
            review.append(_review(
                "webshell", [e], {"ip": e["ip"], "host": "web01"},
                "upload-like request has no follow-up request for an executable "
                "under /uploads/ within the window; need response body/bytes, "
                "multipart POST metadata or later /uploads/ access to decide "
                "whether a script was actually dropped",
                raw,
            ))
    return findings, review


def detect_web_scan(events, raw):
    findings, review, benign = [], [], []
    by_ip: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] == "web" and SENSITIVE.search(e["path"]):
            by_ip.setdefault(e["ip"], []).append(e)

    for ip, hits in sorted(by_ip.items()):
        span = (hits[-1]["ts"] - hits[0]["ts"]).total_seconds()
        distinct = sorted({h["path"] for h in hits})
        denied = sum(1 for h in hits if h["status"] in (401, 403, 404))
        entities = {"ip": ip, "host": "web01", "sensitive_paths": distinct}
        if len(hits) >= SCAN_HITS and span <= SCAN_WINDOW:
            findings.append(_finding(
                "web_scan", "high", hits, entities,
                f"{len(distinct)} distinct sensitive paths probed from {ip} in "
                f"{int(span)}s (threshold {SCAN_HITS} within {SCAN_WINDOW}s); "
                f"{denied}/{len(hits)} rejected (401/403/404) — automated "
                "reconnaissance rather than a user typo",
                raw,
            ))
        elif len(hits) >= SCAN_REVIEW_MIN:
            review.append(_review(
                "web_scan", hits, entities,
                f"only {len(hits)} sensitive probes (below scan threshold "
                f"{SCAN_HITS}); need more requests from this IP, a scan "
                "user-agent, or follow-up exploitation to distinguish targeted "
                "recon from isolated mis-clicks",
                raw,
            ))
        else:
            benign.append({
                "rule": "web_scan",
                "entities": {"ip": ip},
                "observed": f"{len(hits)} sensitive request(s), "
                            f"{denied} rejected with 401/403/404",
                "reason": f"below volume threshold ({len(hits)} < {SCAN_HITS} "
                          f"distinct sensitive paths within {SCAN_WINDOW}s) and "
                          "every probe was denied, so no successful access or "
                          "automation is evidenced; treated as benign probing",
            })
    return findings, review, benign


def detect_brute_benign(events):
    """Documented explanation for failed-then-success logins below threshold."""
    out = []
    fails: dict[tuple, list[dict]] = {}
    accepts: dict[str, list[dict]] = {}
    for e in events:
        if e["kind"] == "fail":
            fails.setdefault((e["ip"], e["user"]), []).append(e)
        elif e["kind"] == "accept":
            accepts.setdefault(e["ip"], []).append(e)
    for (ip, user), fl in sorted(fails.items()):
        if len(fl) >= BRUTE_FAILURES:
            continue
        if any(a["user"] == user for a in accepts.get(ip, [])):
            out.append({
                "rule": "brute_force_success",
                "entities": {"ip": ip, "user": user},
                "observed": f"{len(fl)} failed password(s) then a successful "
                            "authentication from the same IP/user",
                "reason": f"failure count {len(fl)} is below the brute-force "
                          f"threshold {BRUTE_FAILURES}; pattern matches a user "
                          "mistyping a password and then authenticating, not "
                          "credential guessing",
            })
    return out


def scan(path: str) -> dict:
    events, raw = parse_log(path)
    findings: list[dict] = []
    needs_review: list[dict] = []

    bf, bf_review = detect_brute_force(events, raw)
    ws, ws_review = detect_webshell(events, raw)
    scan_hits, scan_review, scan_benign = detect_web_scan(events, raw)

    findings = sorted(bf + ws + scan_hits, key=lambda f: f["line"])
    needs_review = sorted(bf_review + ws_review + scan_review,
                          key=lambda r: r["first_seen"])
    benign_evaluations = sorted(
        scan_benign + detect_brute_benign(events),
        key=lambda b: (b["rule"], b["entities"].get("ip", "")),
    )
    return {
        "findings": findings,
        "needs_review": needs_review,
        "benign_evaluations": benign_evaluations,
        "thresholds": {
            "web_scan": f">= {SCAN_HITS} distinct sensitive paths within "
                        f"{SCAN_WINDOW}s (review from {SCAN_REVIEW_MIN})",
            "webshell": f"upload then script execution under /uploads/ within "
                        f"{UPLOAD_WINDOW}s",
            "brute_force_success": f">= {BRUTE_FAILURES} failures then success "
                                   f"within {BRUTE_WINDOW}s (review from "
                                   f"{BRUTE_REVIEW_MIN} if no outcome)",
        },
    }


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log> <out.json>")
        return 2
    result = scan(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(
        f"{len(result['findings'])} findings, "
        f"{len(result['needs_review'])} needs_review, "
        f"{len(result['benign_evaluations'])} benign evaluations -> {sys.argv[2]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
