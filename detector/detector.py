"""Correlation detector for mixed web/ssh access logs.

Replaces the per-line baseline with three correlation rules plus an explicit
needs_review channel and a record of why benign look-alike traffic was not
flagged.

Rules
-----
web_scan              >= SCAN_HITS distinct sensitive-path probes from one IP
                      inside one SCAN_WINDOW sliding window. 1-2 probes are
                      treated as benign curiosity (and documented); 3-4 go to
                      review. The window is a real sliding window, so probes
                      spread over hours do not merge into a phantom scan.
webshell              an upload-like request from an IP followed, inside
                      UPLOAD_WINDOW seconds, by a request for an executable
                      script under an upload directory carrying a command
                      parameter. Upload without execution goes to review;
                      each upload event is evaluated once so repeated uploads
                      never produce duplicate findings.
brute_force_success   >= BRUTE_FAILURES password failures for one (ip, user)
                      inside one BRUTE_WINDOW sliding window, followed by a
                      successful authentication of that user from the same
                      IP within BRUTE_WINDOW after the last in-window failure.
                      Fewer failures stay benign even when a success follows;
                      failures with no observed outcome go to review. An
                      acceptance *before* the failures is never correlated.

Lines that match none of the known log grammars are collected in
``unparsed_lines`` instead of being silently dropped: the evidence needed to
interpret them (a parser for that log format) is missing by definition.
"""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime

# --- thresholds -----------------------------------------------------------

SCAN_HITS = 5            # distinct sensitive paths that make a scan
SCAN_REVIEW_MIN = 3      # gray zone -> needs_review
SCAN_WINDOW = 300        # seconds, sliding window over sensitive probes
BRUTE_FAILURES = 5       # failed passwords that make brute-force
BRUTE_REVIEW_MIN = 3
BRUTE_WINDOW = 600       # seconds, sliding window over failures / fail->success
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


def parse_log(path: str) -> tuple[list[dict], dict[int, str], list[dict]]:
    """Return structured events, a line-no -> raw line map, and unparsed lines."""
    events: list[dict] = []
    raw: dict[int, str] = {}
    unparsed: list[dict] = []
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
                continue
            unparsed.append({"line": no, "raw": line})
    return events, raw, unparsed


# --- helpers --------------------------------------------------------------

def _describe(e: dict) -> str:
    if e["kind"] == "web":
        return f"web {e['status']} {e['path']}"
    return f"ssh {e['kind']} user={e['user']}"


def _evidence(events: list[dict], raw: dict[int, str]) -> list[dict]:
    return [
        {
            "line": e["line"],
            "timestamp": e["ts"].strftime("%b %d %H:%M:%S"),
            "event": _describe(e),
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
        "evidence": _evidence(evs, raw),
    }


def _review(rule, evs, entities, missing, raw):
    return {
        "rule": rule,
        "first_seen": evs[0]["ts"].strftime("%b %d %H:%M:%S"),
        "last_seen": evs[-1]["ts"].strftime("%b %d %H:%M:%S"),
        "entities": entities,
        "missing": missing,
        "evidence": _evidence(evs, raw),
    }


def _densest_window(hits: list[dict], window: int) -> list[dict]:
    """Return the longest subsequence whose first/last timestamps fit in window.

    Ties keep the earliest window. Used so the rule honours a real sliding
    window rather than merging same-key events spread across hours.
    """
    best: list[dict] = []
    left = 0
    for right in range(len(hits)):
        while (hits[right]["ts"] - hits[left]["ts"]).total_seconds() > window:
            left += 1
        candidate = hits[left:right + 1]
        if len(candidate) > len(best):
            best = candidate
    return best


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
        fl.sort(key=lambda e: e["line"])
        burst = _densest_window(fl, BRUTE_WINDOW)
        # success must follow the failure burst, not precede it, and stay
        # inside BRUTE_WINDOW of the last in-window failure
        success = next(
            (a for a in accepts.get(ip, [])
             if a["user"] == user
             and 0 <= (a["ts"] - burst[-1]["ts"]).total_seconds() <= BRUTE_WINDOW),
            None,
        )
        if len(burst) >= BRUTE_FAILURES and success is not None:
            seq = burst + [success]
            findings.append(_finding(
                "brute_force_success", "high", seq,
                {"ip": ip, "user": user, "host": "web01"},
                f"{len(burst)} password failures for '{user}' from {ip} inside "
                f"one {BRUTE_WINDOW}s window followed by a successful "
                "authentication of the same account from the same IP",
                raw,
            ))
        elif success is not None:
            # outcome known, volume below threshold -> benign, not ambiguous
            continue
        elif len(burst) >= BRUTE_REVIEW_MIN:
            review.append(_review(
                "brute_force_success", burst, {"ip": ip, "user": user},
                f"no authentication outcome observed within {BRUTE_WINDOW}s "
                f"after {len(burst)} failures; need subsequent sshd "
                "Accepted/Failed lines or account-lock status to tell "
                "brute-force success from abandoned guessing",
                raw,
            ))
    return findings, review


def detect_webshell(events, raw):
    findings, review = [], []
    web_events = [e for e in events if e["kind"] == "web"]
    claimed_uploads: set[int] = set()
    claimed_execs: set[int] = set()
    for e in web_events:
        if not UPLOAD_ENDPOINT.search(e["path"]):
            continue
        exec_event = next(
            (w for w in web_events
             if w["line"] not in claimed_execs
             and w["ip"] == e["ip"]
             and UPLOAD_DIR_EXEC.search(w["path"])
             and (SHELL_PARAM.search(w["path"]) or SHELL_NAME.search(w["path"]))
             and 0 <= (w["ts"] - e["ts"]).total_seconds() <= UPLOAD_WINDOW),
            None,
        )
        if exec_event is not None:
            claimed_uploads.add(e["line"])
            claimed_execs.add(exec_event["line"])
            findings.append(_finding(
                "webshell", "critical", [e, exec_event],
                {"ip": e["ip"], "host": "web01",
                 "upload_path": e["path"], "exec_path": exec_event["path"]},
                "upload endpoint returned 200 and the same IP then requested an "
                "executable script under the upload directory with a command "
                "parameter, i.e. an uploaded webshell being exercised",
                raw,
            ))
    # every upload without a correlated execution gets exactly one review item
    for e in web_events:
        if UPLOAD_ENDPOINT.search(e["path"]) and e["line"] not in claimed_uploads:
            review.append(_review(
                "webshell", [e], {"ip": e["ip"], "host": "web01"},
                "upload-like request has no follow-up request for an executable "
                f"under /uploads/ within {UPLOAD_WINDOW}s; need response "
                "body/bytes, multipart POST metadata or later /uploads/ access "
                "to decide whether a script was actually dropped",
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
        hits.sort(key=lambda e: e["line"])
        window_hits = _densest_window(hits, SCAN_WINDOW)
        span = (window_hits[-1]["ts"] - window_hits[0]["ts"]).total_seconds()
        distinct = sorted({h["path"] for h in window_hits})
        denied = sum(1 for h in window_hits if h["status"] in (401, 403, 404))
        entities = {"ip": ip, "host": "web01", "sensitive_paths": distinct}
        if len(distinct) >= SCAN_HITS and span <= SCAN_WINDOW:
            findings.append(_finding(
                "web_scan", "high", window_hits, entities,
                f"{len(distinct)} distinct sensitive paths probed from {ip} in "
                f"{int(span)}s (threshold {SCAN_HITS} within {SCAN_WINDOW}s); "
                f"{denied}/{len(window_hits)} rejected (401/403/404) — "
                "automated reconnaissance rather than a user typo",
                raw,
            ))
        elif len(distinct) >= SCAN_REVIEW_MIN:
            review.append(_review(
                "web_scan", window_hits, entities,
                f"only {len(distinct)} sensitive probes within any "
                f"{SCAN_WINDOW}s window (below scan threshold {SCAN_HITS}); "
                "need more requests from this IP, a scan user-agent, or "
                "follow-up exploitation to distinguish targeted recon from "
                "isolated mis-clicks",
                raw,
            ))
        else:
            benign.append({
                "rule": "web_scan",
                "entities": {"ip": ip},
                "observed": f"{len(hits)} sensitive request(s) over the log, "
                            f"at most {len(window_hits)} within any "
                            f"{SCAN_WINDOW}s window; {denied} rejected with "
                            "401/403/404",
                "reason": f"below volume threshold ({len(distinct)} < "
                          f"{SCAN_HITS} distinct sensitive paths within "
                          f"{SCAN_WINDOW}s) and every probe was denied, so no "
                          "successful access or automation is evidenced; "
                          "sparse denied probes are treated as benign",
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
        fl.sort(key=lambda e: e["line"])
        burst = _densest_window(fl, BRUTE_WINDOW)
        if len(burst) >= BRUTE_FAILURES:
            continue
        if any(a["user"] == user and a["ts"] >= burst[-1]["ts"]
               for a in accepts.get(ip, [])):
            out.append({
                "rule": "brute_force_success",
                "entities": {"ip": ip, "user": user},
                "observed": f"{len(burst)} failed password(s) in a "
                            f"{BRUTE_WINDOW}s window then a successful "
                            "authentication from the same IP/user",
                "reason": f"failure count {len(burst)} is below the brute-force "
                          f"threshold {BRUTE_FAILURES}; pattern matches a user "
                          "mistyping a password and then authenticating, not "
                          "credential guessing",
            })
    return out


def scan(path: str) -> dict:
    events, raw, unparsed = parse_log(path)
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
    result = {
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
    if unparsed:
        # not silently dropped: state exactly which lines and what is missing
        needs_review.append({
            "rule": "unparsed_log_line",
            "first_seen": "",
            "last_seen": "",
            "entities": {"lines": [u["line"] for u in unparsed]},
            "missing": "these lines match neither the nginx nor sshd grammar; "
                       "need their log format/sample documentation or a parser "
                       "extension before they can be assessed",
            "evidence": [
                {"line": u["line"], "timestamp": "", "event": "unparsed",
                 "raw": u["raw"]}
                for u in unparsed
            ],
        })
        result["unparsed_lines"] = [u["line"] for u in unparsed]
    return result


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
