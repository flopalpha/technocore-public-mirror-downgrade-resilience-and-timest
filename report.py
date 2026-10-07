"""Build local JSON and HTML reports."""
import html
import json


def make_report(announcement, mirrors, audits, alignments, lint_result, drift_result):
    if not isinstance(announcement, dict):
        announcement = {}
    if not isinstance(mirrors, list):
        mirrors = []
    room = announcement.get("room", "")
    seq = announcement.get("seq", 0)
    version = announcement.get("version", "")
    content_hash = announcement.get("hash", "")
    rows = []
    for i, m in enumerate(mirrors):
        url = ""
        ver = ""
        h = ""
        if isinstance(m, dict):
            url = str(m.get("url", ""))
            ver = str(m.get("version", ""))
            h = str(m.get("hash", ""))
        status = "unknown"
        notes = ""
        if i < len(alignments) and isinstance(alignments[i], dict):
            item = alignments[i]
            if item.get("passed"):
                status = "pass"
            else:
                status = "fail"
            notes = "; ".join(item.get("reasons", []))
        rows.append({"url": url, "version": ver, "hash": h, "status": status, "notes": notes})
    audit_pass = 0
    for a in audits:
        if isinstance(a, dict) and a.get("passed"):
            audit_pass = audit_pass + 1
    lint_ok = False
    if isinstance(lint_result, dict):
        lint_ok = bool(lint_result.get("passed"))
    drift_ok = False
    if isinstance(drift_result, dict):
        drift_ok = bool(drift_result.get("passed"))
    summary = {
        "mirrors_total": len(mirrors),
        "audits_total": len(audits),
        "audits_passed": audit_pass,
        "lint_passed": lint_ok,
        "drift_passed": drift_ok,
    }
    return {
        "room": room,
        "seq": seq,
        "version": version,
        "hash": content_hash,
        "summary": summary,
        "mirrors": rows,
        "lint": lint_result,
        "drift": drift_result,
        "audits": audits,
    }


def to_json(data):
    return json.dumps(data, indent=2, sort_keys=True)


def to_html(data):
    room = html.escape(str(data.get("room", "")))
    seq = html.escape(str(data.get("seq", "")))
    version = html.escape(str(data.get("version", "")))
    content_hash = html.escape(str(data.get("hash", "")))
    summary = data.get("summary", {})
    mirrors = data.get("mirrors", [])
    parts = []
    parts.append("<!doctype html>")
    parts.append("<html><head><meta charset='utf-8'>")
    parts.append("<title>Mirror check report</title></head><body>")
    parts.append("<h1>Mirror check report</h1>")
    parts.append("<p>Room: " + room + " Seq: " + seq + "</p>")
    parts.append("<p>Version: " + version + " Hash: " + content_hash + "</p>")
    parts.append("<h2>Summary</h2>")
    parts.append("<p>" + html.escape(str(summary)) + "</p>")
    parts.append("<h2>Mirrors</h2>")
    parts.append("<table border='1'><tr><th>URL</th><th>Hash</th><th>Status</th></tr>")
    for m in mirrors:
        url = html.escape(str(m.get("url", "")))
        h = html.escape(str(m.get("hash", "")))
        status = html.escape(str(m.get("status", "")))
        row = "<tr><td>" + url + "</td><td>" + h + "</td><td>" + status + "</td></tr>"
        parts.append(row)
    parts.append("</table></body></html>")
    return "\n".join(parts)
