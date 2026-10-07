"""Command line interface for mirror checks."""
import argparse
import json
import pathlib
import urllib.parse

import mirror_check
import report


def load_json(path):
    text = pathlib.Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def load_text(path):
    return pathlib.Path(path).read_text(encoding="utf-8")


def build_parser():
    p = argparse.ArgumentParser(description="Mirror downgrade and timestamp-distrust checker")
    p.add_argument("--doc-file", default="", help="Path to public doc text file")
    p.add_argument("--announcement-file", default="", help="Path to announcement JSON file")
    p.add_argument("--mirrors-file", default="", help="Path to mirrors JSON file")
    p.add_argument("--claims-file", default="", help="Path to claims JSON file")
    p.add_argument("--fetch-url", default="", help="Single public http(s) URL to fetch and hash")
    p.add_argument("--out-json", default="", help="Path to write JSON report")
    p.add_argument("--out-html", default="", help="Path to write HTML report")
    p.add_argument("--timeout", type=int, default=10, help="Fetch timeout seconds")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.fetch_url:
        data = mirror_check.fetch_url(args.fetch_url, timeout=args.timeout)
        digest = mirror_check.hash_canonical(data)
        print("url: " + args.fetch_url)
        print("sha256: " + digest)
        print("bytes: " + str(len(data)))
        return 0
    announcement = {}
    mirrors = []
    claims = []
    doc_text = ""
    if args.announcement_file:
        announcement = load_json(args.announcement_file)
    if args.mirrors_file:
        loaded = load_json(args.mirrors_file)
        if isinstance(loaded, list):
            mirrors = loaded
    if args.claims_file:
        loaded = load_json(args.claims_file)
        if isinstance(loaded, list):
            claims = loaded
    if args.doc_file:
        doc_text = load_text(args.doc_file)
    audits = [mirror_check.audit_claim(c) for c in claims]
    alignments = []
    for m in mirrors:
        alignments.append(mirror_check.check_alignment(announcement, m))
    lint_result = mirror_check.lint_doc(doc_text) if doc_text else mirror_check.lint_doc("")
    drift_result = mirror_check.check_drift(mirrors)
    rep = report.make_report(announcement, mirrors, audits, alignments, lint_result, drift_result)
    json_text = report.to_json(rep)
    html_text = report.to_html(rep)
    if args.out_json:
        pathlib.Path(args.out_json).write_text(json_text, encoding="utf-8")
    else:
        print(json_text)
    if args.out_html:
        pathlib.Path(args.out_html).write_text(html_text, encoding="utf-8")
    failed = 0
    for a in audits:
        if not a.get("passed"):
            failed = failed + 1
    for a in alignments:
        if not a.get("passed"):
            failed = failed + 1
    if not drift_result.get("passed") and len(mirrors) > 0:
        failed = failed + 1
    if claims or mirrors:
        return 1 if failed > 0 else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
