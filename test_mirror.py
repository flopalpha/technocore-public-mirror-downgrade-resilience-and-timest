"""Tests for mirror checks. No network. Uses tempfile only."""
import json
import pathlib
import tempfile
import unittest

import mirror_check
import report

GOOD_HASH = "a" * 64
OTHER_HASH = "b" * 64


class MirrorCheckTest(unittest.TestCase):
    def test_canonicalize_line_endings(self):
        a = b"hello \r\nworld\r\n"
        b = b"hello\nworld\n"
        self.assertEqual(mirror_check.canonicalize(a), mirror_check.canonicalize(b))

    def test_hash_stable(self):
        data = b"public content v1"
        h1 = mirror_check.hash_canonical(data)
        h2 = mirror_check.hash_canonical(data)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_audit_rejects_mtime_only(self):
        claim = {"mtime": 1234567890, "room": "", "hash": ""}
        result = mirror_check.audit_claim(claim)
        self.assertFalse(result["passed"])
        joined = " ".join(result["reasons"])
        self.assertIn("mtime", joined.lower())

    def test_audit_accepts_good_claim(self):
        claim = {"room": "technocore", "seq": 15671078, "hash": GOOD_HASH}
        result = mirror_check.audit_claim(claim)
        self.assertTrue(result["passed"])

    def test_audit_requires_sequence(self):
        claim = {"room": "technocore", "hash": GOOD_HASH}
        result = mirror_check.audit_claim(claim)
        self.assertFalse(result["passed"])

    def test_alignment_pass(self):
        ann = {"room": "technocore", "seq": 10, "version": "1.2.0", "hash": GOOD_HASH}
        mir = {"url": "https://example.com/a.txt", "version": "1.2.0", "hash": GOOD_HASH}
        result = mirror_check.check_alignment(ann, mir)
        self.assertTrue(result["passed"])

    def test_alignment_detects_downgrade(self):
        ann = {"room": "technocore", "seq": 10, "version": "1.2.0", "hash": GOOD_HASH}
        mir = {"url": "https://example.com/a.txt", "version": "1.1.0", "hash": GOOD_HASH}
        result = mirror_check.check_alignment(ann, mir)
        self.assertFalse(result["passed"])

    def test_alignment_detects_drift(self):
        ann = {"room": "technocore", "seq": 10, "version": "1.2.0", "hash": GOOD_HASH}
        mir = {"url": "https://example.com/a.txt", "version": "1.2.0", "hash": OTHER_HASH}
        result = mirror_check.check_alignment(ann, mir)
        self.assertFalse(result["passed"])

    def test_lint_finds_all_topics(self):
        text = "Use long-poll with wait 10 and sequence cursor. Batch verification cuts memory. Nonce deterministic."
        result = mirror_check.lint_doc(text)
        self.assertTrue(result["passed"])
        self.assertTrue(result["topics"]["cursor"])

    def test_lint_missing_topics(self):
        result = mirror_check.lint_doc("hello world")
        self.assertFalse(result["passed"])
        self.assertTrue(len(result["missing"]) > 0)

    def test_drift_detects_change(self):
        mirrors = [
            {"url": "https://example.com/a", "hash": GOOD_HASH},
            {"url": "https://example.com/b", "hash": OTHER_HASH},
        ]
        result = mirror_check.check_drift(mirrors)
        self.assertFalse(result["passed"])

    def test_drift_pass_single_hash(self):
        mirrors = [
            {"url": "https://example.com/a", "hash": GOOD_HASH},
            {"url": "https://example.com/b", "hash": GOOD_HASH},
        ]
        result = mirror_check.check_drift(mirrors)
        self.assertTrue(result["passed"])

    def test_report_files_with_tempfile(self):
        ann = {"room": "technocore", "seq": 15671078, "version": "1.2.0", "hash": GOOD_HASH}
        mirrors = [{"url": "https://example.com/a.txt", "version": "1.2.0", "hash": GOOD_HASH}]
        audits = [mirror_check.audit_claim({"room": "technocore", "seq": 1, "hash": GOOD_HASH})]
        alignments = [mirror_check.check_alignment(ann, mirrors[0])]
        lint_result = mirror_check.lint_doc("long poll wait cursor batch verification nonce deterministic")
        drift_result = mirror_check.check_drift(mirrors)
        rep = report.make_report(ann, mirrors, audits, alignments, lint_result, drift_result)
        with tempfile.TemporaryDirectory() as tmp:
            out_json = pathlib.Path(tmp).joinpath("out.json")
            out_html = pathlib.Path(tmp).joinpath("out.html")
            out_json.write_text(report.to_json(rep), encoding="utf-8")
            out_html.write_text(report.to_html(rep), encoding="utf-8")
            back = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(back["room"], "technocore")
            self.assertEqual(back["seq"], 15671078)
            html_text = out_html.read_text(encoding="utf-8")
            self.assertIn("technocore", html_text)
            self.assertIn("pass", html_text)

    def test_fetch_rejects_bad_scheme(self):
        with self.assertRaises(ValueError):
            mirror_check.fetch_url("ftp://example.com/file.txt", timeout=2)


if __name__ == "__main__":
    unittest.main()
