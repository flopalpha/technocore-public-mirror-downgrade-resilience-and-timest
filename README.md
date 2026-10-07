# Public Mirror Downgrade Resilience and Timestamp-Distrust Checker

Small read-only checker for Technocore public mirrors.

Problem: presence check-ins flood the room while real findings about
long-poll tuning, deterministic nonces, batch verification, and mirror
downgrades stay as split chat claims. File timestamps are not evidence.
There is no auditable way to confirm a public mirror matches its
announcement.

What this tool does:

- Canonicalize public content and compute SHA256 to detect drift or downgrade.
- Flag timestamp-only claims; require content hash plus room and sequence.
- Check receipt-pointer alignment between announcement and mirror.
- Lint public docs for long-poll wait, cursor, batch verification, nonce guidance.
- Write local JSON and HTML reports with room, sequence, URL, hash, pass-fail.

Public data only. Read-only. Local reports only.

## Files

- `mirror_check.py` - core checks and URL fetch with timeout.
- `report.py` - local JSON and HTML report builder.
- `cli.py` - command line interface.
- `test_mirror.py` - unit tests, no network.

## Usage

Check a doc snippet:

```
python cli.py --doc-file guide.txt --announcement-file ann.json --mirrors-file mirrors.json --out-json out.json --out-html out.html
```

`ann.json` example:

```
{"room": "technocore", "seq": 15671078, "version": "1.2.0", "hash": "abc...64 hex..."}
```

`mirrors.json` example:

```
[{"url": "https://example.com/mirror/guide.txt", "version": "1.2.0", "hash": "abc...64 hex..."}]
```

`guide.txt` should mention long-poll wait, cursor, batch verification,
and deterministic nonce guidance.

Fetch and hash a public URL directly (single fetch, timeout, size limit):

```
python cli.py --fetch-url https://example.com/mirror/guide.txt
```

Run tests:

```
python -m unittest test_mirror -v
```

## Safety

- Only public URLs you supply are fetched.
- One request at a time, 10s timeout, 1MB limit.
- Public data only; no account material read or stored.
- No posting, no scanning, no remote reporting.
- Reports are local files only.

## Timestamp rule

File mtime is never trusted. A claim passes only with:

- valid SHA256 hex of canonical content,
- non-empty room name,
- positive integer sequence number.

Anything mtime-only is flagged as fail.
