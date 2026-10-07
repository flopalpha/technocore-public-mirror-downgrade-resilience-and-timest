"""Core checks for public mirror consistency and timestamp distrust."""
import hashlib
import re
import urllib.parse
import urllib.request


def canonicalize(data):
    """Normalize bytes for stable hashing."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    text = data.decode("utf-8", errors="replace")
    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")
    lines = text.split("\n")
    cleaned = []
    for line in lines:
        cleaned.append(line.rstrip(" \t"))
    while len(cleaned) > 2:
        if cleaned[-1] == "" and cleaned[-2] == "":
            cleaned.pop()
        else:
            break
    out = "\n".join(cleaned)
    return out.encode("utf-8")


def sha256_hex(data):
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).hexdigest()


def hash_canonical(data):
    return sha256_hex(canonicalize(data))


def is_hex64(value):
    if not isinstance(value, str):
        return False
    if len(value) != 64:
        return False
    allowed = set("0123456789abcdefABCDEF")
    for ch in value:
        if ch not in allowed:
            return False
    return True


def parse_version(value):
    if not isinstance(value, str):
        return (0,)
    parts = re.findall(r"\d+", value)
    nums = []
    for p in parts[:4]:
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)
    if not nums:
        return (0,)
    return tuple(nums)


def compare_versions(left, right):
    a = parse_version(left)
    b = parse_version(right)
    size = max(len(a), len(b))
    aa = list(a) + [0] * (size - len(a))
    bb = list(b) + [0] * (size - len(b))
    for x, y in zip(aa, bb):
        if x < y:
            return -1
        if x > y:
            return 1
    return 0


def audit_claim(claim):
    reasons = []
    passed = True
    if not isinstance(claim, dict):
        return {"passed": False, "reasons": ["claim must be an object"]}
    h = claim.get("hash", "")
    room = claim.get("room", "")
    seq = claim.get("seq", None)
    has_mtime = "mtime" in claim and claim.get("mtime") is not None
    hash_ok = is_hex64(h) if isinstance(h, str) else False
    room_ok = isinstance(room, str) and len(room.strip()) > 0
    seq_ok = isinstance(seq, int) and not isinstance(seq, bool) and seq > 0
    if not hash_ok:
        passed = False
        reasons.append("missing or invalid content hash; hash required")
    if not room_ok:
        passed = False
        reasons.append("missing room reference")
    if not seq_ok:
        passed = False
        reasons.append("missing or invalid sequence reference")
    if has_mtime and not (hash_ok and room_ok and seq_ok):
        passed = False
        reasons.append("mtime-only claim flagged; timestamps are not evidence")
    if has_mtime and (hash_ok and room_ok and seq_ok):
        reasons.append("mtime present but ignored; hash plus sequence used")
    if passed:
        reasons.append("ok: hash plus room sequence present; mtime ignored")
    return {"passed": passed, "reasons": reasons}


def is_public_http_url(url):
    if not isinstance(url, str):
        return False
    try:
        parts = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    if not parts.hostname:
        return False
    return True


def check_alignment(announcement, mirror):
    reasons = []
    passed = True
    if not isinstance(announcement, dict):
        return {"passed": False, "reasons": ["announcement must be an object"]}
    if not isinstance(mirror, dict):
        return {"passed": False, "reasons": ["mirror must be an object"]}
    room = announcement.get("room", "")
    seq = announcement.get("seq", None)
    ann_ver = announcement.get("version", "")
    ann_hash = announcement.get("hash", "")
    mir_url = mirror.get("url", "")
    mir_ver = mirror.get("version", "")
    mir_hash = mirror.get("hash", "")
    room_ok = isinstance(room, str) and len(room.strip()) > 0
    seq_ok = isinstance(seq, int) and not isinstance(seq, bool) and seq > 0
    hash_ok = isinstance(ann_hash, str) and is_hex64(ann_hash)
    if not room_ok:
        passed = False
        reasons.append("announcement missing room")
    if not seq_ok:
        passed = False
        reasons.append("announcement missing sequence")
    if not hash_ok:
        passed = False
        reasons.append("announcement missing valid hash")
    if not is_public_http_url(mir_url):
        passed = False
        reasons.append("mirror url must be public http or https")
    if not isinstance(mir_ver, str) or not mir_ver.strip():
        passed = False
        reasons.append("mirror missing version marker")
    if not isinstance(mir_hash, str) or not is_hex64(mir_hash):
        passed = False
        reasons.append("mirror missing valid hash")
    if passed:
        cmp = compare_versions(str(mir_ver), str(ann_ver))
        if cmp < 0:
            passed = False
            reasons.append("downgrade: mirror version below announcement")
        elif cmp > 0:
            reasons.append("note: mirror version ahead of announcement")
        else:
            reasons.append("ok: version markers match")
        if str(mir_hash).lower() != str(ann_hash).lower():
            passed = False
            reasons.append("drift: mirror hash differs from announcement")
        else:
            reasons.append("ok: hashes match")
    return {"passed": passed, "reasons": reasons}


def lint_doc(text):
    if not isinstance(text, str):
        text = ""
    low = text.lower()
    has_wait = ("long" in low and "poll" in low and "wait" in low)
    has_cursor = "cursor" in low
    has_batch = ("batch" in low and "verif" in low)
    has_nonce = ("nonce" in low and "determin" in low)
    topics = {
        "long_poll_wait": has_wait,
        "cursor": has_cursor,
        "batch_verification": has_batch,
        "nonce_determinism": has_nonce,
    }
    missing = []
    for key in sorted(topics.keys()):
        if not topics[key]:
            missing.append(key)
    passed = len(missing) == 0
    reasons = []
    if has_wait:
        reasons.append("ok: long-poll wait guidance present")
    else:
        reasons.append("missing long-poll wait guidance")
    if has_cursor:
        reasons.append("ok: cursor usage present")
    else:
        reasons.append("missing cursor usage")
    if has_batch:
        reasons.append("ok: batch verification present")
    else:
        reasons.append("missing batch verification")
    if has_nonce:
        reasons.append("ok: nonce determinism present")
    else:
        reasons.append("missing nonce determinism")
    return {"passed": passed, "topics": topics, "missing": missing, "reasons": reasons}


def check_drift(mirrors):
    if not isinstance(mirrors, list) or len(mirrors) == 0:
        return {"passed": False, "unique_hashes": [], "reasons": ["no mirrors supplied"]}
    hashes = []
    for m in mirrors:
        if isinstance(m, dict):
            h = m.get("hash", "")
            if isinstance(h, str) and is_hex64(h):
                hashes.append(h.lower())
    unique = sorted(set(hashes))
    if len(hashes) != len(mirrors):
        return {"passed": False, "unique_hashes": unique, "reasons": ["some mirrors lack valid hash"]}
    if len(unique) == 1:
        return {"passed": True, "unique_hashes": unique, "reasons": ["ok: all mirrors share one hash"]}
    return {"passed": False, "unique_hashes": unique, "reasons": ["drift: mirrors disagree"]}


def fetch_url(url, timeout=10, max_bytes=1000000):
    if not is_public_http_url(url):
        raise ValueError("only public http or https urls allowed")
    if timeout < 1:
        timeout = 1
    if timeout > 30:
        timeout = 30
    req = urllib.request.Request(url, headers={"User-Agent": "mirror-check/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("content too large")
    return data
