# v0.1.0
# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import hashlib
import json

# SkillPin -- a tamper-evident pin for ONE public instruction file (for example a skill.md).
#
# Agents are told to "read this URL and follow it". If that file changes after someone reviewed it,
# the agent follows the new text without anyone noticing. SkillPin fixes the fingerprint (SHA-256 of
# the exact bytes) of the reviewed version and lets ANYONE re-read the file later. Every validator
# downloads the file itself and must compute the identical hash and size, so a reading is not one
# party's word. No model is involved.
#
#   witness()   anyone, at most once per min interval: records BASELINE (first reading, when no
#               reviewed hash was given), UNCHANGED, CHANGED or UNREADABLE
#   rebase()    owner only: accept the file as it is now as the new reviewed version (visible in history)
#
# An unreadable file is never counted as a change. Only the bytes at reading time are seen: a change that
# is undone between two readings is invisible. No funds are held; the status is an attestation others may read.

MAX_BYTES = 200000
MAX_HISTORY = 100          # witness() stops here; rebase() may use the 10 reserved rows
MAX_HISTORY_RESERVED = 110
HEX = "0123456789abcdef"


def _bounded(text, minimum: int, maximum: int, name: str) -> str:
    if not isinstance(text, str) or not text.strip() or not minimum <= len(text.strip()) <= maximum:
        raise gl.vm.UserError("invalid " + name)
    return text.strip()


def _host_ok(host: str) -> bool:
    labels = host.split(".")
    return not (len(host) > 253 or len(labels) < 2 or not labels[-1].isalpha() or len(labels[-1]) < 2
                or labels[-1] in ("local", "localhost", "internal", "test", "invalid")
                or any(not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
                       or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label)
                       for label in labels))


def _https_url(text) -> str:
    """An https URL with a plain host name: no userinfo, port, fragment, spaces or control characters."""
    if not isinstance(text, str) or not 12 <= len(text) <= 300 or text != text.strip():
        raise gl.vm.UserError("invalid url")
    if not text.startswith("https://"):
        raise gl.vm.UserError("invalid url")
    if any(ord(c) <= 32 or ord(c) >= 127 or c in '"<>\\^`{|}#' for c in text):
        raise gl.vm.UserError("invalid url")
    authority = text[8:].split("/")[0].split("?")[0]
    if not authority or "@" in authority or ":" in authority or authority != authority.lower() or not _host_ok(authority):
        raise gl.vm.UserError("invalid url")
    return text


def _sha_or_empty(text) -> str:
    if text == "":
        return ""
    if not isinstance(text, str) or len(text) != 64 or any(c not in HEX for c in text):
        raise gl.vm.UserError("invalid sha256")
    return text


# -- time and date, parsed by hand --------------------------------------------

def _digits(text: str, size: int) -> bool:
    return len(text) == size and all(c in "0123456789" for c in text)


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def _civil(text):
    if not isinstance(text, str) or len(text) != 10 or text[4] != "-" or text[7] != "-":
        raise gl.vm.UserError("date must be YYYY-MM-DD")
    y, m, d = text[0:4], text[5:7], text[8:10]
    if not (_digits(y, 4) and _digits(m, 2) and _digits(d, 2)):
        raise gl.vm.UserError("date must be YYYY-MM-DD")
    year, month, day = int(y), int(m), int(d)
    if year < 1970 or not 1 <= month <= 12 or not 1 <= day <= _days_in_month(year, month):
        raise gl.vm.UserError("date must be YYYY-MM-DD")
    return year, month, day


def _epoch_days(year: int, month: int, day: int) -> int:
    year -= 1 if month <= 2 else 0
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _timestamp(raw) -> int:
    """Parse YYYY-MM-DDTHH:MM:SS[.fff](Z|+hh:mm)."""
    if not isinstance(raw, str) or len(raw) < 19 or raw[10] not in ("T", " "):
        raise gl.vm.UserError("unreadable timestamp")
    year, month, day = _civil(raw[0:10])
    clock = raw[11:19]
    if not (_digits(clock[0:2], 2) and clock[2] == ":" and _digits(clock[3:5], 2)
            and clock[5] == ":" and _digits(clock[6:8], 2)):
        raise gl.vm.UserError("unreadable timestamp")
    if int(clock[0:2]) > 23 or int(clock[3:5]) > 59 or int(clock[6:8]) > 60:
        raise gl.vm.UserError("unreadable timestamp")
    rest = raw[19:]
    if rest.startswith("."):
        end = 1
        while end < len(rest) and rest[end] in "0123456789":
            end += 1
        rest = rest[end:]
    offset = 0
    if rest in ("Z", "z", ""):
        offset = 0
    elif len(rest) == 6 and rest[0] in "+-" and rest[3] == ":" and _digits(rest[1:3], 2) and _digits(rest[4:6], 2):
        offset = (int(rest[1:3]) * 3600 + int(rest[4:6]) * 60) * (1 if rest[0] == "+" else -1)
    else:
        raise gl.vm.UserError("unreadable timestamp")
    return (_epoch_days(year, month, day) * 86400
            + int(clock[0:2]) * 3600 + int(clock[3:5]) * 60 + int(clock[6:8]) - offset)


def _now() -> int:
    """Seconds since the epoch from the transaction's consensus timestamp."""
    return _timestamp(gl.message_raw["datetime"])


def _day_start(date_text: str) -> int:
    year, month, day = _civil(date_text)
    return _epoch_days(year, month, day) * 86400


# -- reading the file ---------------------------------------------------------------

def _fetch(url: str):
    response = gl.nondet.web.get(url, headers={"User-Agent": "genlayer-skillpin", "Accept": "*/*"})
    body = response.body or b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    return int(response.status), bytes(body[:MAX_BYTES + 1])


def _error(reason: str) -> dict:
    return {"state": "ERROR", "reason": reason}


def _reading(url: str) -> dict:
    """Never raises. A pure function of the downloaded bytes, so validators reproduce it exactly."""
    try:
        status, body = _fetch(url)
        if status != 200:
            return _error("http")
        if len(body) > MAX_BYTES:
            return _error("too_large")
        if len(body) == 0:
            return _error("empty")
        return {"state": "OK", "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)}
    except Exception:
        return _error("unreadable")


def _canonical(reading: dict) -> str:
    return json.dumps(reading, sort_keys=True)


def _valid_shape(value) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("state") == "ERROR":
        return set(value) == {"state", "reason"} and isinstance(value["reason"], str)
    return (value.get("state") == "OK" and set(value) == {"state", "sha256", "bytes"}
            and isinstance(value["sha256"], str) and len(value["sha256"]) == 64
            and all(c in HEX for c in value["sha256"])
            and type(value["bytes"]) is int and 1 <= value["bytes"] <= MAX_BYTES)


def _consensus(url: str) -> dict:
    """Validators download the file themselves and must compute the identical reading."""
    def leader() -> str:
        return _canonical(_reading(url))

    def validator(result) -> bool:
        if not isinstance(result, gl.vm.Return):
            return False
        proposed = result.calldata
        if not isinstance(proposed, str) or len(proposed) > 400:
            return False
        try:
            parsed = json.loads(proposed)
        except Exception:
            return False
        if not _valid_shape(parsed):
            return False
        return proposed == _canonical(_reading(url))

    return json.loads(gl.vm.run_nondet(leader, validator))


class SkillPin(gl.Contract):
    """Tamper-evident pin for one public instruction file. Holds no funds."""
    name: str
    url: str
    owner: str
    min_interval: u32
    reviewed: str               # the reviewed hash given at deployment, or ""
    baseline: str               # the hash the file is compared with, "" until the first reading
    baseline_bytes: u32
    generation: u32             # 0 at deployment, +1 for every rebase
    status: str                 # NEW | INTACT | CHANGED
    ever_changed: bool
    first_changed_at: bigint
    last_hash: str
    last_bytes: u32
    last_ok_at: bigint
    last_checked: bigint
    readings: u32
    unreadable: u32
    changes: u32
    history_count: u32
    history: TreeMap[u32, str]

    def __init__(self, name: str, url: str, reviewed_sha256: str, min_interval_seconds: int):
        if type(min_interval_seconds) is not int or not 300 <= min_interval_seconds <= 604800:
            raise gl.vm.UserError("min interval must be 300..604800 seconds")
        self.name = _bounded(name, 2, 100, "name")
        self.url = _https_url(url)
        reviewed = _sha_or_empty(reviewed_sha256)
        self.owner = str(gl.message.sender_address).lower()
        self.min_interval = u32(min_interval_seconds)
        self.reviewed = reviewed
        self.baseline = reviewed
        self.baseline_bytes = u32(0)
        self.generation = u32(0)
        self.status = "NEW"
        self.ever_changed = False
        self.first_changed_at = bigint(0)
        self.last_hash = ""
        self.last_bytes = u32(0)
        self.last_ok_at = bigint(0)
        self.last_checked = bigint(0)
        self.readings = u32(0)
        self.unreadable = u32(0)
        self.changes = u32(0)
        self.history_count = u32(0)

    # -- helpers -------------------------------------------------------------------

    def _record(self, action: str, reading: dict, now: int, limit: int, extra: dict = None) -> None:
        if int(self.history_count) >= limit:
            raise gl.vm.UserError("history is full")
        index = self.history_count
        row = {"id": int(index), "action": action, "status": self.status, "reading": reading,
               "baseline": self.baseline, "generation": int(self.generation), "timestamp": now,
               "caller": str(gl.message.sender_address).lower()}
        if extra:
            row.update(extra)
        self.history[index] = json.dumps(row, sort_keys=True)
        self.history_count = u32(int(index) + 1)

    # -- actions -------------------------------------------------------------------

    @gl.public.write
    def witness(self) -> str:
        """Anyone may re-read the file. Returns BASELINE, UNCHANGED, CHANGED or UNREADABLE."""
        if int(self.history_count) >= MAX_HISTORY:
            raise gl.vm.UserError("history is full")
        now = _now()
        if int(self.last_checked) > 0 and now < int(self.last_checked) + int(self.min_interval):
            raise gl.vm.UserError("too soon since the last reading")
        reading = _consensus(self.url)          # storage is copied into the closure arguments first
        self.last_checked = bigint(now)
        if reading["state"] != "OK":
            self.unreadable = u32(int(self.unreadable) + 1)
            self._record("UNREADABLE", reading, now, MAX_HISTORY)
            return "UNREADABLE"
        digest = reading["sha256"]
        self.readings = u32(int(self.readings) + 1)
        self.last_hash = digest
        self.last_bytes = u32(reading["bytes"])
        self.last_ok_at = bigint(now)
        if self.baseline == "":
            self.baseline = digest
            self.baseline_bytes = u32(reading["bytes"])
            self.status = "INTACT"
            outcome = "BASELINE"
        elif digest == self.baseline:
            if int(self.baseline_bytes) == 0:
                self.baseline_bytes = u32(reading["bytes"])
            self.status = "INTACT"
            outcome = "UNCHANGED"
        else:
            self.status = "CHANGED"
            self.changes = u32(int(self.changes) + 1)
            if not self.ever_changed:
                self.ever_changed = True
                self.first_changed_at = bigint(now)
            outcome = "CHANGED"
        self._record(outcome, reading, now, MAX_HISTORY)
        return outcome

    @gl.public.write
    def rebase(self, new_sha256: str) -> str:
        """Owner only. After a legitimate update, accept the file exactly as last read as the new reviewed version."""
        if str(gl.message.sender_address).lower() != self.owner:
            raise gl.vm.UserError("only the owner can rebase")
        if self.status != "CHANGED":
            raise gl.vm.UserError("nothing to accept: the file does not differ from the pin")
        digest = _sha_or_empty(new_sha256)
        if digest == "" or digest != self.last_hash:
            raise gl.vm.UserError("hash is not the one last read")
        now = _now()
        previous = self.baseline
        self.baseline = digest
        self.baseline_bytes = self.last_bytes
        self.generation = u32(int(self.generation) + 1)
        self.status = "INTACT"
        self._record("REBASED", {"state": "OK", "sha256": digest, "bytes": int(self.last_bytes)}, now,
                     MAX_HISTORY_RESERVED, {"previous_baseline": previous})
        return "REBASED"

    # -- views ---------------------------------------------------------------------

    @gl.public.view
    def get_state_json(self) -> str:
        return json.dumps({
            "name": self.name, "url": self.url, "owner": self.owner, "min_interval": int(self.min_interval),
            "reviewed": self.reviewed, "baseline": self.baseline, "baseline_bytes": int(self.baseline_bytes),
            "generation": int(self.generation), "status": self.status, "ever_changed": self.ever_changed,
            "first_changed_at": int(self.first_changed_at), "last_hash": self.last_hash,
            "last_bytes": int(self.last_bytes), "last_ok_at": int(self.last_ok_at),
            "last_checked": int(self.last_checked), "readings": int(self.readings),
            "unreadable": int(self.unreadable), "changes": int(self.changes),
            "history_count": int(self.history_count),
        }, sort_keys=True)

    @gl.public.view
    def get_attestation(self) -> str:
        """INTACT or CHANGED as of the last successful reading; NONE before any reading."""
        return "NONE" if self.status == "NEW" else self.status

    @gl.public.view
    def get_history_json(self, index: int) -> str:
        if type(index) is not int or index < 0 or index >= int(self.history_count):
            raise gl.vm.UserError("history index out of range")
        return self.history[u32(index)]
