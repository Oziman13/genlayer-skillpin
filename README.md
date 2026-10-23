# SkillPin

A tamper-evident pin for **one public instruction file** (for example a `skill.md`), as a GenLayer Intelligent Contract.

**The problem.** AI agents are told "read this URL and follow it". If the file at that URL changes after someone reviewed it, every agent that reads it follows the new text and nobody notices. SkillPin fixes the SHA-256 fingerprint of the reviewed version and lets anyone re-read the file later. Every validator downloads the file itself and must compute the identical hash and size, so a reading is not one party's word.

No AI model is involved: the check is a hash of the exact bytes.

| Step | Who | What happens |
|---|---|---|
| `witness()` | anyone, at most once per min interval | records `BASELINE` (first reading, when no reviewed hash was given), `UNCHANGED`, `CHANGED` or `UNREADABLE` |
| `rebase(sha256)` | owner (the deployer) only | after a legitimate update: accept the file exactly as last read as the new reviewed version; the old and new hash stay in the history |

An unreadable file (HTTP error, empty, larger than 200,000 bytes) is **never** counted as a change. Views: `get_state_json`, `get_history_json(i)`, `get_attestation` (`INTACT`, `CHANGED`, or `NONE` before any reading). The contract holds no funds.

## Constructor

`SkillPin(name, url, reviewed_sha256, min_interval_seconds)`

- `url`: `https://` plus a plain lower-case host name (no port, userinfo, fragment, spaces or non-ASCII characters), at most 300 characters.
- `reviewed_sha256`: 64 lower-case hex characters of the version someone reviewed, or `""` to take the first reading as the baseline.
- `min_interval_seconds`: 300 to 604800.

To get the hash of a file you reviewed: `curl -s URL | sha256sum` (the hash is of the exact bytes, so a changed trailing newline is a change).

## What the status means

- `INTACT`: at the last successful reading the file matched the pinned hash.
- `CHANGED`: at the last successful reading it differed. `changes`, `ever_changed` and `first_changed_at` keep the record even if the file later returns to the pinned bytes (then the status is `INTACT` again but `ever_changed` stays true).
- After `rebase`, `generation` increases and the file is compared with the accepted version from then on. The history shows who accepted which hash and when.

## Known limits (stated honestly)

- **Only readings are seen.** A change that is made and undone between two readings is invisible. Anyone can add readings, but nobody is paid or forced to.
- **Static files only.** If a server answers differently to different validators (per-request content, geo or user-agent variants), the validators disagree and the reading is not accepted. That is a failed transaction, not a false verdict. Plain files such as `raw.githubusercontent.com` or GitHub Pages are stable.
- It fingerprints bytes. It does not judge whether the text is safe (see SkillScan for that), and a file can be harmful from the start.
- Redirects, files above 200,000 bytes and non-200 answers are `UNREADABLE`.
- History holds 100 readings (10 more rows are reserved for `rebase`); after that `witness()` stops.
- The owner is the deploying account; there is no ownership transfer.
- A pin proves what the bytes were at reading time, not who wrote them.

## Tests

`pytest tests/direct` (genlayer-test direct mode, mocked web): 66 tests covering input validation, baseline, change and revert, reviewed hash, unreadable paths, interval, rebase rules, history limits and validator consensus (identical reading accepted; different bytes, bad shapes and lies rejected).
Plus 4 integration tests on a local 5-validator GenLayer network (`pytest tests/glsim`, glsim; real leader/validator rounds, web mocked): baseline and unchanged, change against a reviewed hash, rebase rules, unreadable first reading.
Mutation check: 30 of 34 deliberate breakages are caught; the other four are equivalent (redundant guards); see `evidence/mutation-checks.txt`.

## Live run

Deployed on Studionet: `0x2ffe18c68956A88726816E30C8A787e7b278F27e`, pinning `https://oziman13.github.io/genlayer-milestone-oracle-app/web/skill.md` with a 300 s minimum interval.

| Step | Result |
|---|---|
| `witness()` | `BASELINE`, 2897 bytes, sha256 `b4f03173...9caa` |
| `witness()` 335 s later | `UNCHANGED`, same bytes and hash |
| `get_state_json` | `INTACT`, 2 readings, 0 changes |

Both transactions are FINALIZED with result SUCCESS. Full record: `evidence/live-run-1.txt`. The `CHANGED` and `rebase` paths are covered by the local tests, not yet by a live run.
