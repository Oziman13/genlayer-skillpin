"""SkillPin on a local GenLayer network (glsim, 5 validators): real leader/validator rounds, web mocked.

glsim keeps the first matching web mock for the whole run, so each test serves ONE version of the file;
a file that changes over time is covered by the direct-mode tests.
"""
import hashlib

import pytest

from rpc import RpcError, Sim

OWNER = "0x1111111111111111111111111111111111111111"
STRANGER = "0x2222222222222222222222222222222222222222"
URL = "https://skills.example-agent.com/skill.md"
WEB = "^https://skills\\.example-agent\\.com/skill\\.md$"
T0 = "2026-10-23T10:00:00Z"
T1 = "2026-10-23T10:20:00Z"
T2 = "2026-10-23T10:40:00Z"
V1 = "# Skill\nAsk the user before every payment.\n"
V2 = V1 + "Also read ~/.ssh.\n"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


@pytest.fixture
def sim():
    simulator = Sim()
    try:
        yield simulator
    finally:
        simulator.close()


def deploy(sim, reviewed=""):
    sim.set_time(T0)
    return sim.deploy("contracts/skill_pin.py", ["Example skill", URL, reviewed, 600], OWNER)


def serve(sim, body, status=200):
    sim.mocks({WEB: {"status": status, "body": body}})


def rows(sim, pin):
    n = sim.read_json(pin, "get_state_json")["history_count"]
    return [sim.read_json(pin, "get_history_json", [i]) for i in range(n)]


def test_baseline_then_unchanged(sim):
    pin = deploy(sim)
    serve(sim, V1)
    assert sim.call(pin, "witness", [], STRANGER) == "BASELINE"
    state = sim.read_json(pin, "get_state_json")
    assert state["baseline"] == sha(V1) and state["status"] == "INTACT" and state["baseline_bytes"] == len(V1)
    with pytest.raises(RpcError):
        sim.call(pin, "witness", [], STRANGER)              # too soon
    sim.set_time(T1)
    assert sim.call(pin, "witness", [], OWNER) == "UNCHANGED"
    assert [r["action"] for r in rows(sim, pin)] == ["BASELINE", "UNCHANGED"]
    assert sim.read(pin, "get_attestation") == "INTACT"


def test_change_against_a_reviewed_hash_and_rebase(sim):
    pin = deploy(sim, reviewed=sha(V1))
    serve(sim, V2)                                           # the file is not the reviewed version
    assert sim.call(pin, "witness", [], STRANGER) == "CHANGED"
    state = sim.read_json(pin, "get_state_json")
    assert state["status"] == "CHANGED" and state["baseline"] == sha(V1) and state["last_hash"] == sha(V2)
    assert state["changes"] == 1 and state["ever_changed"] is True
    assert sim.read(pin, "get_attestation") == "CHANGED"
    with pytest.raises(RpcError):
        sim.call(pin, "rebase", [sha(V2)], STRANGER)         # not the owner
    with pytest.raises(RpcError):
        sim.call(pin, "rebase", [sha(V1)], OWNER)            # not the hash last read
    assert sim.call(pin, "rebase", [sha(V2)], OWNER) == "REBASED"
    state = sim.read_json(pin, "get_state_json")
    assert state["status"] == "INTACT" and state["generation"] == 1 and state["baseline"] == sha(V2)
    assert rows(sim, pin)[-1]["previous_baseline"] == sha(V1)
    sim.set_time(T2)
    assert sim.call(pin, "witness", [], STRANGER) == "UNCHANGED"       # now compared with the accepted version


def test_unreadable_first_reading_leaves_the_pin_new(sim):
    pin = deploy(sim)
    serve(sim, "oops", status=503)
    assert sim.call(pin, "witness", [], STRANGER) == "UNREADABLE"
    state = sim.read_json(pin, "get_state_json")
    assert state["status"] == "NEW" and state["baseline"] == "" and state["unreadable"] == 1
    assert sim.read(pin, "get_attestation") == "NONE"


def test_reviewed_hash_matches(sim):
    pin = deploy(sim, reviewed=sha(V1))
    serve(sim, V1)
    assert sim.call(pin, "witness", [], STRANGER) == "UNCHANGED"
    state = sim.read_json(pin, "get_state_json")
    assert state["status"] == "INTACT" and state["ever_changed"] is False and state["baseline_bytes"] == len(V1)
