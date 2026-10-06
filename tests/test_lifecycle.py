import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
import requests
from cryptography.fernet import Fernet, InvalidToken

from recovery.client import ConnectionProblem, Connections
from recovery.provider import CLIENT, REDIRECT, provider


@pytest.fixture
def lab(tmp_path):
    with provider() as p:
        c = Connections(tmp_path / "vault.db", Fernet.generate_key(), p.url)
        yield c, p


def connect(c, tenant="acme"):
    url = c.start(tenant)
    response = requests.get(url, allow_redirects=False, timeout=2)
    assert response.status_code == 302, response.text
    callback = response.headers["Location"]
    c.callback(tenant, callback)
    return callback


def expire(c, tenant="acme"):
    with c.db() as db:
        row = db.execute("SELECT * FROM connections WHERE tenant=?", (tenant,)).fetchone()
        token = c.unseal(tenant, row["sealed"])
        token["expires_at"] = 0
        db.execute(
            "UPDATE connections SET sealed=? WHERE tenant=?", (c.seal(tenant, token), tenant)
        )
    return token


def test_authorize_resource_and_rotation(lab):
    c, p = lab
    connect(c)
    assert c.records("acme")["records"][0]["id"] == "sample-001"
    old = expire(c)
    assert c.records("acme")["records"]
    assert p.validator.refresh_count == 1
    assert old["refresh_token"] not in p.validator.refreshes
    assert c.report()["connections"][0]["status"] == "CONNECTED"


def test_encrypted_at_rest_and_sanitized_report(lab):
    c, _p = lab
    connect(c)
    token = c.access("acme")
    disk = Path(c.path).read_bytes()
    assert token.encode() not in disk
    assert token not in json.dumps(c.report())
    assert "refresh_token" not in json.dumps(c.report())


def test_wrong_key_and_swapped_tenant_rejected(lab):
    c, p = lab
    connect(c, "a")
    connect(c, "b")
    other = Connections(c.path, Fernet.generate_key(), p.url)
    with pytest.raises(InvalidToken):
        other.access("a")
    with c.db() as db:
        db.execute(
            "UPDATE connections SET sealed=(SELECT sealed FROM connections WHERE tenant='a') WHERE tenant='b'"
        )
    with pytest.raises(ConnectionProblem, match="vault_owner"):
        c.access("b")


def test_tenant_cannot_consume_another_callback(lab):
    c, _p = lab
    callback = requests.get(c.start("a"), allow_redirects=False).headers["Location"]
    c.start("b")
    with pytest.raises(ConnectionProblem, match="state_mismatch"):
        c.callback("b", callback)
    assert c.callback("a", callback) == "CONNECTED"


def test_callback_replay_rejected(lab):
    c, _p = lab
    callback = connect(c)
    with pytest.raises(ConnectionProblem):
        c.callback("acme", callback)


def test_expired_state(lab):
    c, _p = lab
    callback = requests.get(c.start("acme"), allow_redirects=False).headers["Location"]
    with c.db() as db:
        db.execute("UPDATE connections SET started=0")
    with pytest.raises(ConnectionProblem):
        c.callback("acme", callback)


@pytest.mark.parametrize("mutation", ["state", "redirect", "duplicate"])
def test_invalid_callback(lab, mutation):
    c, _p = lab
    callback = requests.get(c.start("acme"), allow_redirects=False).headers["Location"]
    if mutation == "state":
        callback = callback.replace("state=", "state=wrong")
    if mutation == "redirect":
        callback = callback.replace("127.0.0.1", "evil.example")
    if mutation == "duplicate":
        callback += "&code=second"
    with pytest.raises(ConnectionProblem):
        c.callback("acme", callback)


def test_provider_rejects_wrong_pkce(lab):
    c, p = lab
    callback = requests.get(c.start("acme"), allow_redirects=False).headers["Location"]
    code = parse_qs(urlsplit(callback).query)["code"][0]
    response = requests.post(
        p.url + "/token",
        data={
            "client_id": CLIENT,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT,
            "code": code,
            "code_verifier": "wrong",
        },
    )
    assert response.status_code == 400
    assert not p.validator.tokens


def test_provider_requires_pkce(lab):
    _c, p = lab
    url = (
        p.url
        + "/authorize?"
        + urlencode(
            {
                "client_id": CLIENT,
                "redirect_uri": REDIRECT,
                "response_type": "code",
                "scope": "records:read",
            }
        )
    )
    response = requests.get(url, allow_redirects=False)
    assert "error=" in response.headers.get("Location", "") or response.status_code == 400


def test_parallel_refresh_has_single_owner(lab):
    c, p = lab
    connect(c)
    expire(c)

    def run():
        try:
            return c.access("acme")
        except ConnectionProblem:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: run(), range(8)))
    assert any(results)
    assert len({x for x in results if x}) == 1
    assert p.validator.refresh_count == 1


@pytest.mark.parametrize("fault", ["lost_response", "malformed", "wrong_scope", "before_503"])
def test_ambiguous_refresh_never_replayed(lab, fault):
    c, p = lab
    connect(c)
    expire(c)
    p.fault = fault
    c.timeout = 0.05 if fault == "lost_response" else 2
    with pytest.raises(ConnectionProblem, match="UNKNOWN"):
        c.access("acme")
    count = p.validator.refresh_count
    with pytest.raises(ConnectionProblem, match="connection_not_ready"):
        c.access("acme")
    assert p.validator.refresh_count == count
    time.sleep(0.3) if fault == "lost_response" else None
    c.timeout = 2
    connect(c)
    assert c.records("acme")["records"]


def test_revoked_grant_requires_reconnection(lab):
    c, p = lab
    connect(c)
    expire(c)
    p.validator.refreshes.clear()
    with pytest.raises(ConnectionProblem, match="RECONNECT"):
        c.access("acme")
    connect(c)
    assert c.records("acme")["records"]


def test_process_restart_during_claim_is_not_retried(lab):
    c, p = lab
    connect(c)
    expire(c)
    with c.db() as db:
        db.execute("UPDATE connections SET status='REFRESHING',started=0")
    restarted = Connections(c.path, Fernet.generate_key(), p.url)
    assert restarted.recover_abandoned("acme")
    assert not restarted.recover_abandoned("acme")
    with pytest.raises(ConnectionProblem):
        restarted.access("acme")
    assert p.validator.refresh_count == 0


def test_active_claim_not_reaped(lab):
    c, _p = lab
    connect(c)
    with c.db() as db:
        db.execute("UPDATE connections SET status='REFRESHING'")
    assert not c.recover_abandoned("acme")
    with pytest.raises(ConnectionProblem):
        c.start("acme")


def test_fenced_completion_cannot_overwrite_reconnect(lab):
    c, _p = lab
    connect(c)
    old = expire(c)
    with c.db() as db:
        db.execute("UPDATE connections SET status='REFRESHING',started=0")
    c.recover_abandoned("acme")
    connect(c)
    with pytest.raises(ConnectionProblem, match="stale_operation"):
        c.exchange(
            "acme", 1, {"grant_type": "refresh_token", "refresh_token": old["refresh_token"]}
        )
    assert c.report()["connections"][0]["status"] == "CONNECTED"


@pytest.mark.parametrize(
    "value",
    [
        {},
        [],
        {"access_token": "x"},
        {
            "access_token": "x",
            "refresh_token": "y",
            "token_type": "Bearer",
            "scope": "records:read",
            "expires_in": True,
        },
    ],
)
def test_malformed_tokens(value):
    assert not Connections.valid_token(value)


@pytest.mark.parametrize(
    "url", ["https://example.com", "http://evil.example:8000", "http://127.0.0.1:8000/redirect"]
)
def test_no_arbitrary_provider(tmp_path, url):
    with pytest.raises(ValueError):
        Connections(tmp_path / "x.db", Fernet.generate_key(), url)


def test_non_object_provider_output_becomes_unknown(lab, monkeypatch):
    c, _p = lab
    connect(c)
    expire(c)

    class Response:
        status_code = 400

        def json(self):
            return []

    monkeypatch.setattr("recovery.client.requests.post", lambda *a, **k: Response())
    with pytest.raises(ConnectionProblem, match="UNKNOWN"):
        c.access("acme")


def test_token_type_must_be_string():
    assert not Connections.valid_token(
        {
            "access_token": "x",
            "refresh_token": "y",
            "token_type": 42,
            "expires_in": 60,
            "scope": "records:read",
        }
    )


def test_claim_survives_actual_child_process_death(lab):
    import subprocess
    import sys

    c, p = lab
    connect(c)
    expire(c)
    # Reconstruct the key only for this isolated child; never publish or log it.
    key = (
        __import__("base64")
        .urlsafe_b64encode(c.cipher._signing_key + c.cipher._encryption_key)
        .decode()
    )
    child = """import os,sys,json
from recovery.client import Connections
path,key,url=json.loads(sys.stdin.read())
c=Connections(path,key.encode(),url)
c.exchange=lambda *args,**kwargs: os._exit(77)
c.access('acme')
"""
    result = subprocess.run(
        [sys.executable, "-c", child],
        input=json.dumps([c.path, key, p.url]),
        text=True,
        check=False,
    )
    assert result.returncode == 77
    assert c.report()["connections"][0]["status"] == "REFRESHING"
    assert p.validator.refresh_count == 0
    with c.db() as db:
        db.execute("UPDATE connections SET started=0")
    assert c.recover_abandoned("acme")
    with pytest.raises(ConnectionProblem):
        c.access("acme")


def test_audit_failure_rolls_back_start(lab):
    c, _p = lab
    with c.db() as db:
        db.execute(
            "CREATE TRIGGER fail_audit BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'audit failed'); END"
        )
    with pytest.raises(Exception, match="audit failed"):
        c.start("acme")
    assert c.report()["connections"] == []
