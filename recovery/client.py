"""Durable connection lifecycle. No background scheduler, external writes or login UI."""

import base64
import hashlib
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from urllib.parse import parse_qs, urlencode, urlsplit

import requests
from cryptography.fernet import Fernet

from .provider import CLIENT, REDIRECT


class ConnectionProblem(Exception):
    pass


class Connections:
    def __init__(self, path, key, provider_url, timeout=2):
        url = urlsplit(provider_url)
        if url.scheme != "http" or url.hostname != "127.0.0.1" or not url.port or url.path:
            raise ValueError("Lab provider must be a loopback HTTP origin")
        self.path, self.cipher, self.origin, self.timeout = (
            str(path),
            Fernet(key),
            provider_url,
            timeout,
        )
        with self.db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS connections(tenant TEXT PRIMARY KEY, status TEXT NOT NULL,
              sealed BLOB, started REAL NOT NULL, version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, tenant TEXT, status TEXT,
              reason TEXT, at REAL);
            """)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def seal(self, tenant, data):
        return self.cipher.encrypt(json.dumps({"tenant": tenant, "data": data}).encode())

    def unseal(self, tenant, blob):
        data = json.loads(self.cipher.decrypt(blob))
        if data["tenant"] != tenant:
            raise ConnectionProblem("vault_owner_mismatch")
        return data["data"]

    def event(self, db, tenant, status, reason):
        db.execute(
            "INSERT INTO events(tenant,status,reason,at) VALUES(?,?,?,?)",
            (tenant, status, reason, time.time()),
        )

    def start(self, tenant):
        if not isinstance(tenant, str) or not tenant or len(tenant) > 80:
            raise ValueError("Invalid tenant")
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM connections WHERE tenant=?", (tenant,)).fetchone()
            if old and old["status"] in {"REFRESHING", "EXCHANGING"}:
                raise ConnectionProblem("operation_in_progress")
            version = old["version"] + 1 if old else 1
            db.execute(
                "INSERT OR REPLACE INTO connections VALUES(?,?,?,?,?)",
                (
                    tenant,
                    "AUTHORIZING",
                    self.seal(tenant, {"state": state, "verifier": verifier}),
                    time.time(),
                    version,
                ),
            )
            self.event(db, tenant, "AUTHORIZING", "user_requested_connection")
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        return (
            self.origin
            + "/authorize?"
            + urlencode(
                {
                    "client_id": CLIENT,
                    "redirect_uri": REDIRECT,
                    "response_type": "code",
                    "scope": "records:read",
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                }
            )
        )

    def callback(self, tenant, callback_url):
        u = urlsplit(callback_url)
        if f"{u.scheme}://{u.netloc}{u.path}" != REDIRECT or u.fragment:
            raise ConnectionProblem("invalid_callback")
        query = parse_qs(u.query)
        if (
            any(len(v) != 1 for v in query.values())
            or not query.get("state")
            or not query.get("code")
        ):
            raise ConnectionProblem("invalid_callback")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM connections WHERE tenant=?", (tenant,)).fetchone()
            if not row or row["status"] != "AUTHORIZING" or time.time() - row["started"] > 600:
                raise ConnectionProblem("authorization_expired_or_used")
            data = self.unseal(tenant, row["sealed"])
            if not secrets.compare_digest(data["state"], query["state"][0]):
                raise ConnectionProblem("state_mismatch")
            db.execute(
                "UPDATE connections SET status='EXCHANGING',sealed=NULL,started=? WHERE tenant=?",
                (time.time(), tenant),
            )
            self.event(db, tenant, "EXCHANGING", "state_consumed")
        return self.exchange(
            tenant,
            row["version"],
            {
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "redirect_uri": REDIRECT,
                "code_verifier": data["verifier"],
            },
        )

    def exchange(self, tenant, version, payload):
        # A timeout or even 5xx can occur after rotation. Never automatically replay a grant.
        status, reason, sealed = "UNKNOWN", "provider_outcome_unconfirmed", None
        try:
            response = requests.post(
                self.origin + "/token",
                data={"client_id": CLIENT, **payload},
                timeout=self.timeout,
                allow_redirects=False,
            )
            result = response.json()
            if (
                response.status_code == 400
                and isinstance(result, dict)
                and result.get("error") == "invalid_grant"
            ):
                status, reason = "RECONNECT", "grant_rejected"
            elif response.status_code == 200 and self.valid_token(result):
                result["expires_at"] = time.time() + result["expires_in"]
                sealed = self.seal(tenant, result)
                status, reason = "CONNECTED", "token_saved"
        except (requests.RequestException, ValueError):
            pass  # no provider body, token, code or exception string enters audit
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE connections SET status=?,sealed=?,started=? WHERE tenant=? AND version=? AND status IN ('EXCHANGING','REFRESHING')",
                (status, sealed, time.time(), tenant, version),
            ).rowcount
            if not changed:
                raise ConnectionProblem("stale_operation")
            self.event(db, tenant, status, reason)
        if status != "CONNECTED":
            raise ConnectionProblem(status)
        return status

    @staticmethod
    def valid_token(t):
        return (
            isinstance(t, dict)
            and all(
                isinstance(t.get(k), str) and 0 < len(t[k]) < 8192
                for k in ("access_token", "refresh_token")
            )
            and isinstance(t.get("token_type"), str)
            and t["token_type"].lower() == "bearer"
            and type(t.get("expires_in")) is int
            and 0 < t["expires_in"] <= 86400
            and t.get("scope") == "records:read"
        )

    def access(self, tenant):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM connections WHERE tenant=?", (tenant,)).fetchone()
            if not row or row["status"] != "CONNECTED":
                raise ConnectionProblem("connection_not_ready")
            token = self.unseal(tenant, row["sealed"])
            if token["expires_at"] > time.time() + min(30, token["expires_in"] / 10):
                return token["access_token"]
            version = row["version"] + 1
            db.execute(
                "UPDATE connections SET status='REFRESHING',version=?,started=? WHERE tenant=?",
                (version, time.time(), tenant),
            )
            self.event(db, tenant, "REFRESHING", "access_expired")
        self.exchange(
            tenant,
            version,
            {"grant_type": "refresh_token", "refresh_token": token["refresh_token"]},
        )
        return self.access(tenant)

    def recover_abandoned(self, tenant):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            n = db.execute(
                "UPDATE connections SET status='UNKNOWN',sealed=NULL,version=version+1 WHERE tenant=? AND status IN ('REFRESHING','EXCHANGING') AND started<?",
                (tenant, time.time() - 60),
            ).rowcount
            if n:
                self.event(db, tenant, "UNKNOWN", "abandoned_operation_reconnect_required")
            return bool(n)

    def records(self, tenant):
        token = self.access(tenant)
        try:
            response = requests.get(
                self.origin + "/records",
                headers={"Authorization": "Bearer " + token},
                timeout=self.timeout,
                allow_redirects=False,
            )
            if response.status_code != 200:
                raise ConnectionProblem("resource_rejected")
            return response.json()
        except (requests.RequestException, ValueError):
            raise ConnectionProblem("resource_unavailable") from None

    def report(self):
        with self.db() as db:
            return {
                "connections": [
                    dict(r)
                    for r in db.execute(
                        "SELECT tenant,status,version FROM connections ORDER BY tenant"
                    )
                ],
                "events": [
                    dict(r)
                    for r in db.execute("SELECT seq,tenant,status,reason FROM events ORDER BY seq")
                ],
            }
