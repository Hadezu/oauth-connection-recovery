"""Disposable OAuthLib provider, NOT an identity product or real vendor sandbox.
Only loopback HTTP. Synthetic consent is automatically granted by /authorize.
OAuthLib owns protocol validation; our adapter supplies local fixtures and faults.
"""

import json
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

from flask import Flask, Response, request
from oauthlib.oauth2 import RequestValidator, Server
from werkzeug.serving import WSGIRequestHandler, make_server

REDIRECT = "http://127.0.0.1:8766/callback"
CLIENT = "recovery-lab"


class Validator(RequestValidator):
    def __init__(self):
        self.codes = {}
        self.tokens = {}
        self.refreshes = {}
        self.refresh_count = 0

    def validate_client_id(self, client_id, request, *args, **kwargs):
        return client_id == CLIENT

    def client_authentication_required(self, request, *args, **kwargs):
        return False  # public client; PKCE required

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        request.client = SimpleNamespace(client_id=CLIENT)
        return client_id == CLIENT

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return redirect_uri == REDIRECT

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return REDIRECT

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return response_type == "code"

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return grant_type in {"authorization_code", "refresh_token"}

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return ["records:read"]

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return set(scopes) == {"records:read"}

    def is_pkce_required(self, client_id, request):
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        self.codes[code["code"]] = {
            "challenge": request.code_challenge,
            "method": request.code_challenge_method,
            "expires": time.time() + 60,
        }

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        row = self.codes.get(code)
        request.user = "synthetic-user"
        request.scopes = ["records:read"]
        return bool(row and row["expires"] > time.time())

    def get_code_challenge(self, code, request):
        return self.codes[code]["challenge"]

    def get_code_challenge_method(self, code, request):
        return self.codes[code]["method"]

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        return redirect_uri == REDIRECT

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        self.codes.pop(code, None)

    def save_bearer_token(self, token, request, *args, **kwargs):
        if request.grant_type == "refresh_token":
            self.refresh_count += 1
            old = self.refreshes.pop(request.refresh_token, None)
            if old:
                self.tokens.pop(old, None)
        self.tokens[token["access_token"]] = time.time() + token["expires_in"]
        self.refreshes[token["refresh_token"]] = token["access_token"]

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        request.user = "synthetic-user"
        return refresh_token in self.refreshes

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        return ["records:read"]

    def rotate_refresh_token(self, request):
        return True

    def validate_bearer_token(self, token, scopes, request):
        request.user = "synthetic-user"
        return self.tokens.get(token, 0) > time.time() and set(scopes) <= {"records:read"}


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass  # authorization URLs contain codes/state; no access log


@contextmanager
def provider():
    app = Flask(__name__)
    validator = Validator()
    oauth = Server(validator, token_expires_in=3600)
    control = SimpleNamespace(fault=None, validator=validator)

    @app.get("/authorize")
    def authorize():
        headers, body, status = oauth.create_authorization_response(
            request.url,
            http_method="GET",
            scopes=["records:read"],
            credentials={"user": "synthetic-user"},
        )
        return Response(body, status=status, headers=headers)

    @app.post("/token")
    def token():
        fault, control.fault = control.fault, None
        if fault == "before_503":
            return Response("{}", status=503)
        headers, body, status = oauth.create_token_response(
            request.url,
            http_method="POST",
            body=request.get_data(as_text=True),
            headers=dict(request.headers),
        )
        if fault == "lost_response":
            time.sleep(0.25)  # rotation committed; client's shorter timeout loses acknowledgement
        if fault == "malformed":
            body = "not json"
        if fault == "wrong_scope":
            data = json.loads(body)
            data["scope"] = "admin"
            body = json.dumps(data)
        return Response(body, status=status, headers=headers)

    @app.get("/records")
    def records():
        valid, _ = oauth.verify_request(
            request.url, http_method="GET", headers=dict(request.headers), scopes=["records:read"]
        )
        return (
            ({"records": [{"id": "sample-001", "status": "open"}]}, 200)
            if valid
            else ({"error": "invalid_token"}, 401)
        )

    server = make_server("127.0.0.1", 0, app, request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    control.url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield control
    finally:
        server.shutdown()
        thread.join(timeout=3)
        server.server_close()
