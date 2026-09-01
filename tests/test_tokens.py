"""
Tests for the Tokens manager: encryption at rest, refresh-threshold dispatch,
access-token refresh success, the two reliability regressions, and cross-instance
locking. No network: requests.post is monkeypatched and sqlite is in-memory.
"""
import datetime
import os
import tempfile

import pytest
from cryptography.fernet import Fernet

import schwabdev.tokens as tokens_mod
from conftest import build_tokens

UTC = datetime.timezone.utc


class FakeResp:
    def __init__(self, ok=True, payload=None, raise_json=False, text=""):
        self.ok, self._payload, self._raise_json, self.text = ok, payload or {}, raise_json, text

    def json(self):
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


# ----------------------------- encryption --------------------------------- #
class TestEncryption:
    def test_roundtrip_with_key(self):
        t = build_tokens(encryption=Fernet.generate_key().decode())
        secret = "super-secret-refresh-token"
        blob = t._enc(secret)
        assert blob.startswith("enc:") and blob != secret
        assert t._dec(blob) == secret
        t._store.close()

    def test_unprefixed_value_passes_through(self):
        # Tokens stored before encryption was enabled lack the prefix and must still load.
        t = build_tokens(encryption=Fernet.generate_key().decode())
        assert t._dec("plain-legacy-token") == "plain-legacy-token"
        t._store.close()

    def test_no_cipher_stores_plaintext(self):
        t = build_tokens(encryption=None)
        assert t._enc("token") == "token"
        t._store.close()


# -------------------------- threshold dispatch ---------------------------- #
class TestUpdateDispatch:
    @pytest.mark.parametrize("at_age,rt_age,force_a,force_r,expected", [
        (10,    100,          False, False, None),       # everything fresh -> no update
        (1800,  100,          False, False, "access"),   # access expired -> refresh access
        (10,    7 * 24 * 3600, False, False, "refresh"), # refresh expired -> full re-auth
        (10,    100,          True,  False, "access"),   # forced access
        (10,    100,          False, True,  "refresh"),  # forced refresh
    ])
    def test_dispatch(self, monkeypatch, at_age, rt_age, force_a, force_r, expected):
        now = datetime.datetime(2024, 3, 5, 12, 0, 0, tzinfo=UTC)
        monkeypatch.setattr(tokens_mod, "_now", lambda: now)
        t = build_tokens()
        t._access_token_issued = now - datetime.timedelta(seconds=at_age)
        t._refresh_token_issued = now - datetime.timedelta(seconds=rt_age)
        called = {}

        def rec(which):
            def f(**k):
                called["which"] = which
                return True
            return f
        t._update_access_token = rec("access")
        t._update_refresh_token = rec("refresh")

        ret = t.update_tokens(force_access_token=force_a, force_refresh_token=force_r)
        assert called.get("which") == expected
        assert ret is (False if expected is None else True)
        t._store.close()


# ---------------------- access-token refresh paths ------------------------ #
class TestAccessTokenRefresh:
    def test_success_persists_and_releases_lock(self, monkeypatch):
        import requests
        t = build_tokens()
        t._access_token_issued = tokens_mod._now() - datetime.timedelta(seconds=1800)
        monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResp(ok=True, payload={
            "access_token": "NEW_AT", "refresh_token": "RT", "id_token": "ID2",
            "expires_in": 1800, "token_type": "Bearer", "scope": "api"}))
        assert t._update_access_token() is True
        assert t.access_token == "NEW_AT"
        assert t._store._cur.execute("SELECT access_token FROM schwabdev").fetchone() is not None
        assert t._store._conn.in_transaction is False  # EXCLUSIVE lock released
        t._store.close()

    def test_unexpected_exception_returns_false(self, monkeypatch):
        # Regression: an unexpected error must yield False (and release the lock),
        # never a misleading "success".
        import requests
        t = build_tokens()
        t._access_token_issued = tokens_mod._now() - datetime.timedelta(seconds=1800)
        monkeypatch.setattr(requests, "post", lambda *a, **k: FakeResp(ok=True, raise_json=True))
        assert t._update_access_token() is False
        assert t._store._conn.in_transaction is False
        t._store.close()

    def test_http_error_returns_false(self, monkeypatch):
        import requests
        t = build_tokens()
        t._access_token_issued = tokens_mod._now() - datetime.timedelta(seconds=1800)
        monkeypatch.setattr(requests, "post",
                            lambda *a, **k: FakeResp(ok=False, text="invalid_grant"))
        assert t._update_access_token() is False
        assert t._store._conn.in_transaction is False
        t._store.close()


# ----------------------- refresh-token (re-auth) -------------------------- #
class TestRefreshTokenAuth:
    def test_failed_auth_returns_false_and_releases_lock(self):
        # Regression: a failed/cancelled authorization must return False cleanly,
        # without crashing and without leaking the EXCLUSIVE write lock.
        t = build_tokens()
        t._refresh_token_issued = tokens_mod._now() - datetime.timedelta(seconds=1000)
        t._prompt_for_auth = lambda auth_url: None  # user provided nothing
        assert t._update_refresh_token() is False
        assert t._store._conn.in_transaction is False
        t._store.close()

    def test_set_tokens_rejects_non_dict(self):
        # Regression: _set_tokens must guard a non-dict argument instead of raising
        # AttributeError on a bool.
        t = build_tokens()
        assert t._set_tokens(tokens_mod._now(), tokens_mod._now(), False) is False
        t._store.close()


# -------------------- cross-instance lock coordination -------------------- #
def test_cross_instance_exclusive_lock():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        a = build_tokens(db_path=path)
        b = build_tokens(db_path=path)
        b._store._conn.execute("PRAGMA busy_timeout = 0;")  # surface the lock immediately
        a._store._cur.execute("BEGIN EXCLUSIVE")            # instance A holds the write lock
        try:
            # Instance B cannot acquire the lock and must back off (return False),
            # not crash or corrupt state.
            assert b._update_access_token() is False
        finally:
            a._store._conn.rollback()
            a._store.close()
            b._store.close()
    finally:
        os.remove(path)
