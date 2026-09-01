"""
Shared test fixtures for the schwabdev suite.

These tests never touch the network or the real OAuth flow. Clients, the stream
base, and the token manager are constructed directly (bypassing __init__).
"""
import logging
import threading

import pytest

import schwabdev.client as client_mod
import schwabdev.stream as stream_mod
import schwabdev.tokens as tokens_mod
import schwabdev.validation as validation_mod

BASE = "https://api.schwabapi.com"
ACCOUNT_HASH = "ABC123DEF456GHI789JKL012" # >= 14 chars so _vhash guard accepts it. Used wherever a test needs an accountHash argument.
LOG = logging.getLogger("schwabdev-tests")
LOG.addHandler(logging.NullHandler())

STREAMER_INFO = {
    "streamerSocketUrl": "wss://fake",
    "schwabClientCustomerId": "CUST",
    "schwabClientCorrelId": "CORR",
    "schwabClientChannel": "CH",
    "schwabClientFunctionId": "FN",
}


# --------------------------------------------------------------------------- #
# Recording HTTP fakes                                                          #
# --------------------------------------------------------------------------- #
def _norm_path(url):
    return url[len(BASE):] if url.startswith(BASE) else url


def _record(calls, method, url, kwargs):
    params = kwargs.get("params")
    headers = kwargs.get("headers")
    calls.append({
        "method": method.upper(),
        "path": _norm_path(url),
        "params": dict(sorted(params.items())) if params else None,
        "json": kwargs.get("json"),
        "headers": dict(sorted(headers.items())) if headers else None,
    })


class RecordingResponse:
    status = status_code = 200
    ok = True
    headers = {"Content-Type": "application/json"}
    text = ""
    def json(self):
        return {}


class AsyncRecordingResponse(RecordingResponse):
    async def json(self):
        return {}
    async def text(self):
        return ""


class FakeSyncSession:
    def __init__(self, calls):
        self.calls = calls
        self.headers = {}

    def request(self, method, url, **kwargs):
        _record(self.calls, method, url, kwargs)
        return RecordingResponse()

    def close(self):
        pass


class FakeAsyncSession:
    def __init__(self, calls):
        self.calls = calls
        self.headers = {}

    async def request(self, method, path, **kwargs):
        _record(self.calls, method, path, kwargs)
        return AsyncRecordingResponse()

    def _verb(self, method):
        async def call(path, **kwargs):
            _record(self.calls, method, path, kwargs)
            return AsyncRecordingResponse()
        return call

    def __getattr__(self, name):
        if name in ("get", "post", "put", "delete"):
            return self._verb(name)
        raise AttributeError(name)

    async def close(self):
        pass


# --------------------------------------------------------------------------- #
# Builders                                                                      #
# --------------------------------------------------------------------------- #
def build_recording_client(is_async=False):
    """A Client/ClientAsync wired to a recording session; returns (client, calls)."""
    calls = []
    cls = client_mod.ClientAsync if is_async else client_mod.Client
    c = cls.__new__(cls)
    c._base_api_url = BASE
    c.timeout = 10
    c.logger = LOG
    c._session_lock = threading.RLock()
    c._session = FakeAsyncSession(calls) if is_async else FakeSyncSession(calls)
    c._validator = validation_mod._Validator(enabled=True)  # __init__ is bypassed, so set it here
    c.update_tokens = lambda *a, **k: False  # never touch real tokens
    if is_async:
        c._parsed = False
    return c, calls


def build_stream_base():
    """A StreamBase with a stubbed streamer-info payload (no socket)."""
    b = stream_mod.StreamBase(None, lambda: STREAMER_INFO, LOG)
    b._streamer_info = STREAMER_INFO
    return b


def build_tokens(db_path=":memory:", encryption=None):
    """A Tokens instance backed by a real sqlite store but no OAuth/network."""
    from cryptography.fernet import Fernet
    from schwabdev.token_store import SqliteTokenStore
    t = tokens_mod.Tokens.__new__(tokens_mod.Tokens)
    t.access_token, t.refresh_token, t.id_token = "AT", "RT", "ID"
    t._app_key, t._app_secret = "appkey", "appsecret"
    t._callback_url = "https://127.0.0.1"
    t._logger = LOG
    t._call_for_auth = None
    t._open_browser_for_auth = False
    t._update_lock = threading.RLock()
    t._access_token_issued = tokens_mod._MIN
    t._refresh_token_issued = tokens_mod._MIN
    t._access_token_timeout = 1800
    t._refresh_token_timeout = 7 * 24 * 60 * 60
    t._cipher_suite = Fernet(encryption) if encryption else None
    t._store = SqliteTokenStore(db_path, LOG)
    return t


# --------------------------------------------------------------------------- #
# Fixtures                                                                       #
# --------------------------------------------------------------------------- #
@pytest.fixture
def sync_client():
    return build_recording_client(is_async=False)


@pytest.fixture
def async_client():
    return build_recording_client(is_async=True)


@pytest.fixture
def stream_base():
    return build_stream_base()


@pytest.fixture
def tokens():
    t = build_tokens()
    yield t
    t._store.close()
