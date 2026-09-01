"""
Tests for the pluggable token store backends.

sqlite and JSON stores are exercised against real files; the redis store is
exercised against a hand-rolled in-memory fake so no `redis` package is needed.
"""
import json
import logging
import os
import tempfile

import pytest

from schwabdev.token_store import (
    FIELDS,
    JSONTokenStore,
    RedisTokenStore,
    SqliteTokenStore,
)

LOG = logging.getLogger("schwabdev-store-tests")
LOG.addHandler(logging.NullHandler())


def _sample_fields():
    return {
        "access_token_issued": "2024-01-01T00:00:00+00:00",
        "refresh_token_issued": "2024-01-01T00:00:00+00:00",
        "access_token": "AT",
        "refresh_token": "RT",
        "id_token": "ID",
        "expires_in": 1800,
        "token_type": "Bearer",
        "scope": "api",
    }


# --------------------------------------------------------------------------- #
# sqlite
# --------------------------------------------------------------------------- #
class TestSqliteStore:
    def test_load_empty_returns_none(self):
        s = SqliteTokenStore(":memory:", LOG)
        assert s.load() is None
        s.close()

    def test_save_then_load_roundtrip(self):
        s = SqliteTokenStore(":memory:", LOG)
        assert s.save(_sample_fields()) is True
        loaded = s.load()
        assert loaded is not None
        for k in FIELDS:
            assert loaded[k] == _sample_fields()[k]
        s.close()

    def test_save_replaces_existing_row(self):
        s = SqliteTokenStore(":memory:", LOG)
        s.save(_sample_fields())
        fields = _sample_fields()
        fields["access_token"] = "AT2"
        s.save(fields)
        assert s.load()["access_token"] == "AT2"
        s.close()

    def test_lock_acquire_and_release(self):
        s = SqliteTokenStore(":memory:", LOG)
        assert s.acquire_lock() is True
        s.release_lock()  # save() commits; here nothing was saved so rollback releases
        assert s._conn.in_transaction is False
        # can re-acquire after release
        assert s.acquire_lock() is True
        s.release_lock()
        s.close()


# --------------------------------------------------------------------------- #
# JSON file
# --------------------------------------------------------------------------- #
class TestJSONStore:
    def test_load_missing_file_returns_none(self):
        with tempfile.TemporaryDirectory() as d:
            s = JSONTokenStore(os.path.join(d, "tokens.json"), LOG)
            assert s.load() is None
            s.close()

    def test_save_then_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "tokens.json")
            s = JSONTokenStore(path, LOG)
            assert s.save(_sample_fields()) is True
            loaded = s.load()
            assert loaded is not None
            for k in FIELDS:
                assert loaded[k] == _sample_fields()[k]
            s.close()

    def test_atomic_write_leaves_no_tmp(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "tokens.json")
            s = JSONTokenStore(path, LOG)
            s.save(_sample_fields())
            assert os.path.exists(path)
            assert not os.path.exists(path + ".tmp")
            # the file is valid JSON
            with open(path) as f:
                assert isinstance(json.load(f), dict)
            s.close()

    def test_lock_acquire_and_release(self):
        with tempfile.TemporaryDirectory() as d:
            s = JSONTokenStore(os.path.join(d, "tokens.json"), LOG)
            assert s.acquire_lock() is True
            s.release_lock()
            # can re-acquire after release
            assert s.acquire_lock() is True
            s.release_lock()
            s.close()


# --------------------------------------------------------------------------- #
# redis (in-memory fake client)
# --------------------------------------------------------------------------- #
class FakeRedis:
    """Minimal in-memory subset of redis.Redis used by RedisTokenStore."""

    def __init__(self):
        self._data = {}
        self._lock = None

    def hgetall(self, key):
        return dict(self._data.get(key, {}))

    def delete(self, key):
        self._data.pop(key, None)

    def hset(self, key, mapping=None):
        self._data.setdefault(key, {}).update(mapping or {})

    def set(self, key, value, nx=False, ex=None):
        if nx and self._data.get(key) is not None:
            return None
        self._data[key] = value
        return True

    def get(self, key):
        return self._data.get(key)

    def pipeline(self):
        outer = self

        class _Pipe:
            def __init__(self):
                self._ops = []

            def delete(self, key):
                self._ops.append(("delete", key))
                return self

            def hset(self, key, mapping=None):
                self._ops.append(("hset", key, mapping))
                return self

            def execute(self):
                for op in self._ops:
                    if op[0] == "delete":
                        outer.delete(op[1])
                    elif op[0] == "hset":
                        outer.hset(op[1], mapping=op[2])
                return []

        return _Pipe()

    def register_script(self, script):
        outer = self

        class _Script:
            def __call__(self, keys=None, args=None):
                key = keys[0]
                if outer.get(key) == args[0]:
                    outer.delete(key)
                    return 1
                return 0

        return _Script()

    def close(self):
        pass


class FakeScriptError:
    """A fake that raises during register_script to exercise the error path."""
    pass


class TestRedisStore:
    def _store(self):
        # Build the store without importing redis by bypassing __init__.
        s = RedisTokenStore.__new__(RedisTokenStore)
        s._redis = FakeRedis()
        s._logger = LOG
        s._lock_ttl = 30
        s._lock_token = None
        s._release_script = s._redis.register_script(RedisTokenStore._RELEASE_SCRIPT)
        return s

    def test_load_empty_returns_none(self):
        s = self._store()
        assert s.load() is None
        s.close()

    def test_save_then_load_roundtrip(self):
        s = self._store()
        assert s.save(_sample_fields()) is True
        loaded = s.load()
        assert loaded is not None
        for k in FIELDS:
            assert loaded[k] == str(_sample_fields()[k])
        s.close()

    def test_acquire_lock_then_second_acquire_fails(self):
        a = self._store()
        b = self._store()
        b._redis = a._redis  # share the same fake server
        b._release_script = a._release_script
        assert a.acquire_lock() is True
        assert b.acquire_lock() is False  # already held
        a.release_lock()
        # now b can acquire
        assert b.acquire_lock() is True
        b.release_lock()
        a.close()
        b.close()

    def test_release_lock_only_deletes_owned(self):
        a = self._store()
        b = self._store()
        b._redis = a._redis
        b._release_script = a._release_script
        a.acquire_lock()
        # b does not own the lock; releasing it is a no-op and must not free a's lock
        b.release_lock()
        assert a._redis.get(RedisTokenStore._LOCK_KEY) is not None
        a.release_lock()
        assert a._redis.get(RedisTokenStore._LOCK_KEY) is None
        a.close()
        b.close()
