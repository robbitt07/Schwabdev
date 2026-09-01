"""
Schwabdev Token Storage Backends.
Abstract token store plus sqlite (default), JSON file, and redis backends.
https://github.com/tylerebowers/Schwab-API-Python
"""
import abc
import json
import logging
import os
import sqlite3
import uuid

# Field keys persisted by every backend. All values are stored as strings
# (Tokens owns datetime parsing and Fernet encryption), except ``expires_in``
# which is stored as an int.
FIELDS = (
    "access_token_issued",
    "refresh_token_issued",
    "access_token",
    "refresh_token",
    "id_token",
    "expires_in",
    "token_type",
    "scope",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schwabdev (
    access_token_issued TEXT NOT NULL,
    refresh_token_issued TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    id_token TEXT NOT NULL,
    expires_in INTEGER,
    token_type TEXT,
    scope TEXT
);
"""


class TokenStore(abc.ABC):
    """Abstract base for pluggable token storage backends."""

    @abc.abstractmethod
    def load(self) -> dict | None:
        """Return the stored token fields as a dict, or None if no row exists."""

    @abc.abstractmethod
    def save(self, fields: dict) -> bool:
        """Persist the token fields (replacing any existing row)."""

    @abc.abstractmethod
    def acquire_lock(self) -> bool:
        """Acquire a cross-instance exclusive lock for a refresh; True if acquired."""

    @abc.abstractmethod
    def release_lock(self) -> None:
        """Release the exclusive lock (no-op if not held)."""

    @abc.abstractmethod
    def close(self) -> None:
        """Release resources held by the store."""

    # Allow use as a context manager so callers can ``with store:`` if desired.
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()


class SqliteTokenStore(TokenStore):
    """Default token store backed by a local sqlite database file."""

    def __init__(self, path: str, logger: logging.Logger):
        path = os.path.expanduser(path)
        db_dir = os.path.dirname(path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._cur = self._conn.cursor()
        self._cur.executescript(_SCHEMA)
        self._cur.execute("PRAGMA busy_timeout = 30000;")
        self._conn.commit()
        self._logger = logger

    def load(self) -> dict | None:
        row = self._cur.execute(
            "SELECT access_token_issued, refresh_token_issued, access_token, "
            "refresh_token, id_token, expires_in, token_type, scope "
            "FROM schwabdev LIMIT 1"
        ).fetchone()
        if not row:
            return None
        return dict(zip(FIELDS, row))

    def save(self, fields: dict) -> bool:
        try:
            self._cur.execute("DELETE FROM schwabdev")
            self._cur.execute(
                "INSERT INTO schwabdev (access_token_issued, refresh_token_issued, "
                "access_token, refresh_token, id_token, expires_in, token_type, scope) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(fields[k] for k in FIELDS),
            )
            self._conn.commit()
            return True
        except Exception as e:
            self._logger.error(e)
            self._logger.error("[Schwabdev] Could not write tokens to sqlite database")
            return False

    def acquire_lock(self) -> bool:
        try:
            self._cur.execute("BEGIN EXCLUSIVE")
            return True
        except sqlite3.Error as e:
            self._logger.error(f"[Schwabdev] Could not begin exclusive transaction ({e})")
            return False

    def release_lock(self) -> None:
        # save() commits on success; otherwise roll back to release the EXCLUSIVE txn.
        if self._conn.in_transaction:
            self._conn.rollback()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


class RedisTokenStore(TokenStore):
    """Token store backed by a redis server (requires the optional ``redis`` extra)."""

    _KEY = "schwabdev:tokens"
    _LOCK_KEY = "schwabdev:tokens:lock"

    # Compare-and-delete so we only release a lock we own (avoids deleting a
    # lock that was expired and re-acquired by another instance).
    _RELEASE_SCRIPT = """
    if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
    else
        return 0
    end
    """

    def __init__(self, url: str, logger: logging.Logger, lock_ttl: int = 30):
        try:
            import redis
        except ImportError as e:
            raise ImportError(
                "Redis token store requires the 'redis' package: "
                "pip install 'schwabdev[redis]'"
            ) from e
        self._redis = redis.Redis.from_url(url, decode_responses=True)
        self._logger = logger
        self._lock_ttl = lock_ttl
        self._lock_token = None
        self._release_script = self._redis.register_script(self._RELEASE_SCRIPT)

    def load(self) -> dict | None:
        raw = self._redis.hgetall(self._KEY)
        if not raw:
            return None
        # hgetall with decode_responses=True returns str keys/values already.
        return {k: raw.get(k) for k in FIELDS}

    def save(self, fields: dict) -> bool:
        try:
            mapping = {k: str(fields[k]) for k in FIELDS}
            pipe = self._redis.pipeline()
            pipe.delete(self._KEY)
            pipe.hset(self._KEY, mapping=mapping)
            pipe.execute()
            return True
        except Exception as e:
            self._logger.error(e)
            self._logger.error("[Schwabdev] Could not write tokens to redis")
            return False

    def acquire_lock(self) -> bool:
        token = str(uuid.uuid4())
        if self._redis.set(self._LOCK_KEY, token, nx=True, ex=self._lock_ttl):
            self._lock_token = token
            return True
        return False

    def release_lock(self) -> None:
        if self._lock_token is None:
            return
        try:
            self._release_script(keys=[self._LOCK_KEY], args=[self._lock_token])
        except Exception as e:
            self._logger.debug(f"[Schwabdev] Could not release redis lock ({e})")
        finally:
            self._lock_token = None

    def close(self) -> None:
        try:
            self._redis.close()
        except Exception:
            pass


class JSONTokenStore(TokenStore):
    """Token store backed by a single JSON file (atomic writes, best-effort locking)."""

    def __init__(self, path: str, logger: logging.Logger):
        self._path = os.path.expanduser(path)
        db_dir = os.path.dirname(self._path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        self._logger = logger
        self._lock_fh = None
        self._lock_path = self._path + ".lock"
        self._marker_held = False

    def load(self) -> dict | None:
        try:
            with open(self._path, "r") as f:
                content = f.read()
        except FileNotFoundError:
            return None
        except OSError as e:
            self._logger.error(f"[Schwabdev] Could not read tokens file ({e})")
            return None
        if not content.strip():
            return None
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError) as e:
            self._logger.error(f"[Schwabdev] Could not parse tokens file ({e})")
            return None
        if not isinstance(data, dict):
            return None
        return {k: data.get(k) for k in FIELDS}

    def save(self, fields: dict) -> bool:
        data = {k: fields[k] for k in FIELDS}
        tmp_path = self._path + ".tmp"
        try:
            with open(tmp_path, "w") as f:
                json.dump(data, f)
            os.replace(tmp_path, self._path)
            return True
        except Exception as e:
            self._logger.error(e)
            self._logger.error("[Schwabdev] Could not write tokens to JSON file")
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass
            return False

    def acquire_lock(self) -> bool:
        # Prefer an OS-level file lock via fcntl (Unix). Fall back to an
        # O_EXCL marker file on platforms without fcntl.
        try:
            import fcntl
        except ImportError:
            return self._acquire_marker_lock()

        try:
            if self._lock_fh is None:
                self._lock_fh = open(self._lock_path, "w")
            fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError as e:
            self._logger.error(f"[Schwabdev] Could not acquire JSON file lock ({e})")
            return False

    def _acquire_marker_lock(self) -> bool:
        try:
            fd = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            self._marker_held = True
            return True
        except OSError as e:
            self._logger.error(f"[Schwabdev] Could not acquire JSON marker lock ({e})")
            return False

    def release_lock(self) -> None:
        if self._lock_fh is not None:
            try:
                import fcntl
                fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self._lock_fh.close()
            except Exception:
                pass
            self._lock_fh = None
        if self._marker_held:
            try:
                os.remove(self._lock_path)
            except OSError:
                pass
            self._marker_held = False

    def close(self) -> None:
        self.release_lock()
