"""
Schwabdev Tokens Module.
Manages Schwab OAuth tokens including storage, retrieval, and refreshing.
https://github.com/tylerebowers/Schwab-API-Python
"""
import base64
import datetime
import json
import logging
import os
import threading
import urllib.parse

import requests
from cryptography.fernet import Fernet

from .token_store import RedisTokenStore, SqliteTokenStore, JSONTokenStore, TokenStore

_ENC_PREFIX = "enc:"
_UTC = datetime.timezone.utc
_MIN = datetime.datetime.min.replace(tzinfo=_UTC)


def _now():
    return datetime.datetime.now(_UTC)


class Tokens:
    def __init__(self, app_key: str = None, app_secret: str = None, callback_url: str = None,
                 logger: logging.Logger = None, tokens_db: str = "~/.schwabdev/tokens.db",
                 encryption: str = None, call_for_auth: callable = None, open_browser_for_auth: bool = True):
        """
        Initialize a tokens manager.

        app_key, app_secret, and callback_url fall back to the global values in
        ~/.schwabdev/env.json when not provided; any argument passed here overrides
        its global counterpart.

        Args:
            app_key (str | None): App key credential (overrides env.json's app_key).
            app_secret (str | None): App secret credential (overrides env.json's app_secret).
            callback_url (str | None): Url for callback (overrides env.json's callback_url).
            logger (logging.Logger | None): logger (defaults to the "Schwabdev" logger).
            tokens_db (str): Path to tokens store (database/redis/file).
                - Default to sqlite database store.
                - Assigned redis store if ``tokens_db`` starts with ``redis://`` or
                  ``rediss://`` (requires ``pip install 'schwabdev[redis]'``).
                - Assigned json store if ``tokens_db`` ends with ``.json``.
            encryption (str | None): Fernet key for encrypting tokens at rest.
            call_for_auth (function | None): Function to call for custom auth flow.
            open_browser_for_auth (bool): Open a browser during the auth flow.
        """
        try:
            with open(os.path.expanduser("~/.schwabdev/env.json")) as f:
                env = json.load(f)
        except OSError:
            env = {}

        app_key = app_key or env.get("app_key", None)
        app_secret = app_secret or env.get("app_secret", None)
        callback_url = callback_url or env.get("callback_url", None)
        logger = logger or logging.getLogger("Schwabdev")

        if not app_key:
            raise ValueError("[Schwabdev] app_key cannot be None.")
        if not app_secret:
            raise ValueError("[Schwabdev] app_secret cannot be None.")
        if not callback_url:
            raise ValueError("[Schwabdev] callback_url cannot be None.")
        if not tokens_db:
            raise ValueError("[Schwabdev] tokens_db cannot be None.")
        # Schwab key/secret lengths vary but are always even and combined >= 32 chars.
        if len(app_key) % 2 != 0 or len(app_secret) % 2 != 0 or len(app_key) + len(app_secret) < 32:
            raise ValueError("[Schwabdev] App key or app secret likely invalid.")
        if not callback_url.startswith("https"):
            raise ValueError("[Schwabdev] callback_url must be https.")
        if callback_url.endswith("/"):
            raise ValueError("[Schwabdev] callback_url cannot be a path (ends with \"/\").")
        if call_for_auth is not None and not callable(call_for_auth):
            raise ValueError("[Schwabdev] call_for_auth must be a callable function.")
        # File-path backends cannot be a bare directory; redis URLs are not paths.
        if not tokens_db.startswith(("redis://", "rediss://")) and tokens_db.endswith("/"):
            raise ValueError("[Schwabdev] Tokens file cannot be a path.")

        # public token state
        self.access_token = None
        self.refresh_token = None
        self.id_token = None

        # private state
        self._app_key = app_key
        self._app_secret = app_secret
        self._callback_url = callback_url
        self._logger = logger
        self._call_for_auth = call_for_auth
        self._open_browser_for_auth = open_browser_for_auth
        self._update_lock = threading.RLock()
        self._access_token_issued = _MIN
        self._refresh_token_issued = _MIN
        self._access_token_timeout = 30 * 60            # seconds (30 min from Schwab)
        self._refresh_token_timeout = 7 * 24 * 60 * 60  # seconds (7 days from Schwab)
        self._cipher_suite = Fernet(encryption) if (encryption and len(encryption) > 16) else None

        # init token store (auto-detect backend from tokens_db)
        self._store = self._build_store(tokens_db)

        with self._update_lock:
            loaded = self._load_tokens_from_store()

        if loaded:
            self.update_tokens()
            at_left = datetime.timedelta(seconds=self._access_token_timeout) - (_now() - self._access_token_issued)
            rt_left = datetime.timedelta(seconds=self._refresh_token_timeout) - (_now() - self._refresh_token_issued)
            self._logger.info(f"Access token expires in: {str(at_left)[:-7]}")
            self._logger.info(f"Refresh token expires in: {str(rt_left)[:-7]}")
        else:
            self._logger.warning("[Schwabdev] Could not load tokens from store, starting authorization flow.")
            self.update_tokens(force_refresh_token=True)

    def _build_store(self, tokens_db: str) -> TokenStore:
        """Select a token store backend from the tokens_db string."""
        if tokens_db.startswith(("redis://", "rediss://")):
            return RedisTokenStore(tokens_db, self._logger)
        if tokens_db.endswith(".json"):
            return JSONTokenStore(tokens_db, self._logger)
        return SqliteTokenStore(tokens_db, self._logger)

    def _close(self):
        try:
            self._store.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self._close()

    def __del__(self):
        self._close()

    # ---- encryption -------------------------------------------------------

    def _enc(self, s: str) -> str:
        if not self._cipher_suite:
            return s
        return _ENC_PREFIX + self._cipher_suite.encrypt(s.encode()).decode()

    def _dec(self, s: str) -> str:
        if not s:
            return ""
        if not s.startswith(_ENC_PREFIX):  # stored unencrypted
            return s
        if not self._cipher_suite:
            raise Exception("Cannot decrypt token, no encryption key provided.")
        return self._cipher_suite.decrypt(s[len(_ENC_PREFIX):].encode()).decode()

    # ---- persistence ------------------------------------------------------

    @staticmethod
    def _parse_dt(value: str) -> datetime.datetime:
        """Parse an ISO datetime, assuming UTC if it is naive."""
        dt = datetime.datetime.fromisoformat(value)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=_UTC)

    def _load_tokens_from_store(self) -> bool:
        """
        Load tokens from the token store into memory.

        Returns:
            bool: True if tokens were loaded, False if no row exists.
        """
        fields = self._store.load()
        if not fields:
            return False

        self._access_token_issued = self._parse_dt(fields["access_token_issued"])
        self._refresh_token_issued = self._parse_dt(fields["refresh_token_issued"])
        try:
            self.access_token = self._dec(fields["access_token"])
            self.refresh_token = self._dec(fields["refresh_token"])
            self.id_token = self._dec(fields["id_token"])
        except Exception as e:
            self._logger.error(f"[Schwabdev] Could not decrypt tokens from store ({e})")
            return False
        return True

    def _set_tokens(self, at_issued: datetime.datetime, rt_issued: datetime.datetime,
                    token_dictionary: dict) -> bool:
        """
        Persist tokens to the store and set in-memory variables.

        Args:
            at_issued (datetime.datetime): access token issued datetime.
            rt_issued (datetime.datetime): refresh token issued datetime.
            token_dictionary (dict): token dictionary from Schwab OAuth.

        Returns:
            bool: True if persisted successfully.
        """
        if not isinstance(token_dictionary, dict):
            return False

        if token_dictionary.get("access_token"):
            self.access_token = token_dictionary["access_token"]
        if token_dictionary.get("refresh_token"):
            self.refresh_token = token_dictionary["refresh_token"]
        if token_dictionary.get("id_token"):
            self.id_token = token_dictionary["id_token"]

        self._access_token_issued = at_issued
        self._refresh_token_issued = rt_issued
        self._access_token_timeout = token_dictionary.get("expires_in", 1800)

        fields = {
            "access_token_issued": at_issued.isoformat(),
            "refresh_token_issued": rt_issued.isoformat(),
            "access_token": self._enc(self.access_token),
            "refresh_token": self._enc(self.refresh_token),
            "id_token": self._enc(self.id_token),
            "expires_in": self._access_token_timeout,
            "token_type": token_dictionary.get("token_type", "Bearer"),
            "scope": token_dictionary.get("scope", "api"),
        }
        return self._store.save(fields)

    def _post_oauth_token(self, grant_type: str, code: str) -> requests.Response:
        """
        Make the OAuth token request for an authorization code or a refresh token.

        Args:
            grant_type (str): 'authorization_code' or 'refresh_token'.
            code (str): authorization code or refresh token.
        """
        headers = {
            "Authorization": "Basic " + base64.b64encode(f"{self._app_key}:{self._app_secret}".encode()).decode(),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if grant_type == "authorization_code":
            data = {"grant_type": "authorization_code", "code": code, "redirect_uri": self._callback_url}
        elif grant_type == "refresh_token":
            data = {"grant_type": "refresh_token", "refresh_token": code}
        else:
            raise Exception("Invalid grant type; options are 'authorization_code' or 'refresh_token'")
        return requests.post("https://api.schwabapi.com/v1/oauth/token", headers=headers, data=data, timeout=30)

    # ---- refresh orchestration -------------------------------------------

    def update_tokens(self, force_access_token: bool = False, force_refresh_token: bool = False) -> bool:
        """
        Update tokens if needed (only the access token is automatically refreshed).

        Args:
            force_access_token (bool): force update of the access token.
            force_refresh_token (bool): force update of the refresh token (also updates the access token).

        Returns:
            bool: True if tokens were updated, False otherwise.
        """
        now = _now()
        rt_delta = datetime.timedelta(seconds=self._refresh_token_timeout) - (now - self._refresh_token_issued)
        at_delta = datetime.timedelta(seconds=self._access_token_timeout) - (now - self._access_token_issued)
        refresh_threshold = datetime.timedelta(seconds=3630)  # 60.5 minutes
        access_threshold = datetime.timedelta(seconds=61)

        if rt_delta < refresh_threshold or force_refresh_token:
            expired = rt_delta < datetime.timedelta(0)
            self._logger.warning(f"The refresh token {'has expired!' if expired else 'is expiring soon (<60min)!'}")
            return self._update_refresh_token()
        if at_delta < access_threshold or force_access_token:
            self._logger.debug("The access token has expired, updating...")
            return self._update_access_token()
        return False

    def _update_access_token(self, overwrite: bool = False) -> bool:
        """Refresh the access token using the refresh token (coordinated across instances)."""
        with self._update_lock:
            last_known = self._access_token_issued
            if not self._store.acquire_lock():
                return False
            try:
                self._load_tokens_from_store()
                if self._access_token_issued > last_known and not overwrite:
                    self._logger.info(f"Access token updated elsewhere at {self._access_token_issued}.")
                    return True
                now = _now()
                try:
                    response = self._post_oauth_token("refresh_token", self.refresh_token)
                except requests.RequestException as e:
                    self._logger.error(f"[Schwabdev] Could not update access token (network error: {e})")
                    return False
                if not response.ok:
                    self._logger.error(f"Could not get new access token; refresh_token likely invalid. ({response.text})")
                    return False
                if self._set_tokens(now, self._refresh_token_issued, response.json()):
                    self._logger.info(f"Access token updated at {self._access_token_issued}")
                    return True
                return False
            except Exception as e:
                self._logger.error(f"[Schwabdev] Could not update access token ({e})")
                return False
            finally:
                self._store.release_lock()  # save() commits on success; otherwise release the lock

    def _update_refresh_token(self, overwrite: bool = False) -> bool:
        """Get new refresh and access tokens via the authorization-code flow (coordinated across instances)."""
        with self._update_lock:
            last_known = self._refresh_token_issued
            if not self._store.acquire_lock():
                now = _now()
                if last_known <= now and self._access_token_issued <= now:
                    self._logger.critical("Refresh token and Access token are invalid, couldn't get store lock.")
                elif last_known <= now:
                    self._logger.warning("Access token valid, Refresh token invalid")
                return False  # otherwise: still have time left, assume another instance is updating
            try:
                self._load_tokens_from_store()
                if self._refresh_token_issued > last_known and not overwrite:
                    self._logger.info(f"Refresh token updated elsewhere at {self._refresh_token_issued}.")
                    return True

                auth_url = (f"https://api.schwabapi.com/v1/oauth/authorize"
                            f"?client_id={self._app_key}&redirect_uri={self._callback_url}")
                now = _now()
                auth_callback = self._prompt_for_auth(auth_url)
                if not auth_callback:
                    return False
                tokens = self._exchange_auth_code(auth_callback)
                if tokens and self._set_tokens(now, now, tokens):
                    self._logger.info(f"Tokens updated at {now}")
                    return True
                return False
            except Exception as e:
                self._logger.error(f"[Schwabdev] Could not update refresh token ({e})")
                return False
            finally:
                self._store.release_lock()

    def _prompt_for_auth(self, auth_url: str):
        """Obtain the authorization callback URL/code, via call_for_auth or the browser+stdin flow."""
        if callable(self._call_for_auth):
            return self._call_for_auth(auth_url)

        print(f"[Schwabdev] Open to authenticate: {auth_url}")
        if self._open_browser_for_auth:
            try:
                import webbrowser
                webbrowser.open(auth_url)
            except Exception as e:
                self._logger.error(e)
                self._logger.warning("Could not open browser for authorization (open the link manually)")

        auth_callback = input("[Schwabdev] After authorizing, paste the address bar url here: ")
        if len(auth_callback) < len(self._callback_url):
            self._logger.error("No authorization URL provided, cannot continue.")
            return None
        return auth_callback

    def _exchange_auth_code(self, url_or_code: str):
        """Exchange the authorization callback URL/code for tokens. Returns the token dict or None."""
        parsed = urllib.parse.urlparse(url_or_code)
        if parsed.scheme:
            code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]
        else:
            code = urllib.parse.unquote(url_or_code)
        if not code:
            self._logger.error(f"Could not parse authorization code from URL. ({url_or_code})")
            return None

        response = self._post_oauth_token("authorization_code", code)
        if not response.ok:
            self._logger.error(response.text)
            self._logger.error(
                "Could not get new refresh and access tokens, check these:\n"
                "1. App status is \"Ready For Use\".\n"
                "2. App key and app secret are valid.\n"
                "3. You pasted the whole url within 30 seconds. (it has a quick expiration)\n"
                "4. https://tylerebowers.github.io/Schwabdev/?source=pages%2Ftroubleshooting.html"
            )
            return None
        return response.json()
