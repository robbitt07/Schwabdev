"""
Schwabdev Client & ClientAsync Module.
For connecting to the Schwab API.
https://github.com/tylerebowers/Schwab-API-Python
"""
import asyncio
import datetime
import logging
import threading
import urllib.parse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import aiohttp
except ImportError:  # async client is optional
    aiohttp = None

from .utils import TimeFormat
from .tokens import Tokens
from .validation import _Validator


class ClientBase:

    _base_api_url = "https://api.schwabapi.com"

    def __init__(self, app_key=None, app_secret=None, callback_url="https://127.0.0.1", tokens_db="~/.schwabdev/tokens.db",
                 encryption=None, timeout=10, call_on_auth=None, open_browser_for_auth=True, validate_params=True):
        """
        Initialize a client to access the Schwab API.

        Args:
            app_key (str): App key credential.
            app_secret (str): App secret credential.
            callback_url (str): URL for callback.
            tokens_db (str): Path to tokens store (database/redis/file).
                - Default to sqlite database store.
                - Assigned redis store if ``tokens_db`` starts with ``redis://`` or
                  ``rediss://`` (requires ``pip install 'schwabdev[redis]'``).
                - Assigned json store if ``tokens_db`` ends with ``.json``.
            timeout (int): Request timeout in seconds - how long to wait for a response.
            call_on_auth (function | None): Function to call for authentication (see docs).
            open_browser_for_auth (bool): Whether to open the browser for authentication.
            validate_params (bool): Validate endpoint parameter types and values before sending.
        """
        if timeout <= 0:
            raise ValueError("Timeout must be greater than 0 (5 seconds or more is recommended).")

        self.timeout = timeout
        self.logger = logging.getLogger("Schwabdev")
        self.tokens = Tokens(app_key, app_secret, callback_url, self.logger, tokens_db,
                             encryption, call_on_auth, open_browser_for_auth)
        self.tokens.update_tokens()  # ensure tokens are up to date on init
        self._validator = _Validator(enabled=validate_params)

    @staticmethod
    def _parse_params(params: dict) -> dict:
        """Remove keys whose value is None (in place) and return the dict."""
        return {k: v for k, v in params.items() if v is not None}

    @staticmethod
    def _format_list(value):
        """Join a list into a comma-separated string; pass through str/None unchanged."""
        if isinstance(value, (list, tuple, set)):
            return ",".join(map(str, value))
        return value

    def _time_convert(self, dt=None, format: "str | TimeFormat" = TimeFormat.ISO_8601):
        """
        Convert a datetime/date to the requested format; pass through str/None unchanged.

        Args:
            dt (datetime.datetime | datetime.date | str | None): value to convert.
            format (str | TimeFormat): target format.

        Returns:
            str | int | None: converted value (or the input passed through).
        """
        if not isinstance(dt, (datetime.datetime, datetime.date)):
            return dt  # str, None, or anything unexpected -> passthrough
        if not isinstance(dt, datetime.datetime):  # bare date -> midnight UTC (so epoch/iso work)
            dt = datetime.datetime(dt.year, dt.month, dt.day, tzinfo=datetime.timezone.utc)
        match format:
            case TimeFormat.ISO_8601 | TimeFormat.ISO_8601.value:
                # Schwab expects 'YYYY-MM-DDTHH:MM:SS.mmmZ' (millisecond precision)
                # A trailing Z denotes UTC, so normalize aware datetimes before
                # formatting. Naive datetimes retain the existing assumed-UTC
                # behavior for backward compatibility.
                if dt.tzinfo is not None and dt.utcoffset() is not None:
                    dt = dt.astimezone(datetime.timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
            case TimeFormat.EPOCH | TimeFormat.EPOCH.value:
                return int(dt.timestamp())
            case TimeFormat.EPOCH_MS | TimeFormat.EPOCH_MS.value:
                return int(dt.timestamp() * 1000)
            case TimeFormat.YYYY_MM_DD | TimeFormat.YYYY_MM_DD.value:
                return dt.strftime("%Y-%m-%d")
            case _:
                raise ValueError(f"Unsupported time format: {format}")

    def _get_streamer_info(self):
        """Fetch streamer connection info from userPreference; returns dict or None on failure."""
        self.tokens.update_tokens()
        try:
            response = requests.get(
                f"{self._base_api_url}/trader/v1/userPreference",
                headers={"Authorization": f"Bearer {self.tokens.access_token}"},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            self.logger.error(f"Could not get streamerInfo (network error: {e})")
            return None
        if not response.ok:
            self.logger.error(f"Could not get streamerInfo (HTTP {response.status_code})")
            return None
        info = response.json().get("streamerInfo") or []
        if not info:
            self.logger.error("streamerInfo missing from userPreference response.")
            return None
        return info[0]


class Client(ClientBase):

    def __init__(self, app_key: str = None, app_secret: str = None, callback_url: str = "https://127.0.0.1",
                 tokens_db: str = "~/.schwabdev/tokens.db", encryption: str = None, timeout: int = 10,
                 call_on_auth: callable = None, open_browser_for_auth: bool = True, validate_params: bool = True):
        """
        Initialize a synchronous client to access the Schwab API.

        Args:
            app_key (str): App key credential.
            app_secret (str): App secret credential.
            callback_url (str): URL for callback.
            tokens_db (str): Path to tokens store (database/redis/file).
                - Default to sqlite database store.
                - Assigned redis store if ``tokens_db`` starts with ``redis://`` or
                  ``rediss://`` (requires ``pip install 'schwabdev[redis]'``).
                - Assigned json store if ``tokens_db`` ends with ``.json``.
            timeout (int): Request timeout in seconds.
            call_on_auth (function | None): Function to call for custom auth flow.
            open_browser_for_auth (bool): Whether to open the browser for authentication.
            validate_params (bool): Whether to validate request parameters.
        """
        super().__init__(app_key, app_secret, callback_url, tokens_db, encryption, timeout,
                         call_on_auth, open_browser_for_auth, validate_params)
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {self.tokens.access_token}"})
        retry = Retry(
            total=3,
            connect=3, # dead/idle pooled connection
            read=2,
            backoff_factor=0.5,
            backoff_max=120,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=["GET", "PUT", "DELETE"], # no retries for POST (method not idempotent)
            raise_on_status=False,
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retry))
        self._session_lock = threading.RLock()

    def update_tokens(self, force_access_token: bool = False, force_refresh_token: bool = False) -> bool:
        """
        Update tokens if needed and refresh the session's auth header.

        Returns:
            bool: True if tokens were updated, False otherwise.
        """
        if self.tokens.update_tokens(force_access_token, force_refresh_token):
            with self._session_lock:
                self._session.headers["Authorization"] = f"Bearer {self.tokens.access_token}"
            return True
        return False

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        self.update_tokens()
        with self._session_lock:
            return self._session.request(method, f"{self._base_api_url}{path}", timeout=self.timeout, **kwargs)

    def close(self):
        try:
            with self._session_lock:
                self._session.close()
        except Exception as e:
            self.logger.debug(f"{e} (Closed before full init?)")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def __del__(self):
        self.close()

    """
    Accounts and Trading Production
    """

    def linked_accounts(self) -> requests.Response:
        """
        Account numbers in plain text cannot be used outside of headers or request/response bodies.
        As the first step consumers must invoke this service to retrieve the list of plain text/encrypted
        value pairs, and use encrypted account values for all subsequent calls for any accountNumber request.

        Returns:
            requests.Response: All linked account numbers and hashes.
        """
        return self._request("GET", "/trader/v1/accounts/accountNumbers")

    def account_details_all(self, fields: str | None = None) -> requests.Response:
        """
        All linked account information for the logged-in user. Balances are returned by default;
        positions are returned based on the "positions" flag.

        Args:
            fields (str | None): fields to return (options: "positions").

        Returns:
            requests.Response: details for all linked accounts.
        """
        self._validator._v_account_details_all(fields)
        return self._request("GET", "/trader/v1/accounts/",
                             params=self._parse_params({"fields": fields}))

    def account_details(self, accountHash: str, fields: str | None = None) -> requests.Response:
        """
        Specific account information with balances and positions.

        Args:
            accountHash (str): account hash from linked_accounts().
            fields (str | None): fields to return.

        Returns:
            requests.Response: details for one linked account.
        """
        self._validator._v_account_details(accountHash, fields)
        return self._request("GET", f"/trader/v1/accounts/{accountHash}",
                             params=self._parse_params({"fields": fields}))

    def account_orders(self, accountHash: str, fromEnteredTime: datetime.datetime | str,
                       toEnteredTime: datetime.datetime | str, maxResults: int | None = None,
                       status: str | None = None) -> requests.Response:
        """
        All orders for a specific account, filterable by the parameters below. Max date range is 1 year.

        Args:
            accountHash (str): account hash from linked_accounts().
            fromEnteredTime (datetime.datetime | str): start date.
            toEnteredTime (datetime.datetime | str): end date.
            maxResults (int | None): maximum number of results (default 3000).
            status (str | None): status of order.

        Returns:
            requests.Response: orders for one linked account.
        """
        self._validator._v_account_orders(accountHash, fromEnteredTime, toEnteredTime, maxResults, status)
        return self._request("GET", f"/trader/v1/accounts/{accountHash}/orders",
                             params=self._parse_params({
                                 "fromEnteredTime": self._time_convert(fromEnteredTime, TimeFormat.ISO_8601),
                                 "toEnteredTime": self._time_convert(toEnteredTime, TimeFormat.ISO_8601),
                                 "maxResults": maxResults,
                                 "status": status}))

    def place_order(self, accountHash: str, order: dict) -> requests.Response:
        """
        Place an order for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            order (dict): order dictionary (format examples in github documentation).

        Returns:
            requests.Response: order number in response header (absent if immediately filled).
        """
        self._validator._v_order(accountHash, order)
        return self._request("POST", f"/trader/v1/accounts/{accountHash}/orders",
                             headers={"Accept": "application/json", "Content-Type": "application/json"},
                             json=order)

    def order_details(self, accountHash: str, orderId: int | str) -> requests.Response:
        """
        Get a specific order by its ID, for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            orderId (int | str): order id.

        Returns:
            requests.Response: order details.
        """
        self._validator._v_order_id(accountHash, orderId)
        return self._request("GET", f"/trader/v1/accounts/{accountHash}/orders/{orderId}")

    def cancel_order(self, accountHash: str, orderId: int | str) -> requests.Response:
        """
        Cancel a specific order by its ID, for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            orderId (int | str): order id.

        Returns:
            requests.Response: response code.
        """
        self._validator._v_order_id(accountHash, orderId)
        return self._request("DELETE", f"/trader/v1/accounts/{accountHash}/orders/{orderId}")

    def replace_order(self, accountHash: str, orderId: int | str, order: dict) -> requests.Response:
        """
        Replace an existing order. The old order is canceled and a new order is created.

        Args:
            accountHash (str): account hash from linked_accounts().
            orderId (int | str): order id.
            order (dict): order dictionary (format examples in github documentation).

        Returns:
            requests.Response: response code.
        """
        self._validator._v_replace_order(accountHash, orderId, order)
        return self._request("PUT", f"/trader/v1/accounts/{accountHash}/orders/{orderId}",
                             headers={"Accept": "application/json", "Content-Type": "application/json"},
                             json=order)

    def account_orders_all(self, fromEnteredTime: datetime.datetime | str,
                           toEnteredTime: datetime.datetime | str, maxResults: int | None = None,
                           status: str | None = None) -> requests.Response:
        """
        Get all orders for all accounts.

        Args:
            fromEnteredTime (datetime.datetime | str): start date.
            toEnteredTime (datetime.datetime | str): end date.
            maxResults (int | None): maximum number of results (default 3000).
            status (str | None): status of order (see documentation for possible values).

        Returns:
            requests.Response: all orders.
        """
        self._validator._v_orders_all(fromEnteredTime, toEnteredTime, maxResults, status)
        return self._request("GET", "/trader/v1/orders",
                             headers={"Accept": "application/json"},
                             params=self._parse_params({
                                 "fromEnteredTime": self._time_convert(fromEnteredTime, TimeFormat.ISO_8601),
                                 "toEnteredTime": self._time_convert(toEnteredTime, TimeFormat.ISO_8601),
                                 "maxResults": maxResults,
                                 "status": status}))

    def preview_order(self, accountHash: str, orderObject: dict) -> requests.Response:
        """
        Preview an order for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            orderObject (dict): order dictionary.
        """
        self._validator._v_order(accountHash, orderObject)
        return self._request("POST", f"/trader/v1/accounts/{accountHash}/previewOrder",
                             headers={"Content-Type": "application/json"}, json=orderObject)

    def transactions(self, accountHash: str, startDate: datetime.datetime | str,
                     endDate: datetime.datetime | str, types: str, symbol: str | None = None) -> requests.Response:
        """
        All transactions for a specific account. Max 3000 transactions; max date range is 1 year.

        Args:
            accountHash (str): account hash from linked_accounts().
            startDate (datetime.datetime | str): start date.
            endDate (datetime.datetime | str): end date.
            types (str): transaction type (see documentation for possible values).
            symbol (str | None): symbol.

        Returns:
            requests.Response: list of transactions for a specific account.
        """
        self._validator._v_transactions(accountHash, startDate, endDate, types, symbol)
        return self._request("GET", f"/trader/v1/accounts/{accountHash}/transactions",
                             params=self._parse_params({
                                 "startDate": self._time_convert(startDate, TimeFormat.ISO_8601),
                                 "endDate": self._time_convert(endDate, TimeFormat.ISO_8601),
                                 "types": types,
                                 "symbol": symbol}))

    def transaction_details(self, accountHash: str, transactionId: str | int) -> requests.Response:
        """
        Get specific transaction information for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            transactionId (str | int): transaction id.

        Returns:
            requests.Response: transaction details.
        """
        self._validator._v_transaction_details(accountHash, transactionId)
        return self._request("GET", f"/trader/v1/accounts/{accountHash}/transactions/{transactionId}")

    def preferences(self) -> requests.Response:
        """
        Get user preference information for the logged-in user.

        Returns:
            requests.Response: User preferences and streaming info.
        """
        return self._request("GET", "/trader/v1/userPreference")

    """
    Market Data
    """

    def quotes(self, symbols: list[str] | str, fields: str | None = None, indicative: bool = False) -> requests.Response:
        """
        Get quotes for a list of tickers.

        Args:
            symbols (list[str] | str): symbols (e.g. "AMD,INTC" or ["AMD", "INTC"]).
            fields (str): fields to get ("all", "quote", "fundamental").
            indicative (bool): whether to get indicative quotes.

        Returns:
            requests.Response: list of quotes.
        """
        self._validator._v_quotes(symbols, fields, indicative)
        return self._request("GET", "/marketdata/v1/quotes",
                             params=self._parse_params({
                                 "symbols": self._format_list(symbols),
                                 "fields": fields,
                                 "indicative": indicative}))

    def quote(self, symbol_id: str, fields: str | None = None) -> requests.Response:
        """
        Get quote for a single symbol.

        Args:
            symbol_id (str): ticker symbol.
            fields (str): fields to get ("all", "quote", "fundamental").

        Returns:
            requests.Response: quote for a single symbol.
        """
        self._validator._v_quote(symbol_id, fields)
        return self._request("GET", f'/marketdata/v1/{urllib.parse.quote(symbol_id, safe="")}/quotes',
                             params=self._parse_params({"fields": fields}))

    def option_chains(self, symbol: str, contractType: str | None = None, strikeCount: int | None = None,
                      includeUnderlyingQuote: bool | None = None, strategy: str | None = None,
                      interval: str | None = None, strike: float | None = None, range: str | None = None,
                      fromDate: datetime.datetime | datetime.date | str | None = None,
                      toDate: datetime.datetime | datetime.date | str | None = None, volatility: float | None = None,
                      underlyingPrice: float | None = None, interestRate: float | None = None,
                      daysToExpiration: int | None = None, expMonth: str | None = None,
                      optionType: str | None = None, entitlement: str | None = None) -> requests.Response:
        """
        Get an option chain for a ticker (contracts associated with each expiration).

        Args:
            symbol (str): ticker symbol.
            contractType (str): contract type ("CALL"|"PUT"|"ALL").
            strikeCount (int): strike count.
            includeUnderlyingQuote (bool): include underlying quote.
            strategy (str): strategy ("SINGLE"|"ANALYTICAL"|"COVERED"|"VERTICAL"|"CALENDAR"|"STRANGLE"|
                "STRADDLE"|"BUTTERFLY"|"CONDOR"|"DIAGONAL"|"COLLAR"|"ROLL").
            interval (str): strike interval.
            strike (float): strike price.
            range (str): range ("ITM"|"NTM"|"OTM"...).
            fromDate (datetime | str): from date (cannot be earlier than the current date).
            toDate (datetime | str): to date.
            volatility (float): volatility.
            underlyingPrice (float): underlying price.
            interestRate (float): interest rate.
            daysToExpiration (int): days to expiration.
            expMonth (str): expiration month.
            optionType (str): option type ("ALL"|"CALL"|"PUT").
            entitlement (str): entitlement ("ALL"|"AMERICAN"|"EUROPEAN").

        Notes:
            1. Large responses can trigger a "Body buffer overflow" error; add parameters to limit data.
            2. Some Schwab symbols differ; use Schwab research tools to find tickers.

        Returns:
            requests.Response: option chain.
        """
        self._validator._v_option_chains(symbol, contractType, strikeCount, includeUnderlyingQuote, strategy, interval, strike, range, fromDate, toDate, volatility, underlyingPrice, interestRate, daysToExpiration, expMonth, optionType, entitlement)
        return self._request("GET", "/marketdata/v1/chains",
                             params=self._parse_params({
                                 "symbol": symbol,
                                 "contractType": contractType,
                                 "strikeCount": strikeCount,
                                 "includeUnderlyingQuote": includeUnderlyingQuote,
                                 "strategy": strategy,
                                 "interval": interval,
                                 "strike": strike,
                                 "range": range,
                                 "fromDate": self._time_convert(fromDate, TimeFormat.YYYY_MM_DD),
                                 "toDate": self._time_convert(toDate, TimeFormat.YYYY_MM_DD),
                                 "volatility": volatility,
                                 "underlyingPrice": underlyingPrice,
                                 "interestRate": interestRate,
                                 "daysToExpiration": daysToExpiration,
                                 "expMonth": expMonth,
                                 "optionType": optionType,
                                 "entitlement": entitlement}))

    def option_expiration_chain(self, symbol: str) -> requests.Response:
        """
        Get an option expiration chain for a ticker.

        Args:
            symbol (str): ticker symbol.

        Returns:
            requests.Response: option expiration chain.
        """
        self._validator._v_symbol(symbol)
        return self._request("GET", "/marketdata/v1/expirationchain",
                             params=self._parse_params({"symbol": symbol}))

    def price_history(self, symbol: str, periodType: str | None = None, period: int | None = None,
                      frequencyType: str | None = None, frequency: int | None = None,
                      startDate: datetime.datetime | str | None = None, endDate: datetime.datetime | str | None = None,
                      needExtendedHoursData: bool | None = None, needPreviousClose: bool | None = None) -> requests.Response:
        """
        Get price history for a ticker.

        Args:
            symbol (str): ticker symbol.
            periodType (str): period type ("day"|"month"|"year"|"ytd").
            period (int): period.
            frequencyType (str): frequency type ("minute"|"daily"|"weekly"|"monthly").
            frequency (int): frequency (minute: 1,5,10,15,30; daily/weekly/monthly: 1).
            startDate (datetime | str): start date.
            endDate (datetime | str): end date.
            needExtendedHoursData (bool): need extended hours data.
            needPreviousClose (bool): need previous close.

        Returns:
            requests.Response: candle history.
        """
        self._validator._v_price_history(symbol, periodType, period, frequencyType, frequency, startDate, endDate, needExtendedHoursData, needPreviousClose)
        return self._request("GET", "/marketdata/v1/pricehistory",
                             params=self._parse_params({
                                 "symbol": symbol,
                                 "periodType": periodType,
                                 "period": period,
                                 "frequencyType": frequencyType,
                                 "frequency": frequency,
                                 "startDate": self._time_convert(startDate, TimeFormat.EPOCH_MS),
                                 "endDate": self._time_convert(endDate, TimeFormat.EPOCH_MS),
                                 "needExtendedHoursData": needExtendedHoursData,
                                 "needPreviousClose": needPreviousClose}))

    def movers(self, symbol: str, sort: str | None = None, frequency: int | None = None) -> requests.Response:
        """
        Get movers in a specific index and direction.

        Args:
            symbol (str): symbol ("$DJI"|"$COMPX"|"$SPX"|"NYSE"|"NASDAQ"|"OTCBB"|"INDEX_ALL"|
                "EQUITY_ALL"|"OPTION_ALL"|"OPTION_PUT"|"OPTION_CALL").
            sort (str): sort ("VOLUME"|"TRADES"|"PERCENT_CHANGE_UP"|"PERCENT_CHANGE_DOWN").
            frequency (int): frequency (0|1|5|10|30|60).

        Notes:
            Must be called within market hours.

        Returns:
            requests.Response: movers.
        """
        self._validator._v_movers(symbol, sort, frequency)
        return self._request("GET", f"/marketdata/v1/movers/{symbol}",
                             headers={"accept": "application/json"},
                             params=self._parse_params({"sort": sort, "frequency": frequency}))

    def market_hours(self, symbols: list[str], date: datetime.datetime | datetime.date | str | None = None) -> requests.Response:
        """
        Get market hours for dates in the future across different markets.

        Args:
            symbols (list[str]): market symbols ("equity", "option", "bond", "future", "forex").
            date (datetime | str): date.

        Returns:
            requests.Response: market hours.
        """
        self._validator._v_market_hours(symbols, date)
        return self._request("GET", "/marketdata/v1/markets",
                             params=self._parse_params({
                                 "markets": self._format_list(symbols),
                                 "date": self._time_convert(date, TimeFormat.YYYY_MM_DD)}))

    def market_hour(self, market_id: str, date: datetime.datetime | datetime.date | str | None = None) -> requests.Response:
        """
        Get market hours for dates in the future for a single market.

        Args:
            market_id (str): market id ("equity"|"option"|"bond"|"future"|"forex").
            date (datetime | str): date.

        Returns:
            requests.Response: market hours.
        """
        self._validator._v_market_hour(market_id, date)
        return self._request("GET", f"/marketdata/v1/markets/{market_id}",
                             params=self._parse_params({"date": self._time_convert(date, TimeFormat.YYYY_MM_DD)}))

    def instruments(self, symbols: str, projection: str) -> requests.Response:
        """
        Get instruments for a list of symbols.

        Args:
            symbols (str): symbol(s).
            projection (str): projection ("symbol-search"|"symbol-regex"|"desc-search"|"desc-regex"|
                "search"|"fundamental").

        Returns:
            requests.Response: instruments.
        """
        self._validator._v_instruments(symbols, projection)
        return self._request("GET", "/marketdata/v1/instruments",
                             params={"symbol": self._format_list(symbols), "projection": projection})

    def instrument_cusip(self, cusip_id: str | int) -> requests.Response:
        """
        Get instrument for a single cusip.

        Args:
            cusip_id (str | int): cusip id.

        Returns:
            requests.Response: instrument.
        """
        self._validator._v_cusip(cusip_id)
        return self._request("GET", f"/marketdata/v1/instruments/{cusip_id}")


class ClientAsync(ClientBase):

    def __init__(self, app_key: str = None, app_secret: str = None, callback_url: str = "https://127.0.0.1",
                 tokens_db: str = "~/.schwabdev/tokens.db", encryption: str = None, timeout: int = 10,
                 call_on_auth: callable = None, open_browser_for_auth: bool = True, 
                 validate_params: bool = True, parsed: bool = False):
        if aiohttp is None:
            raise ImportError("aiohttp is required to use ClientAsync")
        super().__init__(app_key, app_secret, callback_url, tokens_db, encryption, timeout,
                         call_on_auth, open_browser_for_auth, validate_params)
        self._parsed = parsed
        self._session = aiohttp.ClientSession(
            base_url=self._base_api_url,
            headers={"Authorization": f"Bearer {self.tokens.access_token}"},
            timeout=aiohttp.ClientTimeout(total=self.timeout))
        self._session_lock = threading.RLock()

    def update_tokens(self, force_access_token: bool = False, force_refresh_token: bool = False) -> bool:
        """
        Update tokens if needed and refresh the session's auth header.

        Returns:
            bool: True if tokens were updated, False otherwise.
        """
        if self.tokens.update_tokens(force_access_token, force_refresh_token):
            with self._session_lock:
                self._session.headers["Authorization"] = f"Bearer {self.tokens.access_token}"
            return True
        return False

    async def _checker(self):
        while True:
            self.update_tokens()
            await asyncio.sleep(30)

    async def __aenter__(self):
        self._task_group = asyncio.TaskGroup()
        await self._task_group.__aenter__()
        self._checker_task = self._task_group.create_task(self._checker())  # background token refresh
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._checker_task.cancel()
        await asyncio.shield(self._session.close())
        return await self._task_group.__aexit__(exc_type, exc_val, exc_tb)

    async def _parse_response(self, response, parsed: bool | None = None):
        """Return the raw response, or its JSON/text body when parsing is requested."""
        if parsed or (parsed is None and self._parsed):
            if response.headers.get("Content-Type", "").lower().startswith("application/json"):
                return await response.json()
            return await response.text()  # assume text/html | text/plain | etc.
        return response

    async def _request(self, method: str, path: str, *, parsed: bool | None = None, **kwargs):
        """Issue a request on the shared aiohttp session and optionally parse the body."""
        response = await self._session.request(method, path, **kwargs)
        return await self._parse_response(response, parsed)

    @staticmethod
    def _handle_aiohttp_bool(value):
        """aiohttp does not accept bools as query params; encode to 'true'/'false' or None."""
        if value is None:
            return None
        return "true" if value else "false"

    """
    Accounts and Trading Production
    """

    async def linked_accounts(self, parsed: bool | None = None):
        """
        Account numbers in plain text cannot be used outside of headers or request/response bodies.
        Invoke this first to retrieve plain text/encrypted value pairs, then use encrypted values.

        Returns:
            All linked account numbers and hashes.
        """
        return await self._request("GET", "/trader/v1/accounts/accountNumbers", parsed=parsed)

    async def account_details_all(self, fields: str = None, parsed: bool | None = None):
        """
        All linked account information for the logged-in user. Balances by default; positions via flag.

        Args:
            fields (str | None): fields to return (options: "positions").
        """
        self._validator._v_account_details_all(fields)
        return await self._request("GET", "/trader/v1/accounts/",
                                   params=self._parse_params({"fields": fields}), parsed=parsed)

    async def account_details(self, accountHash: str, fields: str = None, parsed: bool | None = None):
        """
        Specific account information with balances and positions.

        Args:
            accountHash (str): account hash from linked_accounts().
            fields (str | None): fields to return.
        """
        self._validator._v_account_details(accountHash, fields)
        return await self._request("GET", f"/trader/v1/accounts/{accountHash}",
                                   params=self._parse_params({"fields": fields}), parsed=parsed)

    async def account_orders(self, accountHash: str, fromEnteredTime: datetime.datetime | str,
                             toEnteredTime: datetime.datetime | str, maxResults: int = None,
                             status: str = None, parsed: bool | None = None):
        """
        All orders for a specific account, filterable below. Max date range is 1 year.

        Args:
            accountHash (str): account hash from linked_accounts().
            fromEnteredTime (datetime | str): start date.
            toEnteredTime (datetime | str): end date.
            maxResults (int | None): maximum number of results (default 3000).
            status (str | None): status of order.
        """
        self._validator._v_account_orders(accountHash, fromEnteredTime, toEnteredTime, maxResults, status)
        return await self._request("GET", f"/trader/v1/accounts/{accountHash}/orders",
                                   headers={"Accept": "application/json"},
                                   params=self._parse_params({
                                       "maxResults": maxResults,
                                       "fromEnteredTime": self._time_convert(fromEnteredTime, TimeFormat.ISO_8601),
                                       "toEnteredTime": self._time_convert(toEnteredTime, TimeFormat.ISO_8601),
                                       "status": status}), parsed=parsed)

    async def place_order(self, accountHash: str, order: dict):
        """
        Place an order for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            order (dict): order dictionary.

        Returns:
            Raw response (order number is in the response header).
        """
        self._validator._v_order(accountHash, order)
        return await self._request("POST", f"/trader/v1/accounts/{accountHash}/orders",
                                   headers={"Accept": "application/json", "Content-Type": "application/json"},
                                   json=order, parsed=False)  # must be raw to read headers

    async def order_details(self, accountHash: str, orderId: int | str, parsed: bool | None = None):
        """
        Get a specific order by its ID, for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            orderId (int | str): order id.
        """
        self._validator._v_order_id(accountHash, orderId)
        return await self._request("GET", f"/trader/v1/accounts/{accountHash}/orders/{orderId}", parsed=parsed)

    async def cancel_order(self, accountHash: str, orderId: int | str, parsed: bool | None = None):
        """
        Cancel a specific order by its ID, for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            orderId (int | str): order id.
        """
        self._validator._v_order_id(accountHash, orderId)
        return await self._request("DELETE", f"/trader/v1/accounts/{accountHash}/orders/{orderId}", parsed=parsed)

    async def replace_order(self, accountHash: str, orderId: int | str, order: dict):
        """
        Replace an existing order. The old order is canceled and a new order is created.

        Args:
            accountHash (str): account hash from linked_accounts().
            orderId (int | str): order id.
            order (dict): order dictionary.

        Returns:
            Raw response (order number is in the response header).
        """
        self._validator._v_replace_order(accountHash, orderId, order)
        return await self._request("PUT", f"/trader/v1/accounts/{accountHash}/orders/{orderId}",
                                   headers={"Accept": "application/json", "Content-Type": "application/json"},
                                   json=order, parsed=False)  # must be raw to read headers

    async def account_orders_all(self, fromEnteredTime: datetime.datetime | str,
                                 toEnteredTime: datetime.datetime | str, maxResults: int = None,
                                 status: str = None, parsed: bool | None = None):
        """
        Get all orders for all accounts.

        Args:
            fromEnteredTime (datetime | str): start date.
            toEnteredTime (datetime | str): end date.
            maxResults (int | None): maximum number of results (default 3000).
            status (str | None): status of order.
        """
        self._validator._v_orders_all(fromEnteredTime, toEnteredTime, maxResults, status)
        return await self._request("GET", "/trader/v1/orders",
                                   headers={"Accept": "application/json"},
                                   params=self._parse_params({
                                       "maxResults": maxResults,
                                       "fromEnteredTime": self._time_convert(fromEnteredTime, TimeFormat.ISO_8601),
                                       "toEnteredTime": self._time_convert(toEnteredTime, TimeFormat.ISO_8601),
                                       "status": status}), parsed=parsed)

    async def preview_order(self, accountHash: str, order: dict, parsed: bool | None = None):
        """Preview an order for a specific account."""
        self._validator._v_order(accountHash, order)
        return await self._request("POST", f"/trader/v1/accounts/{accountHash}/previewOrder",
                                   headers={"Content-Type": "application/json"}, json=order, parsed=parsed)

    async def transactions(self, accountHash: str, startDate: datetime.datetime | str,
                           endDate: datetime.datetime | str, types: str, symbol: str = None,
                           parsed: bool | None = None):
        """
        All transactions for a specific account. Max 3000; max date range is 1 year.

        Args:
            accountHash (str): account hash from linked_accounts().
            startDate (datetime | str): start date.
            endDate (datetime | str): end date.
            types (str): transaction type.
            symbol (str | None): symbol.
        """
        self._validator._v_transactions(accountHash, startDate, endDate, types, symbol)
        return await self._request("GET", f"/trader/v1/accounts/{accountHash}/transactions",
                                   params=self._parse_params({
                                       "startDate": self._time_convert(startDate, TimeFormat.ISO_8601),
                                       "endDate": self._time_convert(endDate, TimeFormat.ISO_8601),
                                       "symbol": symbol,
                                       "types": types}), parsed=parsed)

    async def transaction_details(self, accountHash: str, transactionId: str | int, parsed: bool | None = None):
        """
        Get specific transaction information for a specific account.

        Args:
            accountHash (str): account hash from linked_accounts().
            transactionId (str | int): transaction id.
        """
        self._validator._v_transaction_details(accountHash, transactionId)
        return await self._request("GET", f"/trader/v1/accounts/{accountHash}/transactions/{transactionId}", parsed=parsed)

    async def preferences(self, parsed: bool | None = None):
        """
        Get user preference information for the logged-in user.

        Returns:
            User preferences and streaming info.
        """
        return await self._request("GET", "/trader/v1/userPreference", parsed=parsed)

    """
    Market Data
    """

    async def quotes(self, symbols: list[str] | str, fields: str = None, indicative: bool = False,
                     parsed: bool | None = None):
        """
        Get quotes for a list of tickers.

        Args:
            symbols (list[str] | str): symbols (e.g. "AMD,INTC" or ["AMD", "INTC"]).
            fields (str): fields to get ("all", "quote", "fundamental").
            indicative (bool): whether to get indicative quotes.
        """
        self._validator._v_quotes(symbols, fields, indicative)
        return await self._request("GET", "/marketdata/v1/quotes",
                                   params=self._parse_params({
                                       "symbols": self._format_list(symbols),
                                       "fields": fields,
                                       "indicative": self._handle_aiohttp_bool(indicative)}), parsed=parsed)

    async def quote(self, symbol_id: str, fields: str = None, parsed: bool | None = None):
        """
        Get quote for a single symbol.

        Args:
            symbol_id (str): ticker symbol.
            fields (str): fields to get ("all", "quote", "fundamental").
        """
        self._validator._v_quote(symbol_id, fields)
        return await self._request("GET", f'/marketdata/v1/{urllib.parse.quote(symbol_id, safe="")}/quotes',
                                   params=self._parse_params({"fields": fields}), parsed=parsed)

    async def option_chains(self, symbol: str, contractType: str | None = None, strikeCount: int | None = None,
                            includeUnderlyingQuote: bool | None = None, strategy: str | None = None,
                            interval: str | None = None, strike: float | None = None, range: str | None = None,
                            fromDate: datetime.datetime | datetime.date | str | None = None,
                            toDate: datetime.datetime | datetime.date | str | None = None, volatility: float | None = None,
                            underlyingPrice: float | None = None, interestRate: float | None = None,
                            daysToExpiration: int | None = None, expMonth: str | None = None,
                            optionType: str | None = None, entitlement: str | None = None, parsed: bool | None = None):
        """
        Get an option chain for a ticker (contracts associated with each expiration).

        Args (see sync Client.option_chains for full descriptions):
            symbol, contractType, strikeCount, includeUnderlyingQuote, strategy, interval, strike,
            range, fromDate, toDate, volatility, underlyingPrice, interestRate, daysToExpiration,
            expMonth, optionType, entitlement.

        Notes:
            Large responses can trigger a "Body buffer overflow" error; add parameters to limit data.
        """
        self._validator._v_option_chains(symbol, contractType, strikeCount, includeUnderlyingQuote, strategy, interval, strike, range, fromDate, toDate, volatility, underlyingPrice, interestRate, daysToExpiration, expMonth, optionType, entitlement)
        return await self._request("GET", "/marketdata/v1/chains",
                                   params=self._parse_params({
                                       "symbol": symbol,
                                       "contractType": contractType,
                                       "strikeCount": strikeCount,
                                       "includeUnderlyingQuote": self._handle_aiohttp_bool(includeUnderlyingQuote),
                                       "strategy": strategy,
                                       "interval": interval,
                                       "strike": strike,
                                       "range": range,
                                       "fromDate": self._time_convert(fromDate, TimeFormat.YYYY_MM_DD),
                                       "toDate": self._time_convert(toDate, TimeFormat.YYYY_MM_DD),
                                       "volatility": volatility,
                                       "underlyingPrice": underlyingPrice,
                                       "interestRate": interestRate,
                                       "daysToExpiration": daysToExpiration,
                                       "expMonth": expMonth,
                                       "optionType": optionType,
                                       "entitlement": entitlement}), parsed=parsed)

    async def option_expiration_chain(self, symbol: str, parsed: bool | None = None):
        """
        Get an option expiration chain for a ticker.

        Args:
            symbol (str): ticker symbol.
        """
        self._validator._v_symbol(symbol)
        return await self._request("GET", "/marketdata/v1/expirationchain",
                                   params=self._parse_params({"symbol": symbol}), parsed=parsed)

    async def price_history(self, symbol: str, periodType: str | None = None, period: str | None = None,
                            frequencyType: str | None = None, frequency: int | None = None,
                            startDate: datetime.datetime | str | None = None, endDate: datetime.datetime | str | None = None,
                            needExtendedHoursData: bool | None = None, needPreviousClose: bool | None = None,
                            parsed: bool | None = None):
        """
        Get price history for a ticker.

        Args (see sync Client.price_history for full descriptions):
            symbol, periodType, period, frequencyType, frequency, startDate, endDate,
            needExtendedHoursData, needPreviousClose.
        """
        self._validator._v_price_history(symbol, periodType, period, frequencyType, frequency, startDate, endDate, needExtendedHoursData, needPreviousClose)
        return await self._request("GET", "/marketdata/v1/pricehistory",
                                   params=self._parse_params({
                                       "symbol": symbol,
                                       "periodType": periodType,
                                       "period": period,
                                       "frequencyType": frequencyType,
                                       "frequency": frequency,
                                       "startDate": self._time_convert(startDate, TimeFormat.EPOCH_MS),
                                       "endDate": self._time_convert(endDate, TimeFormat.EPOCH_MS),
                                       "needExtendedHoursData": self._handle_aiohttp_bool(needExtendedHoursData),
                                       "needPreviousClose": self._handle_aiohttp_bool(needPreviousClose)}), parsed=parsed)

    async def movers(self, symbol: str, sort: str = None, frequency: int | None = None, parsed: bool | None = None):
        """
        Get movers in a specific index and direction.

        Args:
            symbol (str): symbol (e.g. "$DJI", "$SPX", "NYSE", "NASDAQ", "OPTION_CALL"...).
            sort (str): sort ("VOLUME"|"TRADES"|"PERCENT_CHANGE_UP"|"PERCENT_CHANGE_DOWN").
            frequency (int): frequency (0|1|5|10|30|60).

        Notes:
            Must be called within market hours.
        """
        self._validator._v_movers(symbol, sort, frequency)
        return await self._request("GET", f"/marketdata/v1/movers/{symbol}",
                                   headers={"accept": "application/json"},
                                   params=self._parse_params({"sort": sort, "frequency": frequency}), parsed=parsed)

    async def market_hours(self, symbols: list[str], date: datetime.datetime | datetime.date | str = None,
                           parsed: bool | None = None):
        """
        Get market hours for dates in the future across different markets.

        Args:
            symbols (list[str]): market symbols ("equity", "option", "bond", "future", "forex").
            date (datetime | str): date.
        """
        self._validator._v_market_hours(symbols, date)
        return await self._request("GET", "/marketdata/v1/markets",
                                   params=self._parse_params({
                                       "markets": symbols,
                                       "date": self._time_convert(date, TimeFormat.YYYY_MM_DD)}), parsed=parsed)

    async def market_hour(self, market_id: str, date: datetime.datetime | datetime.date | str = None,
                          parsed: bool | None = None):
        """
        Get market hours for dates in the future for a single market.

        Args:
            market_id (str): market id ("equity"|"option"|"bond"|"future"|"forex").
            date (datetime | str): date.
        """
        self._validator._v_market_hour(market_id, date)
        return await self._request("GET", f"/marketdata/v1/markets/{market_id}",
                                   params=self._parse_params({"date": self._time_convert(date, TimeFormat.YYYY_MM_DD)}),
                                   parsed=parsed)

    async def instruments(self, symbol: str, projection: str, parsed: bool | None = None):
        """
        Get instruments for a list of symbols.

        Args:
            symbol (str): symbol(s).
            projection (str): projection ("symbol-search"|"symbol-regex"|"desc-search"|"desc-regex"|
                "search"|"fundamental").
        """
        self._validator._v_instruments(symbol, projection)
        return await self._request("GET", "/marketdata/v1/instruments",
                                   params={"symbol": symbol, "projection": projection}, parsed=parsed)

    async def instrument_cusip(self, cusip_id: str | int, parsed: bool | None = None):
        """
        Get instrument for a single cusip.

        Args:
            cusip_id (str | int): cusip id.
        """
        self._validator._v_cusip(cusip_id)
        return await self._request("GET", f"/marketdata/v1/instruments/{cusip_id}", parsed=parsed)
