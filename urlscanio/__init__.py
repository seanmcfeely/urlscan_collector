import asyncio
import json
import logging
from pathlib import Path

import aiohttp

DEFAULT_URLSCAN_API_URL = "https://urlscan.io/api/v1"

class UrlScan:
    DEFAULT_PAUSE_TIME = 3
    DEFAULT_MAX_ATTEMPTS = 15

    def __init__(self, api_key, api_url=DEFAULT_URLSCAN_API_URL, ssl_verify=True, data_dir=Path.cwd(), log_level=logging.INFO):
        self.api_key = api_key
        self.api_url = api_url
        self.data_dir = data_dir
        self.session = aiohttp.ClientSession(trust_env=True)
        self.verbose = True
        self.ssl_verify = ssl_verify
        self.logger = logging.getLogger("urlscan.UrlScan")
        self.logger.setLevel(log_level)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *excinfo):
        await self.session.close()

    async def execute(self, method, url, headers=None, payload=None, params={}):
        async with self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=json.dumps(payload),
                params=params,
                ssl=self.ssl_verify) as response:
            self.logger.debug("%s request made to %s with %d response code", method, url, response.status)
            return response.status, await response.read()

    async def search(self, query: str, search_after: str=None,  size: int=1000, **kwargs):
        headers = {"API-Key": self.api_key}
        params = {"q": query,
                  "size": size}
        if search_after:
            params["search_after"] = search_after
        status, response = await self.execute("GET", f"{self.api_url}/search/", headers, params=params)
        if status == 429:
            self.logger.critical("UrlScan did not accept scan request for %s, reason: too many requests", query)
            return False
        body = json.loads(response)
        if status >= 400:
            self.logger.critical("UrlScan did not accept scan request for %s, reason: %s", query, body["message"])
            return False
        return body
