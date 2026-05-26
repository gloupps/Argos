import aiohttp
import asyncio
from typing import Optional, Dict, Any


class Requester:

    def __init__(
        self,
        base_url: str = "",
        headers: Dict[str, str] = None,
        rate_limit: int = 5,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.timeout = aiohttp.ClientTimeout(total=timeout)

        self.semaphore = asyncio.Semaphore(rate_limit)
        self.session: Optional[aiohttp.ClientSession] = None

    # =========================
    # 🔥 SESSION MANAGEMENT
    # =========================
    async def init(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=self.timeout, headers=self.headers
            )

    async def close(self):
        if self.session:
            await self.session.close()

    # =========================
    # 🔥 CORE REQUEST
    # =========================
    async def request(
        self,
        method: str,
        endpoint: str = "",
        params: Dict[str, Any] = None,
        json: Dict[str, Any] = None,
        data: Any = None,
        headers: Dict[str, str] = None,
        retries: int = 3,
        return_json: bool = True,
    ) -> Optional[Any]:

        await self.init()

        url = f"{self.base_url}{endpoint}"
        params = params or {}

        merged_headers = {**self.headers, **(headers or {})}

        for attempt in range(retries):
            try:
                async with self.semaphore:
                    async with self.session.request(
                        method=method.upper(),
                        url=url,
                        params=params,
                        json=json,
                        data=data,
                        headers=merged_headers,
                        ssl=False,
                    ) as resp:

                        # 🔥 HTTP handling
                        if resp.status == 204:
                            return None

                        if resp.status == 403:
                            return None

                        if resp.status >= 500:
                            raise Exception(f"Server error {resp.status}")

                        # 🔥 Return raw si besoin
                        if not return_json:
                            return await resp.text()

                        # 🔥 Sécurité JSON
                        content_type = resp.headers.get("Content-Type", "")
                        if "application/json" not in content_type:
                            return None

                        return await resp.json()

            except (aiohttp.ClientError, asyncio.TimeoutError):
                if attempt == retries - 1:
                    return None

                await asyncio.sleep(2**attempt)  # exponential backoff

        return None

    # =========================
    # 🔥 SHORTCUTS
    # =========================
    async def get(self, endpoint="", **kwargs):
        return await self.request("GET", endpoint, **kwargs)

    async def post(self, endpoint="", **kwargs):
        return await self.request("POST", endpoint, **kwargs)

    async def put(self, endpoint="", **kwargs):
        return await self.request("PUT", endpoint, **kwargs)

    async def delete(self, endpoint="", **kwargs):
        return await self.request("DELETE", endpoint, **kwargs)
