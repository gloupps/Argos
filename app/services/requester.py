import aiohttp
import asyncio
from typing import Optional, Dict, Any


class Requester:
    """
    Stateless HTTP client — crée une session fraîche par appel.
    On n'utilise PAS de session persistante car chaque job tourne
    dans une nouvelle event loop (asyncio.run) et une session
    aiohttp est liée à la loop qui l'a créée.
    """

    def __init__(self, base_url="", headers=None, rate_limit=5, timeout=30):
        self.base_url  = base_url.rstrip("/")
        self.headers   = headers or {}
        self.timeout   = aiohttp.ClientTimeout(total=timeout)
        self._sem_val  = rate_limit   # stocke la valeur, Semaphore créé par coroutine

    async def request(
        self, method, endpoint="", params=None, json=None,
        data=None, headers=None, retries=3, return_json=True,
    ) -> Optional[Any]:

        url    = f"{self.base_url}{endpoint}"
        params = params or {}
        merged = {**self.headers, **(headers or {})}

        # Session et Semaphore créés dans la loop courante
        async with aiohttp.ClientSession(
            timeout=self.timeout, headers=merged
        ) as session:
            sem = asyncio.Semaphore(self._sem_val)

            for attempt in range(retries):
                try:
                    async with sem:
                        async with session.request(
                            method=method.upper(), url=url,
                            params=params, json=json, data=data,
                            ssl=False,
                        ) as resp:
                            if resp.status == 204: return None
                            if resp.status == 403: return None
                            if resp.status >= 500:
                                raise Exception(f"Server error {resp.status}")
                            if not return_json:
                                return await resp.text()
                            if "application/json" not in resp.headers.get("Content-Type", ""):
                                return None
                            return await resp.json()

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    if attempt == retries - 1:
                        return None
                    await asyncio.sleep(2 ** attempt)

        return None

    async def get(self, endpoint="", **kw):    return await self.request("GET",    endpoint, **kw)
    async def post(self, endpoint="", **kw):   return await self.request("POST",   endpoint, **kw)
    async def put(self, endpoint="", **kw):    return await self.request("PUT",    endpoint, **kw)
    async def delete(self, endpoint="", **kw): return await self.request("DELETE", endpoint, **kw)
