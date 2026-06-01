# app/services/requester.py
import aiohttp
import asyncio
import logging
from typing import Optional, Any, Tuple

logger = logging.getLogger(__name__)


class Requester:
    """
    Client HTTP async stateless — une session fraîche par appel.

    Pas de session persistante : chaque job tourne dans une nouvelle
    event loop (asyncio.run) et une session aiohttp est liée à la loop
    qui l'a créée.

    Paramètres
    ──────────
    base_url    : préfixe ajouté à tous les endpoints (peut être vide)
    headers     : headers globaux fusionnés avec ceux de chaque appel
    rate_limit  : nombre de requêtes simultanées max (Semaphore)
    timeout     : timeout total en secondes
    """

    def __init__(
        self,
        base_url: str = "",
        headers: Optional[dict] = None,
        rate_limit: int = 5,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.headers = headers or {}
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._sem_val = rate_limit

    # ─────────────────────────────────────────────────────
    # Méthode principale
    # ─────────────────────────────────────────────────────
    async def request(
        self,
        method: str,
        endpoint: str = "",
        *,
        params: Optional[dict] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[dict] = None,
        auth: Optional[Tuple[str, str]] = None,
        retries: int = 3,
        return_json: bool = True,
    ) -> Optional[Any]:
        """
        Effectue une requête HTTP avec retry exponentiel.

        Paramètres
        ──────────
        method      : verbe HTTP ("GET", "POST", …)
        endpoint    : chemin ajouté à base_url, OU URL absolue complète
        params      : query string parameters
        json        : corps JSON (sérialisation auto)
        data        : corps brut (form data, bytes…)
        headers     : headers additionnels, fusionnés avec self.headers
        auth        : tuple (login, password) pour HTTP Basic Auth
        retries     : nombre de tentatives avant abandon
        return_json : si False, retourne le texte brut de la réponse

        Retour
        ──────
        dict | list | str | None
            None si la requête échoue ou retourne un status non exploitable.
        """
        # URL : si l'endpoint est déjà absolu on l'utilise tel quel
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            url = endpoint
        else:
            url = f"{self.base_url}{endpoint}"

        merged_headers = {**self.headers, **(headers or {})}
        _auth = aiohttp.BasicAuth(auth[0], auth[1]) if auth else None

        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(
            timeout=self.timeout,
            headers=merged_headers,
            connector=connector,
        ) as session:
            sem = asyncio.Semaphore(self._sem_val)

            for attempt in range(retries):
                try:
                    async with sem:
                        async with session.request(
                            method=method.upper(),
                            url=url,
                            params=params or {},
                            json=json,
                            data=data,
                            auth=_auth,
                        ) as resp:
                            return await self._handle_response(
                                resp, url, method, return_json
                            )

                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    if attempt == retries - 1:
                        logger.warning(
                            "[Requester] %s %s — échec après %d tentatives : %s",
                            method.upper(),
                            url,
                            retries,
                            exc,
                        )
                        return None
                    wait = 2**attempt
                    logger.debug(
                        "[Requester] %s %s — tentative %d/%d, retry dans %ds",
                        method.upper(),
                        url,
                        attempt + 1,
                        retries,
                        wait,
                    )
                    await asyncio.sleep(wait)

        return None

    # ─────────────────────────────────────────────────────
    # Gestion des réponses HTTP
    # ─────────────────────────────────────────────────────
    async def _handle_response(
        self,
        resp: aiohttp.ClientResponse,
        url: str,
        method: str,
        return_json: bool,
    ) -> Optional[Any]:
        status = resp.status

        # ── Succès sans corps ──────────────────────────────
        if status == 204:
            return None

        # ── Auth / droits ──────────────────────────────────
        if status in (401, 403):
            logger.warning("[Requester] %s %s → %d (auth refusé)", method, url, status)
            return None

        # ── Ressource introuvable ──────────────────────────
        if status == 404:
            logger.debug("[Requester] %s %s → 404 (not found)", method, url)
            return None

        # ── Rate limiting ──────────────────────────────────
        if status == 429:
            logger.warning("[Requester] %s %s → 429 (rate limited)", method, url)
            return None

        # ── Erreurs serveur (déclenchent le retry) ─────────
        if status >= 500:
            raise aiohttp.ClientResponseError(
                resp.request_info,
                resp.history,
                status=status,
                message=f"Server error {status}",
            )

        # ── Autres codes non-2xx ───────────────────────────
        if status >= 400:
            logger.warning("[Requester] %s %s → %d (client error)", method, url, status)
            return None

        # ── Corps texte brut ───────────────────────────────
        if not return_json:
            return await resp.text()

        # ── Corps JSON ─────────────────────────────────────
        content_type = resp.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            # Certaines APIs renvoient du JSON sans déclarer le content-type
            # On tente quand même le décodage ; si ça échoue on renvoie None.
            try:
                return await resp.json(content_type=None)
            except Exception:
                logger.debug(
                    "[Requester] %s %s → content-type inattendu : %s",
                    method,
                    url,
                    content_type,
                )
                return None

        try:
            return await resp.json()
        except Exception as exc:
            logger.warning(
                "[Requester] %s %s — erreur décodage JSON : %s", method, url, exc
            )
            return None

    # ─────────────────────────────────────────────────────
    # Raccourcis
    # ─────────────────────────────────────────────────────
    async def get(self, endpoint: str = "", **kw) -> Optional[Any]:
        return await self.request("GET", endpoint, **kw)

    async def post(self, endpoint: str = "", **kw) -> Optional[Any]:
        return await self.request("POST", endpoint, **kw)

    async def put(self, endpoint: str = "", **kw) -> Optional[Any]:
        return await self.request("PUT", endpoint, **kw)

    async def delete(self, endpoint: str = "", **kw) -> Optional[Any]:
        return await self.request("DELETE", endpoint, **kw)

    async def patch(self, endpoint: str = "", **kw) -> Optional[Any]:
        return await self.request("PATCH", endpoint, **kw)
