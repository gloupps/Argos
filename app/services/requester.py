# app/services/requester.py
import aiohttp
import asyncio
import logging
from typing import Optional, Any, Dict, Tuple

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
        allow_redirects: bool = True,
    ) -> Optional[Any]:
        """
        Effectue une requête HTTP avec retry exponentiel.

        Paramètres
        ──────────
        method          : verbe HTTP ("GET", "POST", …)
        endpoint        : chemin ajouté à base_url, OU URL absolue complète
        params          : query string parameters
        json            : corps JSON (sérialisation auto)
        data            : corps brut (form data, bytes…)
        headers         : headers additionnels, fusionnés avec self.headers
        auth            : tuple (login, password) pour HTTP Basic Auth
        retries         : nombre de tentatives avant abandon
        return_json     : si False, retourne le texte brut de la réponse
        allow_redirects : si False, une 3xx n'est pas suivie automatiquement.
                          Utile pour détecter une redirection vers une page de
                          login (auth refusée) qui renverrait sinon du HTML
                          avec un statut 200 après avoir été suivie silencieusement.

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
                            allow_redirects=allow_redirects,
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

        # ── Redirection non suivie (allow_redirects=False) ─
        # Typiquement une session/API-token refusé qui renvoie vers une
        # page de login : mieux vaut le signaler explicitement plutôt que
        # de laisser aiohttp suivre silencieusement et retomber sur du HTML.
        if 300 <= status < 400:
            location = resp.headers.get("Location", "")
            logger.warning(
                "[Requester] %s %s → %d redirection vers %s "
                "(authentification probablement refusée ou URL incorrecte)",
                method, url, status, location,
            )
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
                # Content-type inattendu ET corps non-JSON (ex. text/html) :
                # généralement une page de login, une erreur de proxy, ou le
                # mauvais port/URL (ex. port web Splunk au lieu du port mgmt).
                # Le status HTTP peut être 2xx même si la requête n'a pas
                # abouti côté applicatif (dispatch effectué mais réponse non
                # exploitable) — on le rend visible via un warning avec un
                # extrait du corps pour permettre le diagnostic.
                snippet = ""
                try:
                    body = await resp.text()
                    snippet = body[:200].replace("\n", " ").strip()
                except Exception:
                    pass
                logger.warning(
                    "[Requester] %s %s → %d, content-type inattendu : %s%s",
                    method,
                    url,
                    status,
                    content_type or "(absent)",
                    f" — corps : {snippet!r}" if snippet else "",
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

    # ─────────────────────────────────────────────────────
    # Login par formulaire → cookie de session
    # ─────────────────────────────────────────────────────
    async def login_form(
        self,
        endpoint: str,
        data: dict,
        headers: Optional[dict] = None,
    ) -> Optional[Dict[str, str]]:
        """
        POST de connexion classique (form-urlencoded) qui renvoie les
        cookies de session de la réponse, sans suivre les redirections.

        Utilisé pour l'auth par cookie quand l'API cible n'accepte pas de
        header Authorization (ex. Splunk Web sur le port 8000, qui protège
        son proxy REST par un cookie de session obtenu via
        POST /en-US/account/login, contrairement à splunkd sur le port 8089
        qui accepte Bearer/Basic directement).

        Retour
        ──────
        dict {cookie_name: value} si le login a produit au moins un cookie,
        None sinon.
        """
        url = endpoint if endpoint.startswith("http") else f"{self.base_url}{endpoint}"
        merged_headers = {**self.headers, **(headers or {})}
        connector = aiohttp.TCPConnector(ssl=False)

        try:
            async with aiohttp.ClientSession(
                timeout=self.timeout, headers=merged_headers, connector=connector
            ) as session:
                async with session.post(
                    url, data=data, allow_redirects=False
                ) as resp:
                    # Un login réussi renvoie généralement 200 (JSON avec
                    # sessionKey) ou 303 (redirection vers l'app) — les deux
                    # cas nous intéressent tant qu'un cookie est posé.
                    if resp.status not in (200, 302, 303):
                        logger.warning(
                            "[Requester] login %s → %d (échec probable des identifiants)",
                            url, resp.status,
                        )
                        return None

                    cookies = {
                        key: morsel.value for key, morsel in resp.cookies.items()
                    }
                    if not cookies:
                        logger.warning(
                            "[Requester] login %s → %d mais aucun cookie de session reçu",
                            url, resp.status,
                        )
                        return None
                    return cookies

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.warning("[Requester] login %s — échec : %s", url, exc)
            return None
