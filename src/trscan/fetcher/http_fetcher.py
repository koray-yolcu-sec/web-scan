import asyncio
import random
from urllib.parse import urlparse

import httpx


class HTTPFetcher:
    """HTTP isteklerini yapan ve verileri toplayan fetcher sınıfı"""

    def __init__(
        self,
        timeout: int = 10,
        max_requests: int = 15,
        polite_mode: bool = True,
        user_agent: str = "TRScan/1.0 (Legal Passive Security Scanner; https://github.com/trscan/trscan)",
    ):
        self.timeout = timeout
        self.max_requests = max_requests
        self.polite_mode = polite_mode
        self.user_agent = user_agent
        self.request_count = 0
        self.headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    async def _sleep_polite(self):
        """Polite mod için rastgele bekleme"""
        if self.polite_mode:
            sleep_time = random.uniform(0.5, 1.5)
            await asyncio.sleep(sleep_time)

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        url: str,
        follow_redirects: bool = True,
        method: str = "GET",
    ) -> tuple[int, dict, str, str | None] | None:
        """
        HTTP isteği yapar

        Returns:
            (status_code, headers, text, final_url) tuple veya None (hata durumunda)
        """
        try:
            if self.request_count >= self.max_requests:
                return None

            self.request_count += 1

            response = await client.request(
                method=method,
                url=url,
                headers=self.headers,
                follow_redirects=follow_redirects,
                timeout=self.timeout,
            )

            await self._sleep_polite()

            return (response.status_code, dict(response.headers), response.text, str(response.url))

        except httpx.TimeoutException:
            return None
        except httpx.TooManyRedirects:
            return None
        except httpx.ConnectError:
            return None
        except Exception:
            return None

    async def fetch_main_page(self, url: str) -> dict | None:
        """
        Ana sayfayı çeker ve temel bilgileri toplar

        Returns:
            {
                'status_code': int,
                'headers': Dict,
                'content': str,
                'final_url': str,
                'cookies': List[Dict],
                'redirect_chain': List[str],
                'https_enabled': bool,
                'http_accessible': bool,
            }
        """
        result = {
            "status_code": None,
            "headers": {},
            "content": "",
            "final_url": url,
            "cookies": [],
            "redirect_chain": [],
            "https_enabled": False,
            "http_accessible": False,
        }

        parsed_url = urlparse(url)
        is_https = parsed_url.scheme == "https"
        result["https_enabled"] = is_https

        # HTTPS kontrolü
        if is_https:
            http_url = parsed_url._replace(scheme="http").geturl()

            async with httpx.AsyncClient(verify=True) as client:
                # HTTPS isteği
                https_result = await self._make_request(client, url, follow_redirects=True)
                if https_result:
                    status, headers, content, final_url = https_result
                    result["status_code"] = status
                    result["headers"] = headers
                    result["content"] = content
                    result["final_url"] = final_url
                    result["cookies"] = self._extract_cookies(headers)

                # HTTP erişilebilirlik kontrolü (çok kısa)
                try:
                    http_response = await client.head(
                        http_url, headers=self.headers, follow_redirects=False, timeout=5
                    )
                    result["http_accessible"] = http_response.status_code < 400
                except:
                    result["http_accessible"] = False
        else:
            # HTTP direkt isteği
            async with httpx.AsyncClient(verify=False) as client:
                http_result = await self._make_request(client, url, follow_redirects=True)
                if http_result:
                    status, headers, content, final_url = http_result
                    result["status_code"] = status
                    result["headers"] = headers
                    result["content"] = content
                    result["final_url"] = final_url
                    result["cookies"] = self._extract_cookies(headers)
                    result["http_accessible"] = True

        return result

    async def fetch_additional_paths(
        self, base_url: str, paths: list[str] = None
    ) -> dict[str, dict]:
        """
        Ek path'leri kontrol et (/robots.txt, /sitemap.xml vb.)

        Returns:
            {
                '/robots.txt': {'status': int, 'content': str, 'exists': bool},
                '/sitemap.xml': {'status': int, 'content': str, 'exists': bool},
                ...
            }
        """
        if paths is None:
            paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/login", "/admin"]

        results = {}

        parsed_url = urlparse(base_url)
        base_domain = parsed_url.scheme + "://" + parsed_url.netloc

        async with httpx.AsyncClient(verify=True) as client:
            for path in paths:
                full_url = base_domain + path

                result = await self._make_request(
                    client, full_url, follow_redirects=False, method="GET"
                )

                if result:
                    status, headers, content, final_url = result
                    results[path] = {
                        "status": status,
                        "content": content,
                        "exists": 200 <= status < 300,
                    }
                else:
                    results[path] = {"status": None, "content": "", "exists": False}

        return results

    def _extract_cookies(self, headers: dict) -> list[dict]:
        """Set-Cookie header'larından cookie bilgilerini çıkarır"""
        cookies = []
        set_cookie_headers = headers.get("set-cookie", "")

        if isinstance(set_cookie_headers, str):
            set_cookie_headers = [set_cookie_headers]

        for cookie_str in set_cookie_headers:
            if not cookie_str:
                continue

            cookie_info = self._parse_cookie(cookie_str)
            if cookie_info:
                cookies.append(cookie_info)

        return cookies

    def _parse_cookie(self, cookie_str: str) -> dict | None:
        """Cookie string'ini parçalar"""
        try:
            parts = cookie_str.split(";")
            name_value = parts[0].strip()

            if "=" not in name_value:
                return None

            name, value = name_value.split("=", 1)

            cookie = {
                "name": name.strip(),
                "value": self._mask_value(value.strip()),
                "secure": False,
                "httponly": False,
                "samesite": None,
                "max_age": None,
                "domain": "",
                "path": "",
            }

            for part in parts[1:]:
                part = part.strip().lower()

                if "secure" in part:
                    cookie["secure"] = True
                elif "httponly" in part:
                    cookie["httponly"] = True
                elif "samesite=" in part:
                    cookie["samesite"] = part.split("=", 1)[1].strip()
                elif "max-age=" in part:
                    try:
                        cookie["max_age"] = int(part.split("=", 1)[1].strip())
                    except:
                        pass
                elif "domain=" in part:
                    cookie["domain"] = part.split("=", 1)[1].strip()
                elif "path=" in part:
                    cookie["path"] = part.split("=", 1)[1].strip()

            return cookie

        except Exception:
            return None

    def _mask_value(self, value: str) -> str:
        """Cookie değerini maskele (gizlilik için)"""
        if len(value) <= 4:
            return "****"
        return value[:2] + "****" + value[-2:]

    async def fetch_dns_records(self, domain: str) -> dict:
        """
        DNS kayıtlarını çeker (dnspython kullanılacak)

        Returns:
            {
                'spf': List[str],
                'dkim': List[str],
                'dmarc': List[str],
                'caa': List[str],
                'mx': List[str],
            }
        """
        # DNS çekebilmek için dnspython kullanacağız
        # Bu metod daha sonra analyzers'da çağrılacak
        return {
            "spf": [],
            "dkim": [],
            "dmarc": [],
            "caa": [],
            "mx": [],
        }
