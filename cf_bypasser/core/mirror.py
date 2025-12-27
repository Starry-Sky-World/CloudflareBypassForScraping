import asyncio
import logging
import traceback
from typing import Dict, Any, Optional, Tuple, AsyncIterator, Union, Mapping, Callable
from urllib.parse import urlparse, urljoin

from curl_cffi.requests import AsyncSession

from cf_bypasser.core.bypasser import CamoufoxBypasser
from cf_bypasser.utils.config import BrowserConfig
from cf_bypasser.utils.misc import md5_hash


class RequestMirror:
    """Handles dynamic request mirroring with Cloudflare bypass."""

    _HOP_BY_HOP_HEADERS = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
    
    def __init__(self, bypasser: CamoufoxBypasser = None):
        self.bypasser: CamoufoxBypasser = bypasser or CamoufoxBypasser()
        self.session_cache: Dict[str, AsyncSession] = {}  # Cache curl-cffi sessions per hostname
        
    def extract_mirror_headers(self, headers: Dict[str, str]) -> Tuple[Optional[str], Optional[str], bool]:
        """Extract x-hostname, x-proxy, and x-bypass-cache from headers."""
        hostname: Optional[str] = None
        proxy: Optional[str] = None
        bypass_cache: bool = False
        
        # Look for headers (case-insensitive)
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower == 'x-hostname':
                hostname = value
            elif key_lower == 'x-proxy':
                proxy = value
            elif key_lower == 'x-bypass-cache':
                bypass_cache = value.lower() in ('true', '1', 'yes', 'on')
        
        return hostname, proxy, bypass_cache
    
    def strip_mirror_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Remove x-hostname, x-proxy, and x-bypass-cache headers from request."""
        cleaned_headers = {}
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower not in ['x-hostname', 'x-proxy', 'x-bypass-cache']:
                cleaned_headers[key] = value
        return cleaned_headers
    
    def merge_cookies(self, incoming_cookies: str, cf_cookies: Dict[str, str]) -> str:
        """Merge incoming cookies with Cloudflare clearance cookies."""
        try:
            # Parse incoming cookies
            incoming_dict = {}
            if incoming_cookies:
                for cookie in incoming_cookies.split(';'):
                    cookie = cookie.strip()
                    if '=' in cookie:
                        name, value = cookie.split('=', 1)
                        incoming_dict[name.strip()] = value.strip()
            
            # Merge with CF cookies (CF cookies take priority)
            merged_cookies = {**incoming_dict, **cf_cookies}
            
            # Convert back to cookie string
            cookie_pairs = [f"{name}={value}" for name, value in merged_cookies.items()]
            return '; '.join(cookie_pairs)
        except Exception as e:
            logging.error(f"Error merging cookies: {e}")
            # Fallback to CF cookies only
            return '; '.join([f"{name}={value}" for name, value in cf_cookies.items()])
    
    def build_target_url(self, hostname: str, path: str, query_string: str = None) -> str:
        """Build the target URL."""
        if not hostname.startswith(('http://', 'https://')):
            hostname = f"https://{hostname}"
        
        url = urljoin(hostname, path)
        if query_string:
            url += f"?{query_string}"
        
        return url
    
    async def get_session(self, hostname: str, proxy: Optional[str] = None) -> AsyncSession:
        """Get or create a curl-cffi session for the hostname."""
        session_key = f"{hostname}:{proxy or 'no-proxy'}"
        
        if session_key not in self.session_cache:
            proxy_dict = None
            if proxy:
                proxy_dict = {"http": proxy, "https": proxy}
            
            session = AsyncSession(
                impersonate="firefox",  # Use Firefox impersonation
                proxies=proxy_dict,
                timeout=30
            )
            self.session_cache[session_key] = session
        
        return self.session_cache[session_key]
    
    async def mirror_request(
        self,
        method: str,
        path: str,
        query_string: str,
        headers: Dict[str, str],
        body: bytes = None,
        max_retries: int = 2
    ) -> Tuple[int, Dict[str, str], Union[bytes, AsyncIterator[bytes]], bool]:
        """Mirror the request to the target hostname with CF bypass."""
        
        # Extract hostname, proxy, and bypass cache flag
        hostname, proxy, bypass_cache = self.extract_mirror_headers(headers)
        
        if not hostname:
            raise ValueError("x-hostname header is required")

        def should_stream_response(response_headers: Mapping[str, str]) -> bool:
            content_type = (response_headers.get("content-type") or "").lower()
            if content_type.startswith("text/event-stream"):
                return True

            transfer_encoding = (response_headers.get("transfer-encoding") or "").lower()
            if "chunked" in transfer_encoding:
                return True

            return False

        def build_forward_headers(
            response_headers: Mapping[str, str],
            *,
            content_length: Optional[int],
            streaming: bool,
        ) -> Dict[str, str]:
            forwarded: Dict[str, str] = {}
            for key, value in response_headers.items():
                key_lower = key.lower()
                if key_lower in self._HOP_BY_HOP_HEADERS:
                    continue
                if key_lower in {"content-length", "transfer-encoding"}:
                    continue
                if key_lower == "content-encoding":
                    forwarded[key] = "identity"
                    continue
                forwarded[key] = value

            if not streaming and content_length is not None:
                forwarded["content-length"] = str(content_length)

            return forwarded

        async def aclose_response(resp: Any) -> None:
            try:
                aclose = getattr(resp, "aclose", None)
                if callable(aclose):
                    await aclose()
                    return
            except Exception:
                pass
            try:
                close = getattr(resp, "close", None)
                if callable(close):
                    close()
            except Exception:
                pass

        def get_stream_iter_factory(resp: Any) -> Optional[Callable[[], AsyncIterator[bytes]]]:
            aiter_bytes = getattr(resp, "aiter_bytes", None)
            if callable(aiter_bytes):
                return lambda: aiter_bytes()

            aiter_content = getattr(resp, "aiter_content", None)
            if callable(aiter_content):
                def factory() -> AsyncIterator[bytes]:
                    try:
                        return aiter_content()
                    except TypeError:
                        return aiter_content(chunk_size=65536)

                return factory

            iter_content = getattr(resp, "iter_content", None)
            if callable(iter_content):
                import anyio

                def factory() -> AsyncIterator[bytes]:
                    try:
                        iterator = iter_content(chunk_size=65536)
                    except TypeError:
                        iterator = iter_content()

                    async def gen() -> AsyncIterator[bytes]:
                        try:
                            while True:
                                chunk = await anyio.to_thread.run_sync(lambda: next(iterator, b""))
                                if not chunk:
                                    break
                                yield chunk
                        finally:
                            await aclose_response(resp)

                    return gen()

                return factory

            return None

        for attempt in range(max_retries + 1):
            try:
                logging.info(f"Mirroring {method} request to {hostname}{path} (attempt {attempt + 1}/{max_retries + 1})")
                if bypass_cache:
                    logging.info("x-bypass-cache header detected - forcing fresh cookie generation")
                
                # Get or generate Cloudflare cookies
                target_url = self.build_target_url(hostname, "/")  # Use root for cookie generation
                
                # If bypass_cache is True, invalidate existing cache first
                if bypass_cache:
                    parsed_hostname = urlparse(target_url).netloc
                    cache_key = md5_hash(parsed_hostname + (proxy or ""))
                    self.bypasser.cookie_cache.invalidate(cache_key)
                
                cf_data = await self.bypasser.get_or_generate_cookies(target_url, proxy)
                
                if not cf_data:
                    raise Exception("Failed to get Cloudflare clearance cookies")
                
                # Strip mirror headers and prepare request headers
                clean_headers = self.strip_mirror_headers(headers)
                
                # Override User-Agent with the one used for CF bypass
                clean_headers['user-agent'] = cf_data['user_agent']
                clean_headers.pop("host", None)
                
                # Merge cookies
                incoming_cookies = clean_headers.get('Cookie', '')
                merged_cookies = self.merge_cookies(incoming_cookies, cf_data['cookies'])
                clean_headers['Cookie'] = merged_cookies
                
                # Add Firefox-like headers for better impersonation
                firefox_headers = BrowserConfig.get_firefox_headers()
                for key, value in firefox_headers.items():
                    if key.lower() not in [h.lower() for h in clean_headers.keys()]:
                        clean_headers[key] = value
                
                # Build final target URL
                target_url = self.build_target_url(hostname, path, query_string)
                
                # Get session
                session = await self.get_session(hostname, proxy)
                
                # Make the request (prefer streaming response if supported by the client)
                try:
                    response = await session.request(
                        method=method,
                        url=target_url,
                        headers=clean_headers,
                        data=body,
                        allow_redirects=False,  # Let the client handle redirects
                        stream=True,
                    )
                except TypeError:
                    response = await session.request(
                        method=method,
                        url=target_url,
                        headers=clean_headers,
                        data=body,
                        allow_redirects=False,  # Let the client handle redirects
                    )
                
                # Convert response headers to dict
                response_headers = dict(response.headers)
                status_code = response.status_code

                streaming = should_stream_response(response_headers)

                if streaming:
                    stream_factory = get_stream_iter_factory(response)
                    if stream_factory is None:
                        streaming = False

                # Check if we got a 403 Forbidden response
                if status_code == 403 and attempt < max_retries:
                    logging.warning(f"Got 403 Forbidden from {hostname}, invalidating cache and retrying...")
                    await aclose_response(response)
                    
                    # Invalidate the cached cookies for this hostname
                    parsed_hostname = urlparse(target_url).netloc
                    cache_key = md5_hash(parsed_hostname + (proxy or ""))
                    self.bypasser.cookie_cache.invalidate(cache_key)
                    
                    # Wait a bit before retrying
                    await asyncio.sleep(.5)
                    continue

                if streaming:
                    stream_iter = stream_factory()
                    final_headers = build_forward_headers(response_headers, content_length=None, streaming=True)

                    async def body_gen() -> AsyncIterator[bytes]:
                        try:
                            async for chunk in stream_iter:
                                yield chunk
                        finally:
                            await aclose_response(response)

                    logging.info(f"Request to {hostname} completed with status {status_code} (streaming)")
                    return status_code, final_headers, body_gen(), True

                response_content = response.content
                final_headers = build_forward_headers(
                    response_headers,
                    content_length=len(response_content),
                    streaming=False,
                )

                logging.info(f"Request to {hostname} completed with status {status_code}")
                await aclose_response(response)
                return status_code, final_headers, response_content, False
                
            except Exception as e:
                if attempt < max_retries:
                    logging.warning(f"Request attempt {attempt + 1} failed: {e}, retrying...")
                    await asyncio.sleep(.5)
                    continue
                else:
                    logging.error(f"Error mirroring request after {max_retries + 1} attempts: {e}")
                    logging.error(traceback.format_exc())
                    raise
    
    async def cleanup(self):
        """Clean up resources."""
        for session in self.session_cache.values():
            try:
                await session.close()
            except Exception as e:
                logging.error(f"Error closing session: {e}")
        self.session_cache.clear()
        
        if self.bypasser:
            await self.bypasser.cleanup()


class CookieMerger:
    """Utility class for advanced cookie merging logic."""
    
    @staticmethod
    def parse_cookie_string(cookie_string: str) -> Dict[str, str]:
        """Parse cookie string into dictionary."""
        cookies = {}
        if not cookie_string:
            return cookies
        
        for cookie in cookie_string.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                cookies[name.strip()] = value.strip()
        
        return cookies
    
    @staticmethod
    def cookies_to_string(cookies: Dict[str, str]) -> str:
        """Convert cookie dictionary to string."""
        return '; '.join([f"{name}={value}" for name, value in cookies.items()])
    
    @staticmethod
    def merge_with_priority(
        incoming_cookies: Dict[str, str],
        cf_cookies: Dict[str, str],
        priority_cookies: list = None
    ) -> Dict[str, str]:
        """Merge cookies with priority for specific cookie names."""
        if priority_cookies is None:
            priority_cookies = ['cf_clearance', '__cf_bm', '__cfruid']
        
        merged = dict(incoming_cookies)
        
        # Add CF cookies, giving priority to certain cookies
        for name, value in cf_cookies.items():
            if name in priority_cookies or name not in merged:
                merged[name] = value
        
        return merged
    
    @classmethod
    def advanced_merge(
        cls,
        incoming_cookie_string: str,
        cf_cookies: Dict[str, str]
    ) -> str:
        """Advanced cookie merging with Cloudflare priority."""
        incoming_cookies = cls.parse_cookie_string(incoming_cookie_string)
        merged_cookies = cls.merge_with_priority(incoming_cookies, cf_cookies)
        return cls.cookies_to_string(merged_cookies)
