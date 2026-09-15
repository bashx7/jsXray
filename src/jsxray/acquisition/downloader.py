"""Concurrent HTTP/HTTPS JavaScript downloader for JSXRay."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from jsxray.acquisition.encoding import decode_bytes
from jsxray.acquisition.validator import validate_javascript_content
from jsxray.models.source import JavaScriptSource


class Downloader:
    def __init__(
        self,
        timeout: int = 10,
        max_size_bytes: int = 50 * 1024 * 1024,  # 50MB
        verify_ssl: bool = True,
        max_workers: int = 10,
        user_agent: str = "Mozilla/5.0 (compatible; JSXRay/1.0)",
    ):
        self.timeout = timeout
        self.max_size_bytes = max_size_bytes
        self.verify_ssl = verify_ssl
        self.max_workers = max_workers
        self.user_agent = user_agent

        self.session = requests.Session()
        retries = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=max_workers, pool_maxsize=max_workers)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "*/*",
        })

    def download_url(self, url: str) -> JavaScriptSource:
        """Downloads and validates a single JavaScript URL with strict connection and read timeouts."""
        source = JavaScriptSource(
            identifier=url,
            original_code="",
            url=url,
            is_valid_js=False,
        )
        try:
            # (connect_timeout, read_timeout)
            connect_timeout = min(5, self.timeout)
            read_timeout = self.timeout

            response = self.session.get(
                url,
                timeout=(connect_timeout, read_timeout),
                verify=self.verify_ssl,
                stream=True,
                allow_redirects=True,
            )
            if response.status_code != 200:
                source.errors.append(f"HTTP {response.status_code} {response.reason}")
                return source

            content_type = response.headers.get("Content-Type", "")
            declared_charset = response.encoding or ""

            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > self.max_size_bytes:
                source.errors.append(f"Response exceeds maximum size limit ({self.max_size_bytes} bytes)")
                return source

            raw_bytes = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    raw_bytes.extend(chunk)
                if len(raw_bytes) > self.max_size_bytes:
                    source.errors.append(f"Downloaded content exceeded size limit of {self.max_size_bytes} bytes")
                    return source

            code, encoding = decode_bytes(bytes(raw_bytes), declared_charset=declared_charset)
            source.original_code = code
            source.encoding = encoding
            source.size_bytes = len(raw_bytes)

            is_valid, validation_err = validate_javascript_content(code, content_type=content_type, url=url)
            if is_valid:
                source.is_valid_js = True
            else:
                source.is_valid_js = False
                source.warnings.append(f"Validation warning: {validation_err}")

            return source

        except requests.exceptions.SSLError as e:
            source.errors.append(f"SSL/TLS verification failed: {e}")
            return source
        except requests.exceptions.Timeout:
            source.errors.append("Connection timed out")
            return source
        except requests.exceptions.RequestException as e:
            source.errors.append(f"Network request failed: {e}")
            return source
        except Exception as e:
            source.errors.append(f"Unexpected download error: {e}")
            return source

    def download_all(
        self,
        urls: List[str],
        progress_callback: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> List[JavaScriptSource]:
        """Downloads multiple URLs concurrently."""
        results: List[JavaScriptSource] = []
        if not urls:
            return results

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(urls))) as executor:
            future_to_url = {executor.submit(self.download_url, url): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    source = future.result()
                    results.append(source)
                    if progress_callback:
                        progress_callback(url, source.is_valid_js, source.errors[0] if source.errors else None)
                except Exception as e:
                    failed_source = JavaScriptSource(
                        identifier=url,
                        original_code="",
                        url=url,
                        is_valid_js=False,
                        errors=[str(e)],
                    )
                    results.append(failed_source)
                    if progress_callback:
                        progress_callback(url, False, str(e))

        return results
