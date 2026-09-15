"""URL, application route, static resource, and external link analyzer for JSXRay."""

import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from tree_sitter import Node
from jsxray.analyzers.base import BaseAnalyzer
from jsxray.javascript.ast_utils import (
    extract_string_literal,
    get_node_line_col,
    get_node_snippet,
    get_node_text,
    walk_tree,
)
from jsxray.javascript.reconstruction import StaticReconstructor
from jsxray.models.finding import Confidence, Finding, FindingStatus, FindingType
from jsxray.models.source import JavaScriptSource


class UrlAnalyzer(BaseAnalyzer):
    """Accurately classifies extracted paths into Application Routes, API URLs, Static Resources, and External URLs."""

    @property
    def name(self) -> str:
        return "urls"

    URL_REGEX = re.compile(r"^https?://[a-zA-Z0-9_\-\.:]+(?:/[^\s\"'<>`]*)?$")
    ROUTE_REGEX = re.compile(r"^/[a-zA-Z0-9_\-\.~%!$&'()*+,;=:@{}/]{1,500}$")

    # Sensitive/interesting route keywords for tagging
    TAG_PATTERNS = {
        "admin": re.compile(r"/(admin|manage|dashboard|super|root|control)", re.I),
        "auth": re.compile(r"/(login|signin|sign-in|signup|register|logout|auth|oauth|token|password|reset|verify)", re.I),
        "debug": re.compile(r"/(debug|trace|test|swagger|doc|docs|graphiql|actuator|metrics|health|status)", re.I),
        "file-operation": re.compile(r"/(upload|download|file|files|attachment|export|import|backup)", re.I),
        "object-id": re.compile(r"/\{[a-zA-Z0-9_]+\}|/[0-9]+|/[a-f0-9]{8,}", re.I),
        "internal": re.compile(r"/(internal|private|sys|system|core|backend|rpc)", re.I),
        "redirect": re.compile(r"/(redirect|goto|return|forward|callback)", re.I),
        "api": re.compile(r"/(api|v[0-9]+|graphql|rest|rpc|service|endpoint)", re.I),
    }

    STATIC_EXTENSIONS = (
        ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
        ".css", ".scss", ".sass", ".less",
        ".map", ".wasm",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".avif", ".bmp",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp3", ".mp4", ".wav", ".ogg", ".webm",
        ".pdf", ".zip", ".tar.gz", ".gz",
    )

    STATIC_PATH_INDICATORS = (
        "/cdn/", "/assets/", "/static/", "/chunks/", "/node_modules/",
        "/dist/", "/build/", "/public/", "/fonts/", "/images/",
        "/icons/", "/media/", "/styles/", "/vendor/", "/_next/static/",
        "/_nuxt/", "/wp-content/", "/wp-includes/",
    )

    STANDARD_NAMESPACE_DOMAINS = (
        "www.w3.org", "w3.org", "schema.org", "xmlns.com",
    )

    IGNORED_STRINGS = {
        "/", "//", "/\n", "/*", "*/", "use strict", "production", "development",
        "utf-8", "text/html", "application/json", "text/plain", "GET", "POST",
    }

    @classmethod
    def classify_target(cls, val: str) -> Tuple[str, str, bool]:
        """
        Classifies string into:
        (Category, SubType, is_actionable_route)
        Categories:
          - "Application Route"
          - "API Request URL"
          - "Static Resource"
          - "External URL"
          - "Browser / Standard"
        """
        clean = val.split("?")[0].split("#")[0].strip().lower()

        # 1. Standard / Browser XML/SVG namespaces
        if any(ns in clean for ns in cls.STANDARD_NAMESPACE_DOMAINS):
            return "Browser / Standard", "namespace", False

        # 2. Static resource files and bundle assets
        if clean.endswith(cls.STATIC_EXTENSIONS):
            ext = clean.split(".")[-1]
            return "Static Resource", ext, False

        if any(p in clean for p in cls.STATIC_PATH_INDICATORS):
            return "Static Resource", "asset-path", False

        # 3. Full HTTP/HTTPS URLs
        if val.startswith("http://") or val.startswith("https://"):
            try:
                parsed = urlparse(val)
                hostname = parsed.hostname or ""
                path = parsed.path.lower()
                if any(ns in hostname for ns in cls.STANDARD_NAMESPACE_DOMAINS):
                    return "Browser / Standard", "namespace", False
                if "api" in hostname or "api" in path or "v1" in path or "v2" in path or "graphql" in path or "service" in path:
                    return "API Request URL", "api-url", True
                return "External URL", "external-link", False
            except Exception:
                return "External URL", "external-link", False

        # 4. Relative paths / Application Routes
        if clean.startswith("/api/") or clean.startswith("/v1/") or clean.startswith("/v2/") or clean.startswith("/graphql"):
            return "API Request URL", "api-endpoint", True

        return "Application Route", "application-route", True

    def analyze(self, source: JavaScriptSource, reconstructor: StaticReconstructor) -> List[Finding]:
        findings: List[Finding] = []
        if not source.ast_root:
            return findings

        code_bytes = source.effective_code.encode("utf-8", errors="replace")
        code_lines = source.effective_code.splitlines()

        for node in walk_tree(source.ast_root):
            val: str = ""
            if node.type in ("string", "string_fragment", "template_string"):
                val = extract_string_literal(node, code_bytes) or ""
            elif node.type == "template_string":
                resolved, _, _ = reconstructor.resolve_expression(node)
                val = resolved or ""

            if not val or val in self.IGNORED_STRINGS or len(val) < 2 or len(val) > 1000:
                continue

            val = val.strip()

            is_url = bool(self.URL_REGEX.match(val))
            is_route = bool(self.ROUTE_REGEX.match(val))

            if is_url or is_route:
                category, sub_type, is_actionable = self.classify_target(val)

                # Determine FindingType
                if category == "Static Resource":
                    finding_type = FindingType.STATIC_RESOURCE
                    confidence = Confidence.MEDIUM
                elif category in ("External URL", "Browser / Standard"):
                    finding_type = FindingType.EXTERNAL_URL
                    confidence = Confidence.LOW if category == "Browser / Standard" else Confidence.MEDIUM
                else:
                    # Application Route or API Request URL
                    finding_type = FindingType.URL_ROUTE
                    confidence = Confidence.HIGH if is_url else Confidence.MEDIUM

                tags = [sub_type]
                if category == "Static Resource":
                    tags.append("static-asset")
                elif category == "Browser / Standard":
                    tags.append("browser-standard")
                elif category == "External URL":
                    tags.append("external-link")
                else:
                    tags.append("application-route" if is_route else "api-url")

                for tag_name, pattern in self.TAG_PATTERNS.items():
                    if pattern.search(val):
                        tags.append(tag_name)

                line, col = get_node_line_col(node)
                snippet = get_node_snippet(node, code_lines, code_bytes=code_bytes)

                findings.append(
                    Finding(
                        type=finding_type,
                        value=val,
                        normalized_value=val,
                        confidence=confidence,
                        status=FindingStatus.DETECTED,
                        source_file=source.file_path,
                        source_url=source.url,
                        line=line,
                        column=col,
                        snippet=snippet,
                        original_source=get_node_text(node, code_bytes).strip(),
                        reconstructed_source=val,
                        discovery_method="AST analysis",
                        tags=tags,
                        extra_data={
                            "category": category,
                            "sub_type": sub_type,
                            "is_absolute": is_url,
                            "is_actionable": is_actionable,
                            "is_static_asset": (category == "Static Resource"),
                        },
                    )
                )

        return findings
