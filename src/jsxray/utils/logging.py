"""Terminal logging and output utilities for JSXRay."""

import sys


class Logger:
    @staticmethod
    def banner(version: str = "1.0.0") -> None:
        use_color = sys.stdout.isatty()
        cyan = "\033[96m" if use_color else ""
        white = "\033[97m" if use_color else ""
        bold = "\033[1m" if use_color else ""
        gray = "\033[90m" if use_color else ""
        reset = "\033[0m" if use_color else ""

        banner_text = f"""{cyan}{bold}
       _      {white}{bold}__  __                  
      {cyan}(_)___  {white}\\ \\/ /_ __ __ _ _   _  
      {cyan}| / __|  {white}\\  /| '__/ _` | | | | 
      {cyan}| \\__ \\  {white}/  \\| | | (_| | |_| | 
     {cyan}_/ |___/ {white}/_/\\_\\_|  \\__,_|\\__, | 
    {cyan}|__/                      {white}|___/  
{reset}{gray}  [ JavaScript Security & Secrets Scanner ] - {cyan}v{version}{reset}
{gray}  Created by {white}{bold}Salman{reset}{gray} (aka {cyan}@bashx7{reset}{gray}){reset}
"""
        print(banner_text)

    @staticmethod
    def info(message: str) -> None:
        print(f"[+] {message}")

    @staticmethod
    def warning(message: str) -> None:
        print(f"[!] {message}")

    @staticmethod
    def error(message: str) -> None:
        print(f"[-] {message}", file=sys.stderr)

    @staticmethod
    def success(message: str) -> None:
        print(f"✓ {message}")

    @staticmethod
    def print_summary(stats_dict: dict) -> None:
        print("\nRESULTS")
        print("────────────────────────────")
        mappings = [
            ("API Endpoints", "api_endpoints"),
            ("URLs / Routes", "url_routes"),
            ("Parameters", "parameters"),
            ("Subdomains / Hosts", "api_hosts"),
            ("Secrets", "secrets"),
            ("Credentials", "credentials"),
            ("Authentication", "authentications"),
            ("GraphQL", "graphql_endpoints"),
            ("WebSockets", "websockets"),
            ("SSE Endpoints", "sse_endpoints"),
            ("Internal Hosts", "internal_hosts"),
            ("Dangerous JS", "dangerous_js"),
            ("Technologies", "technologies"),
            ("Source Maps", "source_maps"),
            ("Dynamic Imports", "dynamic_imports"),
            ("Security Candidates", "security_candidates"),
            ("Static Resources", "static_resources"),
            ("External URLs", "external_urls"),
        ]
        for label, key in mappings:
            count = stats_dict.get(key, 0)
            if count > 0 or key in ["api_endpoints", "url_routes", "parameters", "api_hosts", "secrets", "technologies"]:
                print(f"{label:<18} {count:>6}")
        print("────────────────────────────")
