"""Command-line interface entry point for JSXRay."""

import argparse
import sys
import warnings
from pathlib import Path

# Suppress library warnings for clean CLI output
warnings.filterwarnings("ignore")

from jsxray import __version__
from jsxray.engine import JSXRayEngine
from jsxray.utils.logging import Logger


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jsxray",
        description="JSXRay — Lightweight JavaScript Security Intelligence CLI for penetration testers",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-uf",
        "--url-file",
        dest="url_file",
        metavar="FILE",
        help="File containing JavaScript URLs (one per line)",
    )
    group.add_argument(
        "-jf",
        "--js-file",
        dest="js_file",
        metavar="PATH",
        help="JavaScript file or directory to analyze recursively",
    )
    parser.add_argument(
        "-d",
        "--domain",
        dest="domain",
        metavar="DOMAIN",
        default=None,
        help="Target base domain for subdomain scoping (e.g. example.com). Inferred automatically from URLs in -uf mode.",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        metavar="REPORT",
        default="jsxray-results.html",
        help="Output HTML report path (default: jsxray-results.html)",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--concurrency",
        dest="concurrency",
        type=int,
        default=10,
        help="Concurrent download threads (default: 10)",
    )
    parser.add_argument(
        "--insecure",
        dest="insecure",
        action="store_true",
        help="Disable SSL/TLS certificate verification",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"JSXRay {__version__}",
    )
    return parser


def main() -> int:
    Logger.banner(__version__)
    parser = create_parser()
    try:
        args = parser.parse_args()
    except SystemExit as e:
        return e.code


    # Validate input paths
    if args.url_file:
        p = Path(args.url_file).expanduser()
        if not p.exists() or not p.is_file():
            Logger.error(f"URL file does not exist or is not a file: {args.url_file}")
            return 1

    if args.js_file:
        p = Path(args.js_file).expanduser()
        if not p.exists():
            Logger.error(f"JavaScript file or directory does not exist: {args.js_file}")
            return 1

    try:
        engine = JSXRayEngine(
            url_file=args.url_file,
            js_path=args.js_file,
            output_file=args.output,
            target_domain=args.domain,
            downloader_workers=args.concurrency,
            request_timeout=args.timeout,
            verify_ssl=not args.insecure,
        )

        scan_result = engine.run()

        # Print concise statistics
        stats = scan_result.statistics.to_dict()
        Logger.print_summary(stats)

        Logger.success("Scan completed")
        print(f"\nReport: {args.output}\n")
        return 0

    except KeyboardInterrupt:
        Logger.warning("\nScan interrupted by user.")
        return 130
    except Exception as e:
        Logger.error(f"Execution error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
