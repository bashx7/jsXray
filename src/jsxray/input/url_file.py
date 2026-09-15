"""URL file input parser for JSXRay."""

from pathlib import Path
from typing import List
from jsxray.utils.helpers import normalize_url


def parse_url_file(file_path: str) -> List[str]:
    """Reads a file containing one URL per line, stripping comments, empty lines, and duplicates."""
    path = Path(file_path).expanduser().resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"URL file does not exist or is not a file: {file_path}")

    urls: List[str] = []
    seen = set()

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_no_comment = line.split("#", 1)[0].strip()
            if not line_no_comment:
                continue
            # Ignore prose, sentences, markdown text
            if any(c in line_no_comment for c in (" ", "\t", "\r", "\n")):
                continue
            # Must look like a URL: start with http://, https://, //, or host.tld/path
            if line_no_comment.startswith("//"):
                line_no_comment = f"https:{line_no_comment}"
            elif not (line_no_comment.startswith("http://") or line_no_comment.startswith("https://")):
                if "/" in line_no_comment and "." in line_no_comment.split("/")[0]:
                    line_no_comment = f"https://{line_no_comment}"
                elif "." in line_no_comment:
                    line_no_comment = f"https://{line_no_comment}"
                else:
                    continue
            normalized = normalize_url(line_no_comment)
            if normalized and normalized not in seen:
                seen.add(normalized)
                urls.append(line_no_comment)

    return urls
