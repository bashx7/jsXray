"""Local file and directory input discovery for JSXRay."""

import os
from pathlib import Path
from typing import List

SUPPORTED_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}


def discover_local_files(target_path: str) -> List[Path]:
    """Discovers JavaScript files from a single file path or directory recursively."""
    path = Path(target_path).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Input file or directory does not exist: {target_path}")

    discovered: List[Path] = []

    if path.is_file():
        # Directly allow single specified file
        discovered.append(path)
    elif path.is_dir():
        for root, _, files in os.walk(path):
            for file in sorted(files):
                file_path = Path(root) / file
                if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                    discovered.append(file_path)
    else:
        raise ValueError(f"Target path is neither a regular file nor a directory: {target_path}")

    return discovered
