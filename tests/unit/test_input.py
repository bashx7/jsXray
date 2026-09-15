from pathlib import Path
import tempfile
import pytest
from jsxray.input.local_files import discover_local_files
from jsxray.input.url_file import parse_url_file


def test_discover_local_files_single_file():
    with tempfile.NamedTemporaryFile(suffix=".js") as tf:
        files = discover_local_files(tf.name)
        assert len(files) == 1
        assert files[0].resolve() == Path(tf.name).resolve()


def test_discover_local_files_directory():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "a.js").write_text("console.log('a');")
        (p / "sub").mkdir()
        (p / "sub" / "b.ts").write_text("console.log('b');")
        (p / "sub" / "c.txt").write_text("ignore me")

        files = discover_local_files(td)
        assert len(files) == 2
        names = [f.name for f in files]
        assert "a.js" in names
        assert "b.ts" in names
        assert "c.txt" not in names


def test_parse_url_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("""
        # comment line
        https://example.com/app.js
        https://example.com/vendor.js
        https://example.com/app.js   # duplicate

        https://example.com/chunk.js
        """)
        tf_name = tf.name

    urls = parse_url_file(tf_name)
    assert len(urls) == 3
    assert "https://example.com/app.js" in urls
    assert "https://example.com/vendor.js" in urls
    assert "https://example.com/chunk.js" in urls
