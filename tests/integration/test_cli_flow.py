from pathlib import Path
import subprocess
import sys
import tempfile


def test_cli_single_file():
    corpus_file = Path(__file__).parent.parent / "corpus" / "secrets.js"
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as out_tf:
        out_html = out_tf.name

    cmd = [sys.executable, "-m", "jsxray.cli", "-jf", str(corpus_file), "-o", out_html]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    assert "Scan completed" in res.stdout
    assert "Secrets" in res.stdout
    assert Path(out_html).exists()


def test_cli_directory_scan():
    corpus_dir = Path(__file__).parent.parent / "corpus"
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as out_tf:
        out_html = out_tf.name

    cmd = [sys.executable, "-m", "jsxray.cli", "-jf", str(corpus_dir), "-o", out_html]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    assert "Scan completed" in res.stdout
    assert "API Endpoints" in res.stdout
    assert Path(out_html).exists()


def test_cli_invalid_arguments():
    # Both -uf and -jf should fail
    cmd = [sys.executable, "-m", "jsxray.cli", "-uf", "dummy.txt", "-jf", "dummy.js"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode != 0
