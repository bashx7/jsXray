from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time


class MockServer:
    def __init__(self, directory: str):
        self.directory = directory
        handler = lambda *args, **kwargs: SimpleHTTPRequestHandler(*args, directory=self.directory, **kwargs)
        self.httpd = HTTPServer(("127.0.0.1", 0), handler)
        self.port = self.httpd.server_port
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()


def test_url_input_mode_end_to_end():
    corpus_dir = Path(__file__).parent.parent / "corpus"
    server = MockServer(str(corpus_dir))
    server.start()
    time.sleep(0.2)

    try:
        url1 = f"http://127.0.0.1:{server.port}/minified.js"
        url2 = f"http://127.0.0.1:{server.port}/secrets.js"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            tf.write(f"{url1}\n{url2}\n")
            url_file = tf.name

        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as out_tf:
            out_html = out_tf.name

        cmd = [sys.executable, "-m", "jsxray.cli", "-uf", url_file, "-o", out_html]
        res = subprocess.run(cmd, capture_output=True, text=True)
        assert res.returncode == 0
        assert "Downloaded" in res.stdout
        assert "Scan completed" in res.stdout
        assert Path(out_html).exists()
        assert Path(out_html).stat().st_size > 500
    finally:
        server.stop()
