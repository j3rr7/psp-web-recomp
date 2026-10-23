"""Static file server with HTTP Range support (needed to stream game data).

Usage: serve.py <directory> [port] [--mount /url/prefix=/host/dir ...]

A file with an up-to-date ".gz" sibling is sent gzip-compressed to clients
that accept it (serve.sh prepares those for the big build outputs). Directory
listings are disabled, since the server may be reachable through a tunnel.
"""
import http.server
import os
import re
import sys
from functools import partial

RANGE = re.compile(r"bytes=(\d*)-(\d*)$")


class Handler(http.server.SimpleHTTPRequestHandler):
    mounts = {}

    def translate_path(self, path):
        clean = path.split("?", 1)[0].split("#", 1)[0]
        for prefix, target in self.mounts.items():
            if clean.startswith(prefix + "/"):
                rel = clean[len(prefix) + 1:]
                parts = [p for p in http.server.urllib.parse.unquote(rel).split("/") if p not in ("", ".", "..")]
                return os.path.join(target, *parts)
        return super().translate_path(path)

    def list_directory(self, path):
        self.send_error(404, "File not found")
        return None

    def send_compressed(self, path):
        if self.headers.get("Range") or "gzip" not in self.headers.get("Accept-Encoding", ""):
            return None
        packed = path + ".gz"
        if not os.path.isfile(path) or not os.path.isfile(packed):
            return None
        if int(os.path.getmtime(packed)) < int(os.path.getmtime(path)):
            return None
        f = open(packed, "rb")
        self.send_response(200)
        self.send_header("Content-Type", self.guess_type(path))
        self.send_header("Content-Encoding", "gzip")
        self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(os.path.getsize(packed)))
        self.end_headers()
        return f

    def end_headers(self):
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Cache-Control", "no-cache")
        # Cross-origin isolation: lets the page use SharedArrayBuffer, which the
        # GE thread needs.
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        super().end_headers()

    def send_head(self):
        match = RANGE.match(self.headers.get("Range", ""))
        path = self.translate_path(self.path)
        packed = self.send_compressed(path)
        if packed is not None:
            return packed
        if not match or not os.path.isfile(path):
            return super().send_head()
        size = os.path.getsize(path)
        start_text, end_text = match.groups()
        if start_text == "":
            start, end = max(0, size - int(end_text)), size - 1
        else:
            start = int(start_text)
            end = min(int(end_text), size - 1) if end_text else size - 1
        if start >= size or start > end:
            self.send_error(416, "Requested Range Not Satisfiable")
            return None
        f = open(path, "rb")
        f.seek(start)
        self.send_response(206)
        self.send_header("Content-Type", self.guess_type(path))
        self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.send_header("Content-Length", str(end - start + 1))
        self.end_headers()
        self._range_left = end - start + 1
        return f

    def copyfile(self, source, outputfile):
        left = getattr(self, "_range_left", None)
        if left is None:
            return super().copyfile(source, outputfile)
        while left > 0:
            chunk = source.read(min(left, 1 << 20))
            if not chunk:
                break
            outputfile.write(chunk)
            left -= len(chunk)


def main():
    args = sys.argv[1:]
    mounts = {}
    while "--mount" in args:
        i = args.index("--mount")
        prefix, target = args[i + 1].split("=", 1)
        mounts[prefix.rstrip("/")] = os.path.abspath(target)
        del args[i:i + 2]
    directory = args[0]
    port = int(args[1]) if len(args) > 1 else 8613
    Handler.mounts = mounts
    handler = partial(Handler, directory=directory)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
    print(f"http://0.0.0.0:{port}/", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
