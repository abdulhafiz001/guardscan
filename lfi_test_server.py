"""Local file page for the GuardScan LFI demo.

It reads a file from this project folder and prints it inside a <pre> tag.
That is the page shape the LFI module looks for. It listens only on this machine.
"""

from html import escape
from pathlib import Path

from flask import Flask, request

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent


@app.get("/view")
def view():
    name = request.args.get("file", "")
    try:
        target = (ROOT / name).resolve()
        target.relative_to(ROOT)
        if target.name.startswith(".env") or not target.is_file():
            raise ValueError("blocked")
        text = target.read_text(encoding="utf-8", errors="replace")
    except Exception:
        text = f"file not found: {name}"
    return f"<html><body><pre>{escape(text)}</pre></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5056)
