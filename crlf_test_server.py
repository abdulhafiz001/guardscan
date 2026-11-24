"""Local header page for the GuardScan CRLF demo.

It prints the value parameter and the injected header line the CRLF
module looks for. It listens only on this machine.
"""

from html import escape

from flask import Flask, request

app = Flask(__name__)


@app.get("/header")
def header():
    value = request.args.get("value", "")
    body = f"CRLF injection. Injected headers include Set-Cookie. Received: {value}"
    return f"<html><body><p>{escape(body)}</p></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5058)
