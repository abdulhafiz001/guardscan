"""Local redirect page for the GuardScan Open Redirect demo.

It prints the next parameter with the word Redirecting. It does not send
the browser anywhere. It listens only on this machine.
"""

from html import escape

from flask import Flask, request

app = Flask(__name__)


@app.get("/out")
def out():
    dest = request.args.get("next", "")
    body = f"Redirecting to destination: {dest}"
    return f"<html><body><p>{escape(body)}</p></body></html>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5057)
