"""Local webhook receiver for the GuardScan Fintech Gateway demo.

It accepts every POST and returns HTTP 200. That is the missing-signature
behavior the gateway module is meant to flag. It listens only on this machine.
"""

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post("/webhook")
def webhook():
    signature = request.headers.get("x-paystack-signature")
    print("x-paystack-signature:", signature)
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055)
