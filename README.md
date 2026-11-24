# GuardScan

GuardScan is a web and API vulnerability scanner with a dashboard and a command-line tool. It checks seven issues: BOLA/IDOR, payment-webhook signatures, SQL injection, cross-site scripting, local file inclusion, open redirect, and CRLF injection.

Scan only systems you are allowed to test. Use a practice site, or the local pages in this repository. Do not point it at a live payment gateway or any system you do not own.

## What each module checks

| Module | What it looks for |
|---|---|
| BOLA / IDOR | The same URL is requested with Token A, Token B, and no token. A normal HTTP 200 for the second user is High (CVSS 7.5). A 200 with no token is Critical (CVSS 9.1). |
| Fintech Gateway | Six webhook messages: missing or forged Paystack, Flutterwave, and Monnify signatures, plus a changed amount or currency. A success response, usually HTTP 200, is Critical (CVSS 9.3) or High (CVSS 8.2). |
| SQL Injection | Payloads are added to the end of the URL. Five of the lines in `payloads/sqli.txt` are reported as Critical (CVSS 9.8). |
| XSS | Payloads are opened in Chrome. An alert, or the payload appearing in the page, is High (CVSS 7.1). |
| LFI | Payloads are opened in Chrome. A hit is High (CVSS 7.5) only when a `<pre>` block holds file text and does not say `file not found` or `no file specified`. |
| Open Redirect | Payloads are opened in Chrome. A redirect, or a page that says it is redirecting to that address, is Medium (CVSS 6.1). |
| CRLF Injection | Eight header payloads are opened in Chrome. Page text that shows `Set-Cookie` with a header-injection phrase is Medium (CVSS 6.5). |

SQL injection, XSS, LFI, open redirect, and CRLF each open Chrome. Set threads to **2** for those modules. BOLA and the gateway do not open Chrome, so threads can stay at **5**.

Paste BOLA tokens as the raw JWT (`eyJ...`). GuardScan adds `Bearer` itself.

## Run the dashboard

Requirements: Python 3.11 or newer, and Google Chrome for the five browser modules. On Python 3.13 and newer, GuardScan skips Eventlet and uses normal threads.

```text
python app.py
```

Open http://127.0.0.1:5000 and leave that window open. Do not start `python app.py` again, or port 5000 will already be in use.

In Scan Studio, pick a module, paste one target, set the threads, and launch the audit. Reports are written to `reports/` as PDF, HTML, and JSON.

## Local practice pages

These servers listen only on this machine. Stop the previous one with Ctrl+C before starting the next. GuardScan stays running.

```text
python webhook_test_server.py
```

Gateway target: `http://127.0.0.1:5055/webhook`

```text
python lfi_test_server.py
```

LFI target: `http://127.0.0.1:5056/view?file=`

```text
python or_test_server.py
```

Open redirect target: `http://127.0.0.1:5057/out?next=`

```text
python crlf_test_server.py
```

CRLF target: `http://127.0.0.1:5058/header?value=`

Leave the parameter empty. GuardScan adds each payload to the end of the URL.

Two public practice targets used with this project:

```text
http://testphp.vulnweb.com/listproducts.php?cat=
http://testphp.vulnweb.com/search.php?test=
```

The first is for SQL injection. The second is for XSS. For BOLA, use the public crAPI vehicle-location API with two accounts.

## Command line

```text
python scanner_cli.py
```

That opens the menu for all seven modules. For a non-interactive run:

```text
python scanner_cli.py --ci --target "http://127.0.0.1:5055/webhook" --scan-type gateway --fail-on high
```

`--fail-on high` exits with code 1 when a High or Critical finding is present, and 0 when it is not. `--scan-type` accepts `lfi`, `sqli`, `xss`, `or`, `crlf`, `bola`, `gateway`, or `all`.

## Docker

Docker is optional. Chrome is already installed in the image.

```text
docker compose up -d guardscan-web
```

The dashboard is at http://localhost:5000. `shm_size` is 2 GB so headless Chrome can start. Reports stay in the `guardscan-reports` volume.

```text
docker compose run --rm guardscan-cli
docker compose down
```

## Layout

```text
app.py                  Dashboard
scanner_cli.py          Command-line tool
scanners/               One module per file
payloads/               Payload lists
core/                   Scan runner and PDF, HTML, and JSON reports
web/                    Dashboard pages
webhook_test_server.py  Local gateway receiver (port 5055)
lfi_test_server.py      Local file page (port 5056)
or_test_server.py       Local redirect page (port 5057)
crlf_test_server.py     Local header page (port 5058)
```

## License

MIT.
