# BAC-TESTER

A Burp Suite extension for automated **Broken Access Control (BAC)** testing. It intercepts HTTP requests from the Proxy, replays them with a victim's session headers, and classifies each response as **Vulnerable**, **Secure**, or **Suspicious**.

---

## Features

- Auto-injects a victim's session headers into every intercepted `POST`/`PUT`/`PATCH`/`DELETE` request
- Classifies responses into three verdict buckets: Vulnerable, Secure, Suspicious
- Dark-themed UI with real-time counters and tab badges
- Right-click → **Send to Repeater** for any logged request
- Audible beep alert on vulnerability detection
- Skips static assets (`.js`, `.css`, `.png`, etc.) automatically

---

## Requirements

| Requirement | Version |
|---|---|
| Burp Suite | Pro or Community ≥ 2023.x |
| Jython Standalone | 2.7.x |

---

## Installation

1. Download [Jython Standalone](https://www.jython.org/download) and point Burp to it under **Extender → Options → Python Environment**.
2. Clone this repo or download `BacTester.py`.
3. In Burp, go to **Extender → Extensions → Add**.
4. Set **Extension Type** to `Python` and select `BacTester.py`.
5. The **BAC-TESTER** tab will appear in Burp's main menu.

---

## Usage

1. Open the **BAC-TESTER → Config** tab.
2. Paste the victim user's session headers (one per line), e.g.:
   ```
   Cookie: session=abc123; user_id=42
   Authorization: Bearer eyJhbGci...
   ```
3. Click **Save**, then **Enable**.
4. Browse the application as a **privileged user** (attacker) through Burp Proxy.
5. BAC-TESTER replays each request with the victim's session and flags any access control bypass.

---

## Verdict Logic

| Verdict | Condition |
|---|---|
| 🔴 **VULNERABLE** | Response status `2xx` |
| 🟢 **SECURE** | Status `403`, or body contains `forbidden` / `user is not allowed` |
| 🟡 **SUSPICIOUS** | Non-empty body that doesn't match generic error phrases |

---

## Screenshots

> _Add screenshots of the Vulnerable, Secure, and Config tabs here._

---

## Disclaimer

This tool is intended for **authorized security testing only**. Do not use it against systems you do not have explicit written permission to test. The author is not responsible for any misuse.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
