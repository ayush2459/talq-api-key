# FlowSense API Key Dashboard — UI Prototype

This folder contains a standalone, responsive frontend prototype for the FlowSense TALQ Gateway API-key lifecycle.

## Run locally

No build tools or package installation are required.

1. Download or clone the repository.
2. Open `frontend/index.html` directly in a browser, or serve the repository root with a local static server.
3. Open `frontend/index.html`.

For example, with Python from the repository root:

```bash
python -m http.server 5500
```

Then visit http://127.0.0.1:5500/frontend/.

## Prototype behavior

- Responsive API-key dashboard, summary cards, search, and empty state.
- Required-details form with UUID format validation.
- Expiry dropdown: 90 days, 180 days, 365 days, or Never.
- Telegram connection and verification-code screens to preview the intended flow.
- One-time demo-secret screen with copy action.
- Local revoke confirmation and key status updates.

## Important limitations

This is **frontend-only**. It does not call the FastAPI backend, send Telegram messages, verify identity, or create valid API credentials. The Telegram bot name shown in the UI is a placeholder and is not registered. A six-digit code in the prototype only advances the UI; it does not authenticate anyone.

All demo records live in page memory and disappear on reload. Demo secrets must never be used for API access. The real integration will be implemented and tested separately before deployment.
