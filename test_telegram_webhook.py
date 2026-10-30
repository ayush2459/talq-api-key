
import json
import urllib.request
import urllib.error
from dotenv import dotenv_values

env = dotenv_values(".env")
secret = env.get("TELEGRAM_WEBHOOK_SECRET")

if not secret:
    raise SystemExit("TELEGRAM_WEBHOOK_SECRET is missing from .env")

payload = {
    "update_id": 987654321,
    "message": {
        "message_id": 1,
        "date": 1792990000,
        "chat": {"id": 123456789, "type": "private"},
        "from": {
            "id": 123456789,
            "is_bot": False,
            "first_name": "Test"
        },
        "text": "/start"
    }
}

request = urllib.request.Request(
    "https://flowsense-talq-gateway.onrender.com/telegram/webhook",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Content-Type": "application/json",
        "X-Telegram-Bot-Api-Secret-Token": secret
    },
    method="POST"
)

try:
    with urllib.request.urlopen(request, timeout=20) as response:
        print("HTTP status:", response.status)
        print("Response:", response.read().decode("utf-8"))
except urllib.error.HTTPError as error:
    print("HTTP status:", error.code)
    print("Response:", error.read().decode("utf-8"))
except Exception as error:
    print("Request failed:", type(error).__name__, str(error))
