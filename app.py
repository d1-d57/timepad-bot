"""
Бот для уведомлений о продажах билетов на Timepad.

Принимает вебхуки от Timepad, считает продажи по категориям билетов,
шлёт уведомления в Telegram-канал.

При старте подгружает историю заказов из Timepad API, чтобы
счётчик всегда отражал реальность (даже после рестарта/засыпания).
"""

import hashlib
import hmac
import json
import logging
import os
from collections import defaultdict
from threading import Lock

import requests
from flask import Flask, request, abort

# ---------------------------------------------------------------------------
# Конфигурация — всё через переменные окружения, чтобы не светить секреты в коде
# ---------------------------------------------------------------------------
TELEGRAM_TOKEN = os.environ["TELEGRAM_TOKEN"]
TELEGRAM_CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
TIMEPAD_WEBHOOK_SECRET = os.environ["TIMEPAD_WEBHOOK_SECRET"]
TIMEPAD_API_TOKEN = os.environ["TIMEPAD_API_TOKEN"]
TIMEPAD_EVENT_ID = os.environ["TIMEPAD_EVENT_ID"]

# Какие статусы билета считаем «оплачен»
PAID_STATUSES = {"paid", "paid_offline", "paid_ur", "transfer_payment", "ok"}
# Какие статусы — «возврат»
REFUND_STATUSES = {"return_org", "return_tp", "return_payment_request"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Состояние: счётчик «сколько билетов по какой цене продано»
# ticket_id (внутренний id у Timepad'а) -> {"price": int, "name": str, "count": int}
# ---------------------------------------------------------------------------
state_lock = Lock()
# Множество ID билетов, которые уже учтены — чтобы не считать дважды
counted_ticket_ids: set[int] = set()
# Сводка: цена → {"name": str, "count": int}
by_price: dict[int, dict] = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def send_telegram(text: str) -> None:
    """Отправить сообщение в Telegram."""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    try:
        r = requests.post(
            url,
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
        if not r.ok:
            log.error("Telegram error: %s %s", r.status_code, r.text)
    except Exception:
        log.exception("Failed to send Telegram message")


def format_summary() -> str:
    """Строка вида '80 × 800 ₽, 19 × 1000 ₽'."""
    if not by_price:
        return "пока пусто"
    parts = []
    for price in sorted(by_price.keys()):
        count = by_price[price]["count"]
        parts.append(f"{count} × {price} ₽")
    return ", ".join(parts)


def add_ticket(ticket_id: int, price: int, name: str) -> bool:
    """Добавить билет в счётчик. Возвращает True, если впервые."""
    with state_lock:
        if ticket_id in counted_ticket_ids:
            return False
        counted_ticket_ids.add(ticket_id)
        if price not in by_price:
            by_price[price] = {"name": name, "count": 0}
        by_price[price]["count"] += 1
        return True


def remove_ticket(ticket_id: int, price: int) -> bool:
    """Убрать билет (возврат). Возвращает True, если он был учтён."""
    with state_lock:
        if ticket_id not in counted_ticket_ids:
            return False
        counted_ticket_ids.remove(ticket_id)
        if price in by_price and by_price[price]["count"] > 0:
            by_price[price]["count"] -= 1
        return True


# ---------------------------------------------------------------------------
# Загрузка истории при старте
# ---------------------------------------------------------------------------
def load_history() -> None:
    """
    Попытаться один раз при старте подтянуть историю заказов из Timepad
    и пересчитать счётчик. Если не получится — стартуем с пустого состояния.
    Это нормальный режим: новые продажи всё равно будут приходить через вебхук.
    """
    log.info("Loading order history from Timepad...")
    headers = {"Authorization": f"Bearer {TIMEPAD_API_TOKEN}"}
    base_url = f"https://api.timepad.ru/v1/events/{TIMEPAD_EVENT_ID}/orders"

    skip = 0
    limit = 100
    total_loaded = 0
    while True:
        try:
            r = requests.get(
                base_url,
                headers=headers,
                params={"limit": limit, "skip": skip},
                timeout=20,
            )
            if r.status_code == 403:
                log.warning(
                    "Timepad API returned 403 (no view_visitors permission). "
                    "Skipping history load — will count only new sales from webhook."
                )
                return
            r.raise_for_status()
            data = r.json()
        except Exception:
            log.warning("Failed to load history — starting from empty state. New sales will still be tracked.")
            return

        orders = data.get("values", [])
        if not orders:
            break

        for order in orders:
            for ticket in order.get("tickets", []):
                status = (ticket.get("status_raw_name") or "").lower()
                if status not in PAID_STATUSES:
                    continue
                ticket_id = ticket.get("id")
                price = int(round(float(ticket.get("price_nominal", 0))))
                name = ticket.get("ticket_type", {}).get("name", "")
                if ticket_id is not None:
                    if add_ticket(ticket_id, price, name):
                        total_loaded += 1

        if len(orders) < limit:
            break
        skip += limit

    log.info("History loaded: %d tickets, summary: %s", total_loaded, format_summary())


# ---------------------------------------------------------------------------
# Обработчик вебхука
# ---------------------------------------------------------------------------
def verify_signature(body: bytes, signature_header: str) -> bool:
    """Проверить HMAC-SHA1 подпись от Timepad."""
    if not signature_header:
        return False
    expected = hmac.new(
        TIMEPAD_WEBHOOK_SECRET.encode(), body, hashlib.sha1
    ).hexdigest()
    return hmac.compare_digest(f"sha1={expected}", signature_header)


@app.route("/timepad-webhook", methods=["POST"])
def timepad_webhook():
    body = request.get_data()
    sig = request.headers.get("X-Hub-Signature", "")

    if not verify_signature(body, sig):
        log.warning("Bad signature")
        abort(403)

    try:
        payload = json.loads(body)
    except Exception:
        log.exception("Bad JSON")
        return "bad json", 400

    log.info("Webhook received: %s", payload.get("status_raw_name"))

    # Timepad шлёт два типа вебхуков: по заказу (есть tickets[]) и по билету.
    # Нам удобнее работать по заказу — там сразу видно сколько билетов куплено разом.
    tickets = payload.get("tickets") or []

    if not tickets and "ticket" in payload:
        # вебхук по одному билету
        tickets = [payload["ticket"]]

    if not tickets:
        return "ok", 200

    purchased = []   # (ticket_id, price, name) только что оплаченных
    refunded = []    # то же — для возвратов

    for ticket in tickets:
        status = (ticket.get("status_raw_name") or "").lower()
        ticket_id = ticket.get("id")
        if ticket_id is None:
            continue
        price = int(round(float(ticket.get("price_nominal", 0))))
        name = ticket.get("ticket_type", {}).get("name", "")

        if status in PAID_STATUSES:
            if add_ticket(ticket_id, price, name):
                purchased.append((ticket_id, price, name))
        elif status in REFUND_STATUSES:
            if remove_ticket(ticket_id, price):
                refunded.append((ticket_id, price, name))

    # Формируем сообщения
    if purchased:
        # группируем по цене для строки заголовка
        head_groups: dict[int, int] = defaultdict(int)
        for _, price, _ in purchased:
            head_groups[price] += 1
        head_parts = [f"{cnt} × {p} ₽" for p, cnt in sorted(head_groups.items())]
        msg = f"🎟 <b>Новая продажа:</b> {', '.join(head_parts)}\n\nВсего: {format_summary()}"
        send_telegram(msg)

    if refunded:
        head_groups: dict[int, int] = defaultdict(int)
        for _, price, _ in refunded:
            head_groups[price] += 1
        head_parts = [f"{cnt} × {p} ₽" for p, cnt in sorted(head_groups.items())]
        msg = f"↩️ <b>Возврат:</b> {', '.join(head_parts)}\n\nВсего: {format_summary()}"
        send_telegram(msg)

    return "ok", 200


@app.route("/", methods=["GET"])
def index():
    """Healthcheck — Render пингует / для проверки живости."""
    with state_lock:
        total = sum(b["count"] for b in by_price.values())
    return f"Timepad bot is alive. Tickets counted: {total}. Summary: {format_summary()}", 200


# ---------------------------------------------------------------------------
# Старт
# ---------------------------------------------------------------------------
# Загрузка истории выполняется при импорте модуля (gunicorn worker boot)
load_history()

if __name__ == "__main__":
    # Локальный запуск для отладки
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
