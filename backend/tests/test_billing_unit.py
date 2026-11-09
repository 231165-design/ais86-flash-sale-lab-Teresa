import asyncio
import uuid

import httpx

from app.billing import build_invoice_payload, send_invoice

BASE = "https://proyecto.supabase.co/functions/v1/billing"
TOKEN = "a" * 64


def make_payload():
    order_id = uuid.uuid4()
    snapshot = {
        "id": str(order_id),
        "total_cents": 309700,
        "items": [
            {"product_id": "nova-headphones", "name": "Nova", "quantity": 2, "unit_price_cents": 129900},
            {"product_id": "arc-mouse", "name": "Arc", "quantity": 1, "unit_price_cents": 49900},
        ],
        "notification_status": "pending",
    }
    return build_invoice_payload(order_id, snapshot)


def call(handler, payload):
    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await send_invoice(client, BASE, TOKEN, payload)

    return asyncio.run(run())


def invoice_for(payload):
    return {"id": str(uuid.uuid4()), "number": "DEMO-x", "order_id": payload["order_id"], "status": "issued"}


def test_payload_has_exact_contract_fields():
    payload = make_payload()
    assert set(payload) == {"order_id", "currency", "items", "total_cents"}
    assert payload["currency"] == "PEN"
    assert all(set(i) == {"product_id", "name", "quantity", "unit_price_cents"} for i in payload["items"])


def test_request_uses_order_id_as_idempotency_key_and_private_token():
    payload = make_payload()
    seen = {}

    def handler(request):
        seen["key"] = request.headers["Idempotency-Key"]
        seen["token"] = request.headers["X-Billing-Token"]
        seen["url"] = str(request.url)
        return httpx.Response(201, json=invoice_for(payload))

    result, _, _ = call(handler, payload)
    assert result == "issued"
    assert seen["key"] == payload["order_id"]
    assert seen["token"] == TOKEN
    assert seen["url"] == BASE + "/invoices"


def test_201_and_200_replay_are_issued():
    payload = make_payload()
    for status in (201, 200):
        result, data, error = call(lambda r, s=status: httpx.Response(s, json=invoice_for(payload)), payload)
        assert (result, error) == ("issued", None)
        assert data["order_id"] == payload["order_id"]


def test_mismatched_order_id_is_rejected():
    payload = make_payload()
    other = invoice_for(payload)
    other["order_id"] = str(uuid.uuid4())
    result, _, _ = call(lambda r: httpx.Response(201, json=other), payload)
    assert result == "failed"


def test_conflict_and_validation_are_permanent():
    payload = make_payload()
    for status, code in ((409, "IDEMPOTENCY_CONFLICT"), (422, "VALIDATION_ERROR"), (401, "UNAUTHORIZED")):
        body = {"error": {"code": code, "message": "x"}}
        result, _, error = call(lambda r, s=status, b=body: httpx.Response(s, json=b), payload)
        assert result == "failed"
        assert code in error
        assert TOKEN not in error


def test_provider_down_is_retryable():
    payload = make_payload()
    for status in (429, 500, 503):
        result, _, _ = call(lambda r, s=status: httpx.Response(s, json={}), payload)
        assert result == "retry"


def test_timeout_and_network_errors_are_retryable():
    payload = make_payload()

    def timeout(request):
        raise httpx.ReadTimeout("lento", request=request)

    def refused(request):
        raise httpx.ConnectError("caido", request=request)

    assert call(timeout, payload)[0] == "retry"
    assert call(refused, payload)[0] == "retry"
