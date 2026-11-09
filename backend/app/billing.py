"""Adaptador de facturación (Semana 11).

Corre en el backend/worker de S09, nunca en el navegador. Usa el snapshot
persistido del pedido confirmado. La llamada remota NO ocurre dentro de la
transacción del pedido: un fallo de facturación no revierte una venta.
El estado vive en billing_tasks y es independiente de notification_status.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .config import Settings
from .db import utcnow
from .models import BillingTask, Order

logger = logging.getLogger(__name__)

LEASE_SECONDS = 60
PERMANENT_STATUSES = {400, 401, 404, 405, 409, 413, 415, 422}


def build_invoice_payload(order_id: uuid.UUID, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Contrato exacto de facturación a partir del snapshot persistido."""
    items = [
        {
            "product_id": item["product_id"],
            "name": item["name"],
            "quantity": item["quantity"],
            "unit_price_cents": item["unit_price_cents"],
        }
        for item in snapshot["items"]
    ]
    return {
        "order_id": str(order_id),
        "currency": "PEN",
        "items": items,
        "total_cents": snapshot["total_cents"],
    }


async def send_invoice(
    client: httpx.AsyncClient,
    base_url: str,
    token: str,
    payload: dict[str, Any],
) -> tuple[str, dict[str, Any] | None, str | None]:
    """Devuelve (resultado, factura, error): issued | retry | failed.

    - issued: 201 (creada) o 200 (replay) con order_id coincidente.
    - retry: timeout, red, 429 o 5xx; se reintenta con el MISMO cuerpo y clave.
    - failed: error permanente (401/404/409/422...); no se reintenta en bucle.
    Nunca se registran el token ni el cuerpo.
    """
    order_id = payload["order_id"]
    try:
        response = await client.post(
            f"{base_url}/invoices",
            content=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-Billing-Token": token,
                "Idempotency-Key": order_id,
            },
        )
    except (httpx.TimeoutException, httpx.TransportError) as exc:
        return "retry", None, f"red/timeout: {type(exc).__name__}"

    status = response.status_code
    if status in (200, 201):
        try:
            data = response.json()
        except ValueError:
            return "retry", None, f"HTTP {status} con cuerpo no JSON"
        if (
            isinstance(data, dict)
            and data.get("order_id") == order_id
            and isinstance(data.get("id"), str)
            and data.get("status") == "issued"
        ):
            return "issued", data, None
        return "failed", None, "respuesta de facturación inválida (order_id/id/status)"

    code = ""
    try:
        body = response.json()
        code = str(body.get("error", {}).get("code", ""))[:40]
    except (ValueError, AttributeError):
        pass
    label = f"HTTP {status} {code}".strip()
    if status in PERMANENT_STATUSES:
        return "failed", None, label
    return "retry", None, label


async def claim_due_tasks(
    session_factory: async_sessionmaker[AsyncSession],
    limit: int = 20,
) -> list[uuid.UUID]:
    """Toma tareas vencidas con un arrendamiento corto (evita doble envío)."""
    now = utcnow()
    async with session_factory() as session:
        async with session.begin():
            ids = (
                await session.execute(
                    select(BillingTask.order_id)
                    .where(BillingTask.status == "pending", BillingTask.next_attempt_at <= now)
                    .order_by(BillingTask.created_at)
                    .limit(limit)
                    .with_for_update(skip_locked=True)
                )
            ).scalars().all()
            if ids:
                await session.execute(
                    update(BillingTask)
                    .where(BillingTask.order_id.in_(ids))
                    .values(next_attempt_at=now + timedelta(seconds=LEASE_SECONDS))
                )
            return list(ids)


async def process_task(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    client: httpx.AsyncClient,
    order_id: uuid.UUID,
) -> str:
    async with session_factory() as session:
        order = await session.get(Order, order_id)
        task = await session.get(BillingTask, order_id)
        if order is None or task is None or task.status != "pending":
            return "skipped"
        payload = build_invoice_payload(order.id, dict(order.snapshot))

    result, invoice, error = await send_invoice(
        client,
        settings.billing_base_url,
        settings.billing_token_value(),
        payload,
    )

    now = utcnow()
    async with session_factory() as session:
        async with session.begin():
            task = await session.get(BillingTask, order_id, with_for_update=True)
            if task is None:
                return "skipped"
            task.attempts += 1
            task.updated_at = now
            if result == "issued" and invoice is not None:
                task.status = "issued"
                task.invoice_id = str(invoice["id"])[:64]
                task.invoice_number = str(invoice.get("number", ""))[:80] or None
                task.last_error = None
            elif result == "retry" and task.attempts < settings.billing_max_auto_attempts:
                task.status = "pending"
                task.last_error = (error or "")[:300]
                task.next_attempt_at = now + timedelta(seconds=settings.billing_retry_seconds)
            else:
                # failed permanente, o reintentos automáticos agotados:
                # el pedido sigue confirmado; se recupera con reintento manual.
                task.status = "failed"
                task.last_error = (error or "")[:300]
    return result


async def run_billing_pass(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    client: httpx.AsyncClient,
) -> int:
    ids = await claim_due_tasks(session_factory)
    for order_id in ids:
        await process_task(session_factory, settings, client, order_id)
    return len(ids)


async def billing_loop(database: Any, settings: Settings) -> None:
    async with httpx.AsyncClient(timeout=settings.billing_timeout_seconds) as client:
        while True:
            handled = 0
            try:
                if settings.billing_configured:
                    handled = await run_billing_pass(database.session_factory, settings, client)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("billing error type=%s", type(exc).__name__)
            await asyncio.sleep(0.5 if handled else 2.0)


async def requeue_task(
    session: AsyncSession,
    order_id: uuid.UUID,
    dataset_id: str,
) -> BillingTask | None:
    """Reintento manual: vuelve a 'pending' una tarea fallida (mismo cuerpo y clave)."""
    async with session.begin():
        task = await session.get(BillingTask, order_id, with_for_update=True)
        if task is None or task.dataset_id != dataset_id:
            return None
        if task.status == "failed":
            now = utcnow()
            task.status = "pending"
            task.attempts = 0
            task.next_attempt_at = now
            task.updated_at = now
        return task
