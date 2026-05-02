from sqlalchemy import select

from .models import Invoice
from .session import session


def update_invoice(invoice_id, tenant_id, body):
    invoice = session.execute(
        select(Invoice).where(Invoice.id == invoice_id, Invoice.tenant_id == tenant_id)
    ).scalar_one()
    invoice.memo = body.memo
    session.commit()
    return invoice
