from sqlalchemy import select

from .models import Invoice
from .session import session


def update_invoice(invoice_id, body):
    invoice = session.get(Invoice, invoice_id)
    invoice.status = body.status
    session.commit()
    return invoice
