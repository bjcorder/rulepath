from uuid import UUID

from fastapi import APIRouter, Depends

from . import invoice_service

router = APIRouter()


def get_current_user():
    return object()


@router.patch("/invoices/{invoice_id}")
def update_invoice(invoice_id: UUID, body: object, current_user=Depends(get_current_user)):
    return invoice_service.update_invoice(invoice_id, body)
