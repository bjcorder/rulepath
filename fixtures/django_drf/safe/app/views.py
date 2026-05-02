from rest_framework.viewsets import ModelViewSet

from .models import Invoice


class InvoiceViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, InvoicePermission]

    def get_queryset(self):
        return Invoice.objects.filter(tenant_id=self.request.user.tenant_id)

    def get_object(self):
        obj = super().get_object()
        self.check_object_permissions(self.request, obj)
        return obj
