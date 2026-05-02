from rest_framework.viewsets import ModelViewSet

from .models import Invoice


class InvoiceViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return Invoice.objects.get(id=self.kwargs["pk"])
