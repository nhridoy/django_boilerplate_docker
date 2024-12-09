from django.contrib.auth import authenticate, login, logout, password_validation  # noqa
from rest_framework import (
    exceptions,
    generics,
    permissions,  # noqa
    response,
    status,
    views,
    viewsets,
)

from user import models, serializers


# Profile Related Views
class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = serializers.UserSerializer
    queryset = models.User.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        return self.request.user
