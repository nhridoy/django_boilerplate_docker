import pyotp
from django.conf import settings
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

from helper import helper
from user import models, serializers
from user.throttle import AnonUserRateThrottle


class OTPCheckView(views.APIView):
    """
    Check if OTP is active for user or not
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.OTPCheckSerializer

    def get(self, request, *args, **kwargs):
        try:
            user_otp = generics.get_object_or_404(
                models.OTPModel, user=self.request.user
            )
            serializer = self.serializer_class(user_otp)
            return response.Response(
                {
                    "detail": serializer.data.get("is_active"),
                }
            )
        except Exception as e:
            raise exceptions.APIException from e


class OTPCreateView(generics.GenericAPIView):
    """
    OTPCreateView class for handling QR code creation, verification, and OTP disabling.

    _get method generates a QR code and a random key.
    _post method verifies the OTP and updates the user's OTP key if valid.
    _delete method disables the user's OTP.

    Args:
        request: The HTTP request object.
        args: Additional positional arguments.
        kwargs: Additional keyword arguments.

    Returns:
        Response object with relevant data and status code.
    Raises:
        NotAcceptable: If the OTP is incorrect or expired.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.OTPCreateSerializer

    @staticmethod
    def _clear_user_otp(user_otp):
        user_otp.key = ""
        user_otp.is_active = False
        user_otp.save()

    def get(self, request, *args, **kwargs):
        generated_key = pyotp.random_base32()
        current_user = self.request.user
        qr_key = pyotp.TOTP(generated_key).provisioning_uri(
            name=current_user.email, issuer_name=settings.PROJECT_NAME
        )
        return response.Response(
            {"qr_key": qr_key, "generated_key": generated_key},
            status=status.HTTP_200_OK,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        generated_key = serializer.validated_data.get("generated_key")
        otp = serializer.validated_data.get("otp")
        current_user = self.request.user
        user_otp = models.OTPModel.objects.get(user=current_user)

        totp = pyotp.TOTP(generated_key)
        if totp.verify(otp):
            user_otp.key = helper.encrypt(str(generated_key))
            user_otp.is_active = True
            user_otp.save()
            return response.Response(
                {"detail": "Accepted"},
                status=status.HTTP_200_OK,
            )
        else:
            print(totp.now())
            self._clear_user_otp(user_otp)
            raise exceptions.NotAcceptable(detail="OTP is Wrong or Expired!!!")

    def delete(self, request, *args, **kwargs):
        current_user = self.request.user
        user_otp = generics.get_object_or_404(models.OTPModel, user=current_user)
        self._clear_user_otp(user_otp)
        return response.Response({"message": "OTP Removed"})
