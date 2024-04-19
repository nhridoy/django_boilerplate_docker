import contextlib
import datetime
from typing import BinaryIO

import jwt
import pyotp
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, password_validation  # noqa
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.template.loader import render_to_string
from jwt import DecodeError
from rest_framework import (  # noqa
    exceptions,
    generics,
    permissions,
    response,
    status,
    views,
    viewsets,
)
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from helper import helper
from user import models, serializers
from user.auth import (
    set_jwt_access_cookie,
    set_jwt_cookies,
    set_jwt_refresh_cookie,
    unset_jwt_cookies,
)
from user.throttle import AnonUserRateThrottle


class PasswordValidateView(views.APIView):
    """
    View for validating password
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.PasswordValidateSerializer

    def post(self, request, *args, **kwargs):
        current_user = self.request.user
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        if authenticate(
            request=request,
            username=current_user.email,
            password=serializer.validated_data.get("password"),
        ):
            return response.Response(
                {"message": "Password Accepted"}, status=status.HTTP_200_OK
            )
        return response.Response(
            {"message": "Wrong Password"},
            status=status.HTTP_406_NOT_ACCEPTABLE,
        )


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.ChangePasswordSerializer

    @staticmethod
    def _logout_on_password_change(request):
        resp = response.Response(
            {"detail": "Password updated successfully"},
            status=status.HTTP_200_OK,
        )
        if settings.REST_AUTH.get("SESSION_LOGIN", False):
            logout(request)
        unset_jwt_cookies(resp)
        return resp

    def _change_password(self, request, user, password):
        password_validation.validate_password(password=password, user=user)
        user.set_password(password)
        user.save()
        if settings.REST_AUTH.get("LOGOUT_ON_PASSWORD_CHANGE", True):
            self._logout_on_password_change(request=request)
        return response.Response(
            {"detail": "Password updated successfully"},
            status=status.HTTP_200_OK,
        )

    def update(self, request, *args, **kwargs):
        user = self.request.user
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check old password
        old_password = serializer.validated_data.get("old_password")
        if not user.check_password(old_password):
            return response.Response(
                {"old_password": ["Wrong password."]},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        # set_password also hashes the password that the user will get
        password = serializer.validated_data.get("password")
        retype_password = serializer.validated_data.get("retype_password")

        if password != retype_password:
            raise exceptions.NotAcceptable(detail="Passwords do not match")
        try:
            self._change_password(
                request=request,
                user=user,
                password=password,
            )

        except ValidationError as e:
            return response.Response(
                {"detail": e},
                status=status.HTTP_403_FORBIDDEN,
            )


class ResetPasswordView(views.APIView):
    """
    View for getting email or sms for password reset
    post: username: ""
    """

    serializer_class = serializers.ResetPasswordSerializer
    authentication_classes = []
    permission_classes = []
    throttle_classes = (AnonUserRateThrottle,)

    @staticmethod
    def generate_link(*args):
        payload = {
            "user": str(args[0].id),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=30),
            "is_email": True,
        }

        return f"{args[1]}/auth/reset-password/{helper.encrypt(helper.encode_token(payload=payload))}/"

    def email_sender_helper(
        self, user, origin, organization_logo, attachment: BinaryIO = None
    ):
        url = self.generate_link(user, origin)
        context = {
            "url": url,
            "organization_logo": organization_logo,
        }
        # TODO Mail sender function called for later
        # task.send_mail_task.delay(
        #     subject=helper.encrypt("Forget Password"),
        #     body=helper.encrypt(f"To reset your password please click this link {url}"),
        #     html_message=helper.encrypt(
        #         render_to_string(template_name="forget_password.html", context=context)
        #     ),
        #     attachment=attachment.read() if attachment else None,
        #     attachment_name=attachment.name if attachment else None,
        #     from_email=helper.encrypt(settings.DEFAULT_FROM_EMAIL),
        #     recipient_list=(user.email,),
        #     # reply_to=("mail@gmail.com",),
        #     # cc=("mail1@gmail.com", "mail2@gmail.com"),
        #     # bcc=("mail3@gmail.com",),
        #     smtp_host=helper.encrypt(settings.EMAIL_HOST),
        #     smtp_port=helper.encrypt(settings.EMAIL_PORT),
        #     auth_user=helper.encrypt(settings.EMAIL_HOST_USER),
        #     auth_password=helper.encrypt(settings.EMAIL_HOST_PASSWORD),
        #     use_ssl=settings.EMAIL_USE_SSL,
        #     use_tls=settings.EMAIL_USE_TLS,
        #     already_encrypted=False,
        # )

        return response.Response({"detail": "Email Sent", "is_email": True})

    def post(self, *args, **kwargs):
        try:
            origin = self.request.headers["origin"]
        except Exception as e:
            raise exceptions.PermissionDenied() from e
        ser = self.serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)
        user = ser.user

        if user.email:
            organization_logo = (
                "https://nexisltd.com/_next/static/media/logo.396c4947.svg"
            )
            return self.email_sender_helper(user, origin, organization_logo)

        raise exceptions.PermissionDenied(
            detail="No Email found!!!",
        )


class ResetPasswordCheckView(views.APIView):
    """
    View for checking if the url is expired or not
    post: token: ""
    """

    authentication_classes = []
    permission_classes = []
    serializer_class = serializers.ResetPasswordCheckSerializer

    def post(self, *args, **kwargs):
        ser = self.serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)

        try:
            helper.decode_token(token=helper.decrypt(str(ser.data.get("token"))))

        except Exception as e:
            raise exceptions.APIException(detail=e) from e
        return response.Response({"data": "Accepted"})


class ResetPasswordConfirmView(views.APIView):
    """
    View for resetting password after checking the token
    post: token: "", password: ""
    """

    serializer_class = serializers.ResetPasswordConfirmSerializer
    authentication_classes = []
    permission_classes = []

    def post(self, *args, **kwargs):
        ser = self.serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)

        try:
            return self._change_password(ser)
        except Exception as e:
            raise exceptions.APIException(detail=e) from e

    @staticmethod
    def _change_password(ser):
        decoded = helper.decode_token(token=helper.decrypt(str(ser.data.get("token"))))

        if ser.validated_data.get("password") != ser.validated_data.get(
            "retype_password"
        ):
            raise exceptions.NotAcceptable(detail="Passwords doesn't match!!!")

        user = models.User.objects.get(id=decoded.get("user"))
        password_validation.validate_password(
            password=ser.data.get("password"), user=user
        )
        user.set_password(ser.data.get("password"))
        user.save()
        return response.Response({"detail": "Password Changed Successfully"})
