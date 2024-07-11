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
from rest_framework import (
    exceptions,
    generics,
    permissions,  # noqa
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

# Signup View


class NewUserView(viewsets.ModelViewSet):
    """
    View for New User Create and resend email
    """

    queryset = models.User.objects.all()
    permission_classes = ()
    authentication_classes = ()

    # permission_classes = [apipermissions.IsSuperUser]
    def get_throttles(self):
        # permission_classes = [apipermissions.IsSuperUser]
        if self.action == "resend_email":
            return [AnonUserRateThrottle()]
        return super().get_throttles()

    def get_serializer_class(self):
        if self.action == "create":
            return serializers.NewUserSerializer
        elif self.action == "resend_email":
            return serializers.ResendVerificationEmailSerializer

    @staticmethod
    def _login(request, user):
        refresh = RefreshToken.for_user(user)
        refresh["email"] = user.email
        if settings.REST_AUTH.get("SESSION_LOGIN", False):
            login(request, user)
        resp = response.Response()

        set_jwt_cookies(
            response=resp,
            access_token=refresh.access_token,
            refresh_token=refresh,
        )

        resp.data = {
            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE"): str(refresh),
            settings.REST_AUTH.get("JWT_AUTH_COOKIE"): str(refresh.access_token),
        }
        resp.status_code = status.HTTP_201_CREATED
        return resp

    @staticmethod
    def generate_link(*args):
        payload = {
            "user": str(args[0].id),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=30),
        }

        return f"{args[1]}/auth/verify-email/{helper.encrypt(helper.encode_token(payload=payload))}/"

    def _verification_email(self, user, origin):
        context = {
            "url": self.generate_link(user, origin),
        }

        # TODO Mail sender function called for later
        # task.send_mail_task.delay(
        #     subject=helper.encrypt("Verify Email"),
        #     body=helper.encrypt(
        #         f"For using MailGrass please verify email by clicking this link {context.get('url')}"
        #     ),
        #     html_message=helper.encrypt(
        #         render_to_string(
        #             template_name="email_verification.html", context=context
        #         )
        #     ),
        #     from_email=helper.encrypt(settings.DEFAULT_FROM_EMAIL),
        #     recipient_list=(user.email,),
        #     smtp_host=helper.encrypt(settings.EMAIL_HOST),
        #     smtp_port=helper.encrypt(settings.EMAIL_PORT),
        #     auth_user=helper.encrypt(settings.EMAIL_HOST_USER),
        #     auth_password=helper.encrypt(settings.EMAIL_HOST_PASSWORD),
        #     use_ssl=settings.EMAIL_USE_SSL,
        #     use_tls=settings.EMAIL_USE_TLS,
        #     already_encrypted=False,
        # )

        return response.Response(
            {
                "detail": "Verification Email Sent",
                "email_verification_required": True,
            }
        )

    def create(self, request, *args, **kwargs):
        """
        create method for creating
        """
        # Need the origin to generate email verification link
        try:
            origin = self.request.headers["origin"]
        except Exception as e:
            raise exceptions.PermissionDenied(
                detail="Origin not found on request header"
            ) from e

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        if settings.EMAIL_VERIFICATION_REQUIRED:
            return self._verification_email(user=user, origin=origin)
        # Login After Registration
        return self._login(request=request, user=user)

    def resend_email(self, *args, **kwargs):
        """
        resend_mail method for resending verification email
        """
        # Need the origin to generate email verification link
        try:
            origin = self.request.headers["origin"]
        except Exception as e:
            raise exceptions.PermissionDenied(
                detail="Origin not found on request header"
            ) from e

        serializer_class = self.get_serializer_class()
        ser = serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)
        user = ser.user
        if user.is_email_verified:
            raise exceptions.PermissionDenied(detail="Email already verified")
        if user.email:
            organization_logo = (
                "https://nexisltd.com/_next/static/media/logo.396c4947.svg"
            )
            return self._verification_email(user=user, origin=origin)

        raise exceptions.PermissionDenied(
            detail="No Email found!!!",
        )

    @staticmethod
    def verify_email(*args, **kwargs):
        try:
            data = helper.decode_token(token=helper.decrypt(kwargs.get("token")))
            try:
                user = models.User.objects.get(id=data["user"])
                if user.is_email_verified:
                    return response.Response(
                        {
                            "detail": "Email Already Verified",
                        }
                    )
                user.is_email_verified = True
                user.save()
            except (models.User.DoesNotExist, ValidationError) as e:
                raise exceptions.NotFound(detail=e) from e
        except (
            jwt.ExpiredSignatureError,
            jwt.InvalidTokenError,
            jwt.DecodeError,
        ) as e:
            raise exceptions.ValidationError(detail={"detail": e}) from e
        return response.Response({"detail": "Email Verification Successful"})
