import contextlib

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.auth.password_validation import validate_password
from django.db import transaction
from django.db.models import Q
from django.urls import exceptions as url_exceptions
from django.utils.translation import gettext_lazy as _
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework import exceptions, serializers, validators
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from user import models


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        if settings.SIMPLE_JWT.get("UPDATE_LAST_LOGIN"):
            update_last_login(None, self.user)

        return data, self.user

    def get_token(self, user):
        token = super().get_token(user)
        token["username"] = user.username
        token["email"] = user.email
        token["is_staff"] = user.is_staff
        token["is_active"] = user.is_active
        token["is_superuser"] = user.is_superuser
        return token


# class TokenObtainPairSerializer(TokenObtainSerializer):
#     token_class = tokens.RefreshToken
#
#     def validate(self, attrs):
#         data = super().validate(attrs)
#
#         refresh = self.get_token(self.user)
#         # Add custom claims
#         refresh["email"] = self.user.email
#         refresh["is_superuser"] = self.user.is_superuser
#         refresh["is_staff"] = self.user.is_staff
#
#         data[settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE")] = str(refresh)
#         data[settings.REST_AUTH.get("JWT_AUTH_COOKIE")] = str(refresh.access_token)
#
#         if settings.SIMPLE_JWT.get("UPDATE_LAST_LOGIN"):
#             update_last_login(None, self.user)
#
#         return data, self.user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField()
    password = serializers.CharField(style={"input_type": "password"})

    def authenticate(self, **kwargs):
        return authenticate(self.context["request"], **kwargs)

    def _validate_email(self, email, password):
        if email and password:
            user = self.authenticate(email=email, password=password)
        else:
            msg = _('Must include "email" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def _validate_username(self, username, password):
        if username and password:
            user = self.authenticate(username=username, password=password)
        else:
            msg = _('Must include "username" and "password".')
            raise exceptions.ValidationError(msg)

        return user

    def _validate_username_email(self, username, email, password):
        if email and password:
            user = self.authenticate(email=email, password=password)
        elif username and password:
            user = self.authenticate(username=username, password=password)
        else:
            msg = _(
                'Must include either "username" or "email" and "password".',
            )
            raise exceptions.ValidationError(msg)

        return user

    def get_auth_user_using_allauth(self, username, email, password):
        from allauth.account import app_settings

        # Authentication through email
        if (
            app_settings.AUTHENTICATION_METHOD
            == app_settings.AuthenticationMethod.EMAIL
        ):
            return self._validate_email(email, password)

        # Authentication through username
        if (
            app_settings.AUTHENTICATION_METHOD
            == app_settings.AuthenticationMethod.USERNAME
        ):
            return self._validate_username(username, password)

        # Authentication through either username or email
        return self._validate_username_email(username, email, password)

    def get_auth_user_using_orm(self, username, email, password):
        if email:
            with contextlib.suppress(models.User.DoesNotExist):
                username = models.User.objects.get(
                    email__iexact=email,
                ).get_username()
        if username:
            return self._validate_username_email(username, "", password)

        return None

    def get_auth_user(self, username, email, password):
        """
        Retrieve the auth user from given POST payload by using
        either `allauth` auth scheme or bare Django auth scheme.

        Returns the authenticated user instance if credentials are correct,
        else `None` will be returned
        """
        if "allauth" in settings.INSTALLED_APPS:
            # When `is_active` of a user is set to False,
            # allauth tries to return template html
            # which does not exist. This is the solution for it.
            # See issue #264.
            try:
                return self.get_auth_user_using_allauth(
                    username,
                    email,
                    password,
                )
            except url_exceptions.NoReverseMatch as e:
                msg = _("Unable to log in with provided credentials.")
                raise exceptions.ValidationError(msg) from e
        return self.get_auth_user_using_orm(username, email, password)

    @staticmethod
    def validate_auth_user_status(user):
        if not user.is_active:
            msg = _("User account is disabled.")
            raise exceptions.ValidationError(msg)

    @staticmethod
    def validate_email_verification_status(user):
        from allauth.account import app_settings

        if (
            app_settings.EMAIL_VERIFICATION
            == app_settings.EmailVerificationMethod.MANDATORY
            and not user.emailaddress_set.filter(
                email=user.email, verified=True
            ).exists()
        ):
            raise serializers.ValidationError(_("E-mail is not verified."))

    def validate(self, attrs):
        username = attrs.get("username")
        email = attrs.get("email")
        password = attrs.get("password")
        user = self.get_auth_user(username, email, password)

        if not user:
            msg = _("Unable to log in with provided credentials.")
            raise exceptions.ValidationError(msg)

        # Did we get back an active user?
        self.validate_auth_user_status(user)

        # If required, is the email verified?
        if "dj_rest_auth.registration" in settings.INSTALLED_APPS:
            self.validate_email_verification_status(user)

        attrs["user"] = user
        return attrs


class OTPLoginSerializer(serializers.Serializer):
    """
    Serializer to log in with OTP
    """

    secret = serializers.CharField(write_only=True)
    otp = serializers.IntegerField(write_only=True)
