import contextlib

from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.urls import exceptions as url_exceptions
from django.utils.translation import gettext_lazy as _
from rest_framework import exceptions, serializers, validators
from rest_framework_simplejwt import settings as jwt_settings
from rest_framework_simplejwt import tokens
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from user import models


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    JWT Custom Token Claims Serializer
    """

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

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        cls.validate_email_verification_status(user)
        # Add custom claims
        token["email"] = user.email
        token["is_superuser"] = user.is_superuser
        token["is_staff"] = user.is_staff

        return token


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


class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    token_class = tokens.RefreshToken

    def validate(self, attrs):
        try:
            refresh = self.token_class(attrs["refresh"])
        except TokenError as e:
            raise exceptions.AuthenticationFailed(detail=e) from e

        data = {"access": str(refresh.access_token)}

        if jwt_settings.api_settings.ROTATE_REFRESH_TOKENS:
            if jwt_settings.api_settings.BLACKLIST_AFTER_ROTATION:
                with contextlib.suppress(AttributeError):
                    # Attempt to blacklist the given refresh token
                    # If blacklist app not installed, `blacklist` method
                    # will not be present
                    refresh.blacklist()
            refresh.set_jti()
            refresh.set_exp()
            refresh.set_iat()

            data["refresh"] = str(refresh)

        return data


class NewUserSerializer(serializers.ModelSerializer):
    """
    New User Registration Serializer
    """

    email = serializers.EmailField(
        required=True,
        validators=[
            validators.UniqueValidator(
                queryset=models.User.objects.all(),
            )
        ],
    )
    username = serializers.CharField(
        required=True, validators=[UnicodeUsernameValidator()]
    )

    password1 = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    password2 = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        required=True,
        label="Retype Password",
    )

    class Meta:
        model = models.User
        fields = ["username", "email", "password1", "password2"]

    def validate(self, attrs):
        if attrs["password1"] != attrs["password2"]:
            raise validators.ValidationError(
                {
                    "password1": "Password Doesn't Match",
                }
            )
        if models.User.objects.filter(username=attrs["username"]).exists():
            raise validators.ValidationError(
                {"username": "user with this User ID already exists."}
            )
        return attrs

    def create(self, validated_data):
        user = models.User.objects.create(
            username=validated_data["username"],
            email=validated_data["email"],
        )
        user.set_password(validated_data["password1"])
        user.save()
        return user


class PasswordValidateSerializer(serializers.Serializer):
    """
    Serializer for validating password
    """

    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        required=True,
    )


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """

    old_password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        required=True,
    )
    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        required=True,
    )
    retype_password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        required=True,
    )


class QRCreateSerializer(serializers.Serializer):
    """
    Serializer for QR create view
    """

    generated_key = serializers.CharField()
    otp = serializers.IntegerField(write_only=True)


class OTPLoginSerializer(serializers.Serializer):
    """
    Serializer to login with OTP
    """

    secret = serializers.CharField(write_only=True)
    otp = serializers.IntegerField(write_only=True)


class OTPCheckSerializer(serializers.ModelSerializer):
    """
    Serializer for checking if OTP is active or not
    """

    # detail = serializers.BooleanField(read_only=True)

    class Meta:
        model = models.OTPModel
        fields = ["is_active"]
