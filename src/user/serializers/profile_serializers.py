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
from rest_framework_simplejwt import settings as jwt_settings
from rest_framework_simplejwt import tokens
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenObtainSerializer,
)

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


# class TokenRefreshSerializer(serializers.Serializer):
#     refresh = serializers.CharField()
#
#     token_class = tokens.RefreshToken
#
#     def validate(self, attrs):
#         try:
#             refresh = self.token_class(attrs["refresh"])
#         except TokenError as e:
#             raise exceptions.AuthenticationFailed(detail=e) from e
#
#         data = {"access": str(refresh.access_token)}
#
#         if jwt_settings.api_settings.ROTATE_REFRESH_TOKENS:
#             if jwt_settings.api_settings.BLACKLIST_AFTER_ROTATION:
#                 with contextlib.suppress(AttributeError):
#                     # Attempt to blacklist the given refresh token
#                     # If blacklist app not installed, `blacklist` method
#                     # will not be present
#                     refresh.blacklist()
#             refresh.set_jti()
#             refresh.set_exp()
#             refresh.set_iat()
#
#             data["refresh"] = str(refresh)
#
#         return data


class NewUserSerializer(serializers.ModelSerializer):
    """
    User Serializer
    """

    password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        required=True,
        validators=[validate_password],
    )
    retype_password = serializers.CharField(
        style={"input_type": "password"},
        write_only=True,
        required=True,
        label="Retype Password",
    )
    first_name = serializers.CharField(source="user_information.first_name")
    last_name = serializers.CharField(source="user_information.last_name")
    phone_number = PhoneNumberField(source="user_information.phone_number")
    gender = serializers.ChoiceField(
        source="user_information.gender",
        choices=models.UserInformationModel.gender_options,
    )

    class Meta:
        model = models.User
        fields = (
            "id",
            "username",
            "email",
            "password",
            "retype_password",
            "first_name",
            "last_name",
            "phone_number",
            "gender",
        )
        read_only_fields = (
            "id",
            "is_email_verified",
        )

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("retype_password"):
            raise validators.ValidationError(
                {
                    "password": "Passwords Doesn't Match",
                }
            )
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        information_user = validated_data.pop("user_information")

        # As usual, create the User
        validated_data.pop("retype_password")
        user = models.User.objects.create_user(**validated_data)

        # Then create UserInformation or related object with additional fields
        models.UserInformationModel.objects.update_or_create(
            user=user, defaults={**information_user}
        )

        return user


class UserSerializer(serializers.ModelSerializer):
    """
    User Serializer
    """

    first_name = serializers.CharField(source="user_information.first_name")
    last_name = serializers.CharField(source="user_information.last_name")
    phone_number = PhoneNumberField(source="user_information.phone_number")
    address_one = serializers.CharField(source="user_information.address_one")
    address_two = serializers.CharField(source="user_information.address_two")
    city = serializers.CharField(source="user_information.city")
    zipcode = serializers.CharField(source="user_information.zipcode")
    country = serializers.CharField(source="user_information.country")
    profile_pic = serializers.ImageField(source="user_information.profile_pic")
    birth_date = serializers.DateField(source="user_information.birth_date")
    gender = serializers.ChoiceField(
        source="user_information.gender",
        choices=models.UserInformationModel.gender_options,
    )

    class Meta:
        model = models.User
        fields = (
            "id",
            "username",
            "email",
            "is_email_verified",
            "first_name",
            "last_name",
            "phone_number",
            "address_one",
            "address_two",
            "city",
            "zipcode",
            "country",
            "profile_pic",
            "birth_date",
            "gender",
        )
        read_only_fields = (
            "id",
            "username",
            "email",
            "is_email_verified",
        )

    @transaction.atomic
    def update(self, instance, validated_data):
        if information_user := validated_data.pop("user_information", None):
            # Update the UserInformation fields or related object
            user_information = instance.user_information
            for key, value in information_user.items():
                setattr(user_information, key, value)
            user_information.save()

        return instance


class ResendVerificationEmailSerializer(serializers.Serializer):
    """
    New User Registration Serializer
    """

    username = serializers.CharField()

    def validate_username(self, value):
        try:
            self.user = models.User.objects.get(Q(username=value) | Q(email=value))
        except models.User.DoesNotExist as e:
            raise validators.ValidationError(
                detail="Wrong Username/Email/Phone Number"
            ) from e
        return value


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


# Forget/Reset Password Section
class ResetPasswordSerializer(serializers.Serializer):
    """
    Reset Password Request Serializer
    """

    username = serializers.CharField(required=True)

    def validate_username(self, value):
        try:
            self.user = models.User.objects.get(Q(email=value) | Q(username=value))
        except models.User.DoesNotExist as e:
            raise validators.ValidationError(
                detail="Wrong Username/Email/Phone Number"
            ) from e
        return value


class ResetPasswordCheckSerializer(serializers.Serializer):
    """
    Serializer for reset-password-check api view
    """

    token = serializers.CharField(required=True)

    class Meta:
        fields = "__all__"


class ResetPasswordConfirmSerializer(serializers.Serializer):
    """
    Reset Password Confirm Serializer
    """

    token = serializers.CharField(required=True)
    password = serializers.CharField(
        style={"input_type": "password"},
        # write_only=True,
        required=True,
        validators=[validate_password],
    )
    retype_password = serializers.CharField(
        style={"input_type": "password"},
        # write_only=True,
        required=True,
    )
