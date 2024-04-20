import contextlib

from django.conf import settings
from django.contrib.auth import authenticate, password_validation
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

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError(detail="You have entered Wrong password.")
        return value

    def validate_retype_password(self, value):
        if self.initial_data.get("password") != self.initial_data.get(
            "retype_password"
        ):
            raise serializers.ValidationError("The two password fields didn't match.")
        return value

    def validate_password(self, value):
        user = self.context["request"].user
        password_validation.validate_password(password=value, user=user)
        return value


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
