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
