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
