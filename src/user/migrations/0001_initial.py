# Generated by Django 5.0.4 on 2024-04-20 15:46

import uuid

import django.db.models.deletion
import phonenumber_field.modelfields
from django.conf import settings
from django.db import migrations, models

import helper.helper


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                ("password", models.CharField(max_length=128, verbose_name="password")),
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "username",
                    models.CharField(
                        max_length=100, unique=True, verbose_name="Username"
                    ),
                ),
                (
                    "email",
                    models.EmailField(
                        max_length=100,
                        unique=True,
                        validators=[helper.helper.validate_email],
                        verbose_name="Email",
                    ),
                ),
                ("is_email_verified", models.BooleanField(default=False)),
                (
                    "date_joined",
                    models.DateTimeField(auto_now_add=True, verbose_name="Date Joined"),
                ),
                ("last_login", models.DateTimeField(auto_now=True)),
                (
                    "is_staff",
                    models.BooleanField(
                        default=False,
                        help_text="Designate if the user has staff status",
                        verbose_name="Staff Status",
                    ),
                ),
                (
                    "is_active",
                    models.BooleanField(
                        default=True,
                        help_text="Designate if the user has active status",
                        verbose_name="Active Status",
                    ),
                ),
                (
                    "is_superuser",
                    models.BooleanField(
                        default=False,
                        help_text="Designate if the user has superuser status",
                        verbose_name="Superuser Status",
                    ),
                ),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to. A user will get all permissions granted to each of their groups.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.group",
                        verbose_name="groups",
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        help_text="Specific permissions for this user.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.permission",
                        verbose_name="user permissions",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="OTPModel",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("status", models.BooleanField(default=True)),
                ("key", models.TextField(blank=True, null=True, unique=True)),
                ("is_active", models.BooleanField(default=False)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_otp",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="UserInformationModel",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("status", models.BooleanField(default=True)),
                ("first_name", models.CharField(max_length=254)),
                ("last_name", models.CharField(max_length=254)),
                (
                    "phone_number",
                    phonenumber_field.modelfields.PhoneNumberField(
                        max_length=128, region=None, verbose_name="Phone Number"
                    ),
                ),
                ("address_one", models.CharField(max_length=255)),
                ("address_two", models.CharField(blank=True, max_length=255)),
                ("city", models.CharField(max_length=100)),
                ("zipcode", models.CharField(max_length=50)),
                ("country", models.CharField(max_length=100, verbose_name="Country")),
                (
                    "profile_pic",
                    models.ImageField(default="users/default.png", upload_to="users/"),
                ),
                ("birth_date", models.DateField(null=True, verbose_name="Birth Date")),
                (
                    "gender",
                    models.CharField(
                        choices=[
                            ("Male", "Male"),
                            ("Female", "Female"),
                            ("Other", "Other"),
                        ],
                        max_length=20,
                        verbose_name="Choose Gender",
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="user_information",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
    ]
