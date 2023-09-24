import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin

# from django.core.validators import FileExtensionValidator
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from phonenumber_field.modelfields import PhoneNumberField

from core.models import BaseModel
from helper import helper
from user.managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User Model Class
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        verbose_name="ID",
    )
    username = models.CharField(
        max_length=100,
        verbose_name="Username",
        unique=True,
    )
    email = models.EmailField(
        max_length=100,
        verbose_name="Email",
        unique=True,
        validators=[helper.validate_email],
    )
    is_email_verified = models.BooleanField(default=False)
    date_joined = models.DateTimeField(
        verbose_name="Date Joined",
        auto_now_add=True,
    )
    last_login = models.DateTimeField(
        auto_now=True,
    )

    is_staff = models.BooleanField(
        verbose_name="Staff Status",
        default=False,
        help_text="Designate if the user has " "staff status",
    )
    is_active = models.BooleanField(
        verbose_name="Active Status",
        default=True,
        help_text="Designate if the user has " "active status",
    )
    is_superuser = models.BooleanField(
        verbose_name="Superuser Status",
        default=False,
        help_text="Designate if the " "user has superuser " "status",
    )

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = [
        "email",
    ]

    objects = UserManager()

    def __str__(self):
        return self.username


class UserInformationModel(BaseModel):
    """
    Model to store user basic information
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="user_information"
    )
    first_name = models.CharField(
        max_length=254,
    )

    last_name = models.CharField(
        max_length=254,
    )
    phone_number = PhoneNumberField(
        verbose_name="Phone Number",
    )

    address_one = models.CharField(
        max_length=255,
    )

    address_two = models.CharField(
        max_length=255,
        blank=True,
    )
    city = models.CharField(
        max_length=100,
    )

    zipcode = models.CharField(
        max_length=50,
    )
    country = models.CharField(
        verbose_name="Country",
        max_length=100,
    )
    profile_pic = models.ImageField(
        upload_to="users/",
        default="users/default.png",
    )

    birth_date = models.DateField(
        verbose_name="Birth Date",
        null=True,
    )
    gender_options = (
        ("Male", "Male"),
        ("Female", "Female"),
        ("Other", "Other"),
    )

    gender = models.CharField(
        verbose_name="Choose Gender",
        choices=gender_options,
        max_length=20,
    )

    def __str__(self):
        return f"{self.user}'s information"


class OTPModel(BaseModel):
    """
    Model to handle user OTP
    """

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="user_otp",
    )
    key = models.TextField(
        unique=True,
        blank=True,
        null=True,
    )
    is_active = models.BooleanField(
        default=False,
    )

    def __str__(self):
        return f"OTP - {self.user.username} - {self.user.email}"


@receiver(post_save, sender=User)
def create_instance(sender, instance, created, **kwargs):
    if created:
        OTPModel.objects.create(
            user=instance,
        )
        UserInformationModel.objects.create(
            user=instance,
        )

        # TODO Mail sender function called for later
        # if not settings.EMAIL_VERIFICATION_REQUIRED or instance.is_email_verified:
        #     task.send_mail_task.delay(
        #         subject=helper.encrypt("Welcome to MailGrass"),
        #         body=helper.encrypt(f"Welcome {instance.username}"),
        #         # html_message=helper.encrypt(render_to_string(template_name="forget_password.html", context=context)),
        #         # attachment=attachment.read() if attachment else None,
        #         # attachment_name=attachment.name if attachment else None,
        #         from_email=helper.encrypt(settings.DEFAULT_FROM_EMAIL),
        #         recipient_list=(instance.email,),
        #         # reply_to=("mail@gmail.com",),
        #         # cc=("mail1@gmail.com", "mail2@gmail.com"),
        #         # bcc=("mail3@gmail.com",),
        #         smtp_host=helper.encrypt(settings.EMAIL_HOST),
        #         smtp_port=helper.encrypt(settings.EMAIL_PORT),
        #         auth_user=helper.encrypt(settings.EMAIL_HOST_USER),
        #         auth_password=helper.encrypt(settings.EMAIL_HOST_PASSWORD),
        #         use_ssl=settings.EMAIL_USE_SSL,
        #         use_tls=settings.EMAIL_USE_TLS,
        #         already_encrypted=False,
        #     )


# @receiver(post_save, sender=User)
# def save_instance(sender, instance, **kwargs):
#     instance.user_otp.save()
#     instance.user_information.save()
