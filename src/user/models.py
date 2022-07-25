from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.core.validators import FileExtensionValidator
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver

from core.models import BaseModel

# Create your models here.


class UserManager(BaseUserManager):
    """
    This is the manager for custom user model
    """

    def create_user(self, username, email, password=None):

        if not username:
            raise ValueError("Username should not be empty")

        if not email:
            raise ValueError("Email should not be empty")

        if not password:
            raise ValueError("Password should not be empty")

        user = self.model(
            username=username,
            email=self.normalize_email(email=email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None):

        user = self.create_user(username=username, email=email, password=password)
        user.is_superuser = True
        user.is_staff = True
        user.is_active = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User Model Class
    """

    username = models.CharField(max_length=100, verbose_name="Username", unique=True)

    email = models.EmailField(max_length=100, verbose_name="Email", unique=True)
    date_joined = models.DateTimeField(verbose_name="Date Joined", auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)

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

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

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
    first_name = models.CharField(max_length=254)

    last_name = models.CharField(max_length=254)
    phone_number = models.CharField(max_length=50, verbose_name="Phone Number")

    address_one = models.CharField(max_length=255)

    address_two = models.CharField(max_length=255, blank=True)
    city = models.CharField(max_length=100)

    zipcode = models.CharField(max_length=50)
    country = models.CharField(verbose_name="Country", max_length=100)
    profile_pic = models.ImageField(upload_to="users/", default="users/default.png")

    birth_date = models.DateField(verbose_name="Birth Date", null=True)
    gender_options = (
        ("Male", "Male"),
        ("Female", "Female"),
        ("Other", "Other"),
    )

    gender = models.CharField(
        verbose_name="Choose Gender", choices=gender_options, max_length=20
    )

    def __str__(self):
        return f"{self.user}'s information"


class OTPModel(BaseModel):
    """
    Model to handle user OTP
    """

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="user_otp")
    key = models.TextField(unique=True, blank=True, null=True)
    is_active = models.BooleanField(default=False)

    def __str__(self):
        return f"OTP - {self.user.username} - {self.user.email}"


@receiver(post_save, sender=User)
def create_instance(sender, instance, created, **kwargs):
    if created:
        OTPModel.objects.create(user=instance)
        UserInformationModel.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_instance(sender, instance, **kwargs):
    instance.user_otp.save()
    instance.user_information.save()
