import os

from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.core.management.base import BaseCommand
from dotenv import load_dotenv

load_dotenv()

# from users.models import email_superuser

SUPERUSER_USERNAME = os.getenv("SUPERUSER_USERNAME")
SUPERUSER_EMAIL = os.getenv("SUPERUSER_EMAIL")
SUPERUSER_PASSWORD = os.getenv("SUPERUSER_PASSWORD")

if not SUPERUSER_PASSWORD:
    raise ImproperlyConfigured("'SUPERUSER_PASSWORD' environment variable is unset")

User = get_user_model()


help_message = f"""
Sets up the DB, creating:
1) superuser with admin rights (Username: {SUPERUSER_USERNAME})
"""


class Command(BaseCommand):
    """
    init: Command to set up database for the application
    """

    help = help_message

    def handle(self, *args, **kwargs):
        if (
            not User.objects.filter(username=SUPERUSER_USERNAME).exists()
            or not User.objects.filter(email=SUPERUSER_EMAIL).exists()
        ):
            User.objects.create_superuser(
                username=SUPERUSER_USERNAME,
                email=SUPERUSER_EMAIL,
                password=SUPERUSER_PASSWORD,
            )
            print("Super-User Created!")
        print("Set-Up Complete!")
