from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.db.models import Q

User = get_user_model()


class EmailPhoneUsernameAuthenticationBackend(object):
    @staticmethod
    def authenticate(request, username=None, password=None):
        try:
            user = User.objects.get(
                Q(user_information__phone_number=username)
                | Q(email=username)
                | Q(username=username),
            )

        except User.DoesNotExist:
            return None

        return (
            user
            if user
            and check_password(
                password,
                user.password,
            )
            else None
        )

    @staticmethod
    def get_user(user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
