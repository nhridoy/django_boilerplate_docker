import contextlib

import jwt
import MailChecker
import requests
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ValidationError

from .blocked_domains import domain_list


def send_sms(numbers: list, message: str):
    for number in numbers:
        # requests.post(f"http://10.27.27.147:8000/?number={number}&message={message}")

        url = f"http://10.27.27.147:8000/?number={number}&message={message}"

        response = requests.request("POST", url)

        print(response.text)


def encode_token(payload: dict):
    return jwt.encode(
        payload=payload,
        key=settings.SECRET_KEY,
        algorithm=settings.SIMPLE_JWT.get("ALGORITHM"),
    )


def decode_token(token: str):
    return jwt.decode(
        jwt=token,
        key=settings.SECRET_KEY,
        algorithms="HS256",
    )


def encrypt(data: str) -> str:
    """
    Encrypt any string and return another string
    """
    key = bytes(settings.SECRET_KEY, "utf-8")
    return Fernet(key).encrypt(bytes(data, "utf-8")).decode("utf-8")


def decrypt(token: str) -> str:
    """
    Take an encrypted string and decrypt it. Return string
    """
    key = bytes(settings.SECRET_KEY, "utf-8")
    try:
        return Fernet(key).decrypt(bytes(token, "utf-8")).decode("utf-8")
    except InvalidToken as e:
        return "Unencrypted String"


def validate_email(email):
    with contextlib.suppress(IndexError):
        if (
            (host := email.rsplit("@", 1)[1]) in domain_list
            or email
            and "@" in email
            and MailChecker.MailChecker.is_blacklisted(email)
        ):
            raise ValidationError(f"Email with domain: {host} not accepted")
