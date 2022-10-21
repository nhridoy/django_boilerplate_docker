import jwt
import requests
from cryptography.fernet import Fernet
from django.conf import settings


def send_sms(numbers: list, message: str):
    for number in numbers:
        # requests.post(f"http://10.27.27.147:8000/?number={number}&message={message}")

        url = f"http://10.27.27.147:8000/?number={number}&message={message}"

        response = requests.request("POST", url)

        print(response.text)


def create_token(payload: dict):
    return jwt.encode(
        payload=payload,
        key=settings.SECRET_KEY,
        algorithm=settings.SIMPLE_JWT["ALGORITHM"],
    )


def encode(data: str):
    key = bytes(settings.SECRET_KEY, "utf-8")
    return Fernet(key).encrypt(bytes(data, "utf-8"))


def decode(token: str):
    key = bytes(settings.SECRET_KEY, "utf-8")
    return Fernet(key).decrypt(bytes(token, "utf-8")).decode("utf-8")
