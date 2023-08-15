from django.conf import settings
from django.utils import timezone


def set_jwt_access_cookie(response, access_token):
    if cookie_name := settings.REST_AUTH.get("JWT_AUTH_COOKIE", "access"):
        access_token_expiration = timezone.now() + settings.SIMPLE_JWT.get(
            "ACCESS_TOKEN_LIFETIME"
        )
        cookie_secure = settings.REST_AUTH.get("JWT_AUTH_SECURE", False)
        cookie_httponly = settings.REST_AUTH.get("JWT_AUTH_HTTPONLY", True)
        cookie_samesite = settings.REST_AUTH.get("JWT_AUTH_SAMESITE", "Lax")

        response.set_cookie(
            cookie_name,
            access_token,
            expires=access_token_expiration,
            secure=cookie_secure,
            httponly=cookie_httponly,
            samesite=cookie_samesite,
        )


def set_jwt_refresh_cookie(response, refresh_token):
    if refresh_cookie_name := settings.REST_AUTH.get(
        "JWT_AUTH_REFRESH_COOKIE", "refresh"
    ):
        refresh_token_expiration = timezone.now() + settings.SIMPLE_JWT.get(
            "REFRESH_TOKEN_LIFETIME"
        )
        refresh_cookie_path = settings.REST_AUTH.get(
            "JWT_AUTH_REFRESH_COOKIE_PATH", "/"
        )
        cookie_secure = settings.REST_AUTH.get("JWT_AUTH_SECURE", False)
        cookie_httponly = settings.REST_AUTH.get("JWT_AUTH_HTTPONLY", True)
        cookie_samesite = settings.REST_AUTH.get("JWT_AUTH_SAMESITE", "Lax")

        response.set_cookie(
            refresh_cookie_name,
            refresh_token,
            expires=refresh_token_expiration,
            secure=cookie_secure,
            httponly=cookie_httponly,
            samesite=cookie_samesite,
            path=refresh_cookie_path,
        )


def set_jwt_cookies(response, access_token, refresh_token):
    """
    Set cookie
    """
    set_jwt_access_cookie(response, access_token)
    set_jwt_refresh_cookie(response, refresh_token)


def unset_jwt_cookies(response):
    cookie_name = settings.REST_AUTH.get("JWT_AUTH_COOKIE", "access")
    refresh_cookie_name = settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "refresh")
    refresh_cookie_path = settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE_PATH", "/")
    cookie_samesite = settings.REST_AUTH.get("JWT_AUTH_SAMESITE", "Lax")

    if cookie_name:
        response.delete_cookie(cookie_name, samesite=cookie_samesite)
    if refresh_cookie_name:
        response.delete_cookie(
            refresh_cookie_name, path=refresh_cookie_path, samesite=cookie_samesite
        )
