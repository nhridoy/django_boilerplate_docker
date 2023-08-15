"""
Django settings for core project.

Generated by 'django-admin startproject' using Django 4.0.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.0/ref/settings/
"""
import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = BASE_DIR.joinpath("templates")
STATIC_DIR = BASE_DIR.joinpath("static")
MEDIA_DIR = BASE_DIR.joinpath("media")

# Django Configuration
ON_PRODUCTION = os.getenv("ON_PRODUCTION") == "True"
DJANGO_SECRET_KEY = os.getenv("SECRET_KEY")
PROJECT_NAME = os.getenv("PROJECT_NAME")
DJANGO_DEBUG = os.getenv("DEBUG") == "True"
SECURE_SSL_REDIRECT = os.getenv("SECURE_SSL_REDIRECT") == "True"
DJANGO_ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS").split(",")
CORS_HOSTS = os.getenv("CORS_HOSTS").split(",")

# Database configuration
DJANGO_DB_ENGINE = os.getenv("DB_ENGINE")
DJANGO_DB_NAME = os.getenv("DB_NAME")
DJANGO_DB_USER = os.getenv("DB_USER")
DJANGO_DB_PASSWORD = os.getenv("DB_PASSWORD")
DJANGO_DB_HOST = os.getenv("DB_HOST")

# Email configuration
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = os.getenv("EMAIL_PORT")
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS") == "True"
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL") == "True"
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = DJANGO_SECRET_KEY

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = DJANGO_DEBUG

ALLOWED_HOSTS = DJANGO_ALLOWED_HOSTS

# Application definition

INSTALLED_APPS = [
    "django.contrib.sites",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third Party
    "corsheaders",
    "rest_framework",
    "rest_framework.authtoken",
    "rest_framework_simplejwt.token_blacklist",
    "rest_framework_simplejwt",
    "django_cleanup.apps.CleanupConfig",
    "django_crontab",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "dj_rest_auth.registration",
    "drf_spectacular",
    "phonenumber_field",
    # Installed Apps
    "user",
]

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework.authentication.BasicAuthentication",
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "dj_rest_auth.jwt_auth.JWTCookieAuthentication",
    ),
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
        "rest_framework.parsers.FileUploadParser",
    ],
}

# DRF Spectacular for api organised view
SPECTACULAR_SETTINGS = {
    "TITLE": "Oxygen API",
    "DESCRIPTION": "Oxygen is django boilerplate with \
    custom User model and authentication system",
    "VERSION": "0.5.0",
    # "EXCLUDE_CONTENT_TYPES": ["multipart/form-data"],
    "COMPONENT_SPLIT_REQUEST": True,
    "PARSER_WHITELIST": [
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.FormParser",
        "rest_framework.parsers.MultiPartParser",
        "rest_framework.parsers.FileUploadParser",
    ],
    # 'RENDERER_WHITELIST': [],
}
# If you are not using JWT Authentication system please comment this section
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=90),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "VERIFYING_KEY": None,
    "AUDIENCE": None,
    "ISSUER": None,
    "JWK_URL": None,
    "LEEWAY": 0,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",  # noqa
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",
    "JTI_CLAIM": "jti",
    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),
}

REST_AUTH = {
    "OLD_PASSWORD_FIELD_ENABLED": True,
    "LOGOUT_ON_PASSWORD_CHANGE": True,
    "SESSION_LOGIN": False,
    "USE_JWT": True,
    "JWT_AUTH_COOKIE": "access",
    "JWT_AUTH_REFRESH_COOKIE": "refresh",
    "JWT_AUTH_REFRESH_COOKIE_PATH": "/",
    "JWT_AUTH_SECURE": False,  # If set to True, the cookie will only be sent through https scheme. Default is False.
    "JWT_AUTH_HTTPONLY": True,
    # If set to True, the client-side JavaScript will not be able to access the cookie. Default is True.
    "JWT_AUTH_SAMESITE": "Lax",
    "JWT_AUTH_RETURN_EXPIRATION": False,
    "JWT_AUTH_COOKIE_USE_CSRF": False,
    "JWT_AUTH_COOKIE_ENFORCE_CSRF_ON_UNAUTHENTICATED": False,
}

EMAIL_VERIFICATION_REQUIRED = True

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # 'user.middleware.AuthorizationMiddleware',
]

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [TEMPLATE_DIR],
        # create Template directory and set template directory here as -> 'DIRS': [BASE_DIR/'template'] # noqa
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"

# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases


if ON_PRODUCTION:
    DATABASES = {
        "default": {
            "ENGINE": DJANGO_DB_ENGINE,
            "NAME": DJANGO_DB_NAME,
            "USER": DJANGO_DB_USER,
            "PASSWORD": DJANGO_DB_PASSWORD,
            "HOST": DJANGO_DB_HOST,
        }
    }
else:
    # SqliteDB
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }
# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",  # noqa
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",  # noqa
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",  # noqa
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",  # noqa
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.0/topics/i18n/

LANGUAGE_CODE = "en-us"

# change as per your region Ex: 'America/New_York' | 'Asia/Dhaka'
TIME_ZONE = "Asia/Dhaka"

USE_I18N = True

USE_TZ = False

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.0/howto/static-files/

STATIC_URL = "static/"
# STATIC_ROOT = "static"
# STATICFILES_DIRS = [STATIC_DIR]
if DEBUG:
    STATICFILES_DIRS = [
        STATIC_DIR,
    ]
else:
    STATIC_ROOT = STATIC_URL
STATICFILES_STORAGE = "whitenoise.storage.CompressedStaticFilesStorage"
WHITENOISE_AUTOREFRESH = True

MEDIA_URL = "/media/"
# MEDIA_ROOT = "media"
MEDIA_ROOT = BASE_DIR.joinpath("media")
# DEBUG_PROPAGATE_EXCEPTIONS = True

# Default primary key field type
# https://docs.djangoproject.com/en/4.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_USER_MODEL = "user.User"
AUTHENTICATION_BACKENDS = [
    "user.backends.EmailPhoneUsernameAuthenticationBackend"
]  # <-- Untested with dj_rest_auth package

CORS_ALLOW_ALL_ORIGINS = True
# Turn this on if want to specify hosts
# CORS_ALLOWED_ORIGINS = CORS_HOSTS
CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:8000"]
# CORS_ALLOWED_ORIGINS = os.getenv("CSRF_TRUSTED_ORIGINS").split(",")
# CSRF_TRUSTED_ORIGINS = os.getenv("CSRF_TRUSTED_ORIGINS").split(",")
SITE_ID = 1

CRONJOBS = []
