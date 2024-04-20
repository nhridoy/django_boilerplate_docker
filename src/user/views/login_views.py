import contextlib

import pyotp
from dj_rest_auth.jwt_auth import (
    set_jwt_access_cookie,
    set_jwt_cookies,
    set_jwt_refresh_cookie,
    unset_jwt_cookies,
)
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, password_validation  # noqa
from django.core.exceptions import ObjectDoesNotExist
from jwt import DecodeError, ExpiredSignatureError
from rest_framework import (  # noqa
    exceptions,
    generics,
    permissions,
    response,
    status,
    views,
    viewsets,
)
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from helper import helper
from user import models, serializers
from user.throttle import AnonUserRateThrottle


def direct_login(request, user, token_data):
    """
    Directly logs in a user by setting JWT cookies in the response and returning the token data.

    Args:
        request: The HTTP request object.
        user: The user object to be logged in.
        token_data: Dictionary containing token data.

    Returns:
        Response object with token data and status code.
    """

    if settings.REST_AUTH.get("SESSION_LOGIN", False):
        login(request, user)
    resp = response.Response()

    set_jwt_cookies(
        response=resp,
        access_token=token_data.get(
            settings.REST_AUTH.get("JWT_AUTH_COOKIE", "access"),
        ),
        refresh_token=token_data.get(
            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "refresh"),
        ),
    )
    resp.data = token_data
    resp.status_code = status.HTTP_200_OK
    return resp


# Login Views
class LoginView(TokenObtainPairView):
    """
    JWT Custom Token Claims View

    MEHTOD: POST:
        username/email
        password
            if otp enabled:
                return secret key for next otp step
            else:
                if session auth enabled:
                    login user
                else:
                    set cookie with access and refresh token and returns
    """

    serializer_class = serializers.CustomTokenObtainPairSerializer

    @staticmethod
    def _otp_login(user):
        """
        Method for returning secret key if OTP is active for user
        """
        refresh_token = RefreshToken.for_user(user)
        secret = helper.encrypt(str(refresh_token))
        return response.Response(
            {"secret": secret},
            status=status.HTTP_202_ACCEPTED,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data[1]
        if settings.EMAIL_VERIFICATION_REQUIRED and not user.is_email_verified:
            return response.Response(
                data={
                    "detail": "Email not Verified",
                    "email_verification_required": True,
                },
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            if user.user_otp.is_active:
                return self._otp_login(user=user)
            return direct_login(
                request=request, user=user, token_data=serializer.validated_data[0]
            )

        except TokenError as e:
            raise InvalidToken(e.args[0]) from e


class TokenRefreshView(generics.GenericAPIView):
    """
    View for get new access token for a valid refresh token
    """

    serializer_class = TokenRefreshSerializer
    permission_classes = ()
    authentication_classes = ()

    @staticmethod
    def _set_cookie(resp, serializer):
        if refresh := serializer.validated_data.get(
            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE")
        ):  # noqa
            set_jwt_refresh_cookie(
                response=resp,
                refresh_token=refresh,
            )
        set_jwt_access_cookie(
            response=resp,
            access_token=serializer.validated_data.get(
                settings.REST_AUTH.get("JWT_AUTH_COOKIE")
            ),  # noqa
        )

    def post(self, request, *args, **kwargs):
        refresh = request.COOKIES.get(
            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "refresh")
        ) or request.data.get(
            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "refresh")
        )

        serializer = self.serializer_class(
            data={settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "refresh"): refresh}
        )
        serializer.is_valid(raise_exception=True)
        resp = response.Response()
        self._set_cookie(resp=resp, serializer=serializer)
        resp.data = serializer.validated_data
        resp.status_code = status.HTTP_200_OK
        return resp


#
# class LogoutView(views.APIView):
#     """
#     Calls Django logout method and delete the Token object
#     assigned to the current User object.
#
#     Accepts/Returns nothing.
#     """
#
#     permission_classes = (permissions.IsAuthenticated,)
#     throttle_scope = "dj_rest_auth"
#
#     def get(self, request, *args, **kwargs):
#         if getattr(settings, "ACCOUNT_LOGOUT_ON_GET", False):
#             resp = self._logout(request)
#         else:
#             resp = self.http_method_not_allowed(request, *args, **kwargs)
#
#         return self.finalize_response(request, resp, *args, **kwargs)
#
#     def post(self, request, *args, **kwargs):
#         return self._logout(request)
#
#     @staticmethod
#     def _logout(request):
#         with contextlib.suppress(AttributeError, ObjectDoesNotExist):
#             request.user.auth_token.delete()
#
#         if settings.REST_AUTH.get("SESSION_LOGIN", False):
#             logout(request)
#
#         resp = response.Response(
#             {"detail": "Successfully logged out."},
#             status=status.HTTP_200_OK,
#         )
#
#         if settings.REST_AUTH.get("USE_JWT", True):
#             cookie_name = settings.REST_AUTH.get("JWT_AUTH_COOKIE", "access")
#
#             unset_jwt_cookies(resp)
#
#             if "rest_framework_simplejwt.token_blacklist" in settings.INSTALLED_APPS:
#                 # add refresh token to blacklist
#                 try:
#                     token = RefreshToken(
#                         request.COOKIES.get(
#                             settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE")
#                         )
#                         or request.data.get(
#                             settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE")
#                         )
#                     )
#                     token.blacklist()
#                 except KeyError:
#                     resp.data = {
#                         "detail": "Refresh token was not included in request data."
#                     }
#                     resp.status_code = status.HTTP_401_UNAUTHORIZED
#                 except (TokenError, AttributeError, TypeError) as error:
#                     if hasattr(error, "args"):
#                         if (
#                             "Token is blacklisted" in error.args
#                             or "Token is invalid or expired" in error.args
#                         ):
#                             resp.data = {"detail": error.args[0]}
#                             resp.status_code = status.HTTP_401_UNAUTHORIZED
#                         else:
#                             resp.data = {"detail": "An error has occurred."}
#                             resp.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
#
#                     else:
#                         resp.data = {"detail": "An error has occurred."}
#                         resp.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
#
#             elif not cookie_name:
#                 message = (
#                     "Neither cookies or blacklist are enabled, so the token "
#                     "has not been deleted server side. Please make sure the token is deleted client side.",
#                 )
#                 resp.data = {"detail": message}
#                 resp.status_code = status.HTTP_200_OK
#         return resp


class OTPLoginView(views.APIView):
    """
    View for Login with OTP

    Has two parameters
        secret: secret key found from the login api route
        otp: code from the authenticator app
    """

    authentication_classes = []
    permission_classes = []
    serializer_class = serializers.OTPLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            return self._validate_otp_and_generate_token(serializer, request)
        except DecodeError as e:
            raise InvalidToken(detail="Wrong Secret") from e

    def _validate_otp_and_generate_token(self, serializer, request):
        data = helper.decode_token(
            token=helper.decrypt(str(serializer.validated_data.get("secret")))
        )
        otp = serializer.validated_data.get("otp")
        current_user = generics.get_object_or_404(models.User, id=data.get("user_id"))
        totp = pyotp.TOTP(helper.decrypt(str(current_user.user_otp.key)))

        print(totp.now())
        if not totp.verify(otp):
            raise ExpiredSignatureError("OTP is Wrong or Expired!!!")
        token = self._get_token(current_user)
        return direct_login(
            user=current_user,
            request=request,
            token_data={
                settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE", "refresh"): str(
                    token
                ),
                settings.REST_AUTH.get("JWT_AUTH_COOKIE", "access"): str(
                    token.access_token
                ),
            },
        )

    @staticmethod
    def _get_token(user):
        token = RefreshToken.for_user(user)
        token["username"] = user.username
        token["email"] = user.email
        token["is_staff"] = user.is_staff
        token["is_active"] = user.is_active
        token["is_superuser"] = user.is_superuser
        return token
