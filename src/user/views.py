import contextlib
import datetime
from typing import BinaryIO

import jwt
import pyotp
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, password_validation  # noqa
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.template.loader import render_to_string
from jwt import DecodeError
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

from .auth import (
    set_jwt_access_cookie,
    set_jwt_cookies,
    set_jwt_refresh_cookie,
    unset_jwt_cookies,
)
from .throttle import AnonUserRateThrottle

# Signup View


class NewUserView(viewsets.ModelViewSet):
    """
    View for New User Create and resend email
    """

    queryset = models.User.objects.all()
    permission_classes = ()
    authentication_classes = ()

    # permission_classes = [apipermissions.IsSuperUser]
    def get_throttles(self):
        # permission_classes = [apipermissions.IsSuperUser]
        if self.action == "resend_email":
            return [AnonUserRateThrottle()]
        return super().get_throttles()

    def get_serializer_class(self):
        if self.action == "create":
            return serializers.NewUserSerializer
        elif self.action == "resend_email":
            return serializers.ResendVerificationEmailSerializer

    @staticmethod
    def _login(request, user):
        refresh = RefreshToken.for_user(user)
        refresh["email"] = user.email
        if settings.REST_AUTH.get("SESSION_LOGIN", False):
            login(request, user)
        resp = response.Response()

        set_jwt_cookies(
            response=resp,
            access_token=refresh.access_token,
            refresh_token=refresh,
        )

        resp.data = {
            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE"): str(refresh),
            settings.REST_AUTH.get("JWT_AUTH_COOKIE"): str(refresh.access_token),
        }
        resp.status_code = status.HTTP_201_CREATED
        return resp

    @staticmethod
    def generate_link(*args):
        payload = {
            "user": str(args[0].id),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=30),
        }

        return f"{args[1]}/auth/verify-email/{helper.encrypt(helper.encode_token(payload=payload))}/"

    def _verification_email(self, user, origin):
        context = {
            "url": self.generate_link(user, origin),
        }

        # TODO Mail sender function called for later
        # task.send_mail_task.delay(
        #     subject=helper.encrypt("Verify Email"),
        #     body=helper.encrypt(
        #         f"For using MailGrass please verify email by clicking this link {context.get('url')}"
        #     ),
        #     html_message=helper.encrypt(
        #         render_to_string(
        #             template_name="email_verification.html", context=context
        #         )
        #     ),
        #     from_email=helper.encrypt(settings.DEFAULT_FROM_EMAIL),
        #     recipient_list=(user.email,),
        #     smtp_host=helper.encrypt(settings.EMAIL_HOST),
        #     smtp_port=helper.encrypt(settings.EMAIL_PORT),
        #     auth_user=helper.encrypt(settings.EMAIL_HOST_USER),
        #     auth_password=helper.encrypt(settings.EMAIL_HOST_PASSWORD),
        #     use_ssl=settings.EMAIL_USE_SSL,
        #     use_tls=settings.EMAIL_USE_TLS,
        #     already_encrypted=False,
        # )

        return response.Response(
            {
                "detail": "Verification Email Sent",
                "email_verification_required": True,
            }
        )

    def create(self, request, *args, **kwargs):
        """
        create method for creating
        """
        try:
            origin = self.request.headers["origin"]
        except Exception as e:
            raise exceptions.PermissionDenied() from e

        serializer_class = self.get_serializer_class()
        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        if settings.EMAIL_VERIFICATION_REQUIRED:
            return self._verification_email(user=user, origin=origin)
        # Login After Registration
        return self._login(request=request, user=user)

    def resend_email(self, *args, **kwargs):
        """
        resend_mail method for resending verification email
        """
        try:
            origin = self.request.headers["origin"]
        except Exception as e:
            raise exceptions.PermissionDenied() from e

        serializer_class = self.get_serializer_class()
        ser = serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)
        user = ser.user
        if user.is_email_verified:
            raise exceptions.PermissionDenied(detail="Email already verified")
        if user.email:
            organization_logo = (
                "https://nexisltd.com/_next/static/media/logo.396c4947.svg"
            )
            return self._verification_email(user=user, origin=origin)

        raise exceptions.PermissionDenied(
            detail="No Email found!!!",
        )

    @staticmethod
    def verify_email(*args, **kwargs):
        try:
            data = helper.decode_token(token=helper.decrypt(kwargs.get("token")))
            try:
                user = models.User.objects.get(id=data["user"])
                if user.is_email_verified:
                    return response.Response(
                        {
                            "detail": "Email Already Verified",
                        }
                    )
                user.is_email_verified = True
                user.save()
            except (models.User.DoesNotExist, ValidationError) as e:
                raise exceptions.NotFound(detail=e) from e
        except (
            jwt.ExpiredSignatureError,
            jwt.InvalidTokenError,
            jwt.DecodeError,
        ) as e:
            raise exceptions.ValidationError(detail={"detail": e}) from e
        return response.Response({"detail": "Email Verification Successful"})


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

    serializer_class = serializers.TokenObtainPairSerializer

    @staticmethod
    def _direct_login(request, user, token_data):
        """
        Method for login without OTP
        """
        if settings.REST_AUTH.get("SESSION_LOGIN", False):
            login(request, user)
        resp = response.Response()

        set_jwt_cookies(
            response=resp,
            access_token=token_data.get(
                settings.REST_AUTH.get("JWT_AUTH_COOKIE"),
            ),
            refresh_token=token_data.get(
                settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE"),
            ),
        )
        resp.data = token_data
        resp.status_code = status.HTTP_200_OK
        return resp

    @staticmethod
    def _otp_login(user):
        """
        Method for returning secret key if OTP is active for user
        """
        refresh_token = RefreshToken.for_user(user)
        fer_key = helper.encrypt(str(refresh_token))
        return response.Response(
            {"secret": fer_key},
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
            return self._direct_login(
                request=request, user=user, token_data=serializer.validated_data[0]
            )

        except TokenError as e:
            raise InvalidToken(e.args[0]) from e


class MyTokenRefreshView(generics.GenericAPIView):
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
            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE")
        ) or request.data.get(settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE"))

        serializer = self.serializer_class(
            data={settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE"): refresh}
        )
        serializer.is_valid(raise_exception=True)
        resp = response.Response()
        self._set_cookie(resp=resp, serializer=serializer)
        resp.data = serializer.validated_data
        resp.status_code = status.HTTP_200_OK
        return resp


class LogoutView(views.APIView):
    """
    Calls Django logout method and delete the Token object
    assigned to the current User object.

    Accepts/Returns nothing.
    """

    permission_classes = (permissions.IsAuthenticated,)
    throttle_scope = "dj_rest_auth"

    def get(self, request, *args, **kwargs):
        if getattr(settings, "ACCOUNT_LOGOUT_ON_GET", False):
            resp = self._logout(request)
        else:
            resp = self.http_method_not_allowed(request, *args, **kwargs)

        return self.finalize_response(request, resp, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self._logout(request)

    @staticmethod
    def _logout(request):
        with contextlib.suppress(AttributeError, ObjectDoesNotExist):
            request.user.auth_token.delete()

        if settings.REST_AUTH.get("SESSION_LOGIN", False):
            logout(request)

        resp = response.Response(
            {"detail": "Successfully logged out."},
            status=status.HTTP_200_OK,
        )

        if settings.REST_AUTH.get("USE_JWT", True):
            cookie_name = settings.REST_AUTH.get("JWT_AUTH_COOKIE", "access")

            unset_jwt_cookies(resp)

            if "rest_framework_simplejwt.token_blacklist" in settings.INSTALLED_APPS:
                # add refresh token to blacklist
                try:
                    token = RefreshToken(
                        request.COOKIES.get(
                            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE")
                        )
                        or request.data.get(
                            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE")
                        )
                    )
                    token.blacklist()
                except KeyError:
                    resp.data = {
                        "detail": "Refresh token was not included in request data."
                    }
                    resp.status_code = status.HTTP_401_UNAUTHORIZED
                except (TokenError, AttributeError, TypeError) as error:
                    if hasattr(error, "args"):
                        if (
                            "Token is blacklisted" in error.args
                            or "Token is invalid or expired" in error.args
                        ):
                            resp.data = {"detail": error.args[0]}
                            resp.status_code = status.HTTP_401_UNAUTHORIZED
                        else:
                            resp.data = {"detail": "An error has occurred."}
                            resp.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

                    else:
                        resp.data = {"detail": "An error has occurred."}
                        resp.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

            elif not cookie_name:
                message = (
                    "Neither cookies or blacklist are enabled, so the token "
                    "has not been deleted server side. Please make sure the token is deleted client side.",
                )
                resp.data = {"detail": message}
                resp.status_code = status.HTTP_200_OK
        return resp


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

    @staticmethod
    def _otp_login(current_user, request):
        refresh = RefreshToken.for_user(current_user)
        refresh["email"] = current_user.email
        if settings.REST_AUTH.get("SESSION_LOGIN", False):
            login(request, current_user)
        resp = response.Response()

        set_jwt_cookies(
            response=resp,
            access_token=refresh.access_token,
            refresh_token=refresh,
        )

        resp.data = {
            settings.REST_AUTH.get("JWT_AUTH_REFRESH_COOKIE"): str(refresh),
            settings.REST_AUTH.get("JWT_AUTH_COOKIE"): str(refresh.access_token),
        }
        resp.status_code = status.HTTP_200_OK
        return resp

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        secret = serializer.validated_data.get("secret")
        otp = serializer.validated_data.get("otp")
        decrypted = helper.decrypt(str(secret))
        try:
            data = helper.decode_token(token=decrypted)
            current_user = models.User.objects.get(id=data["user_id"])
            current_user_key = helper.decrypt(str(current_user.user_otp.key))
            print(current_user_key)
            totp = pyotp.TOTP(current_user_key)
            print(totp.now())
            if totp.verify(otp):
                return self._otp_login(current_user=current_user, request=request)
            else:
                raise exceptions.NotAcceptable(detail="OTP is Wrong or Expired!!!")
        except DecodeError as e:
            raise InvalidToken(detail="Wrong Secret") from e


class OTPCheckView(views.APIView):
    """
    Check if OTP is active for user or not
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.OTPCheckSerializer

    def get(self, request, *args, **kwargs):
        try:
            user_otp = generics.get_object_or_404(
                models.OTPModel, user=self.request.user
            )
            serializer = self.serializer_class(user_otp)
            return response.Response(
                {
                    "detail": serializer.data.get("is_active"),
                }
            )
        except Exception as e:
            raise exceptions.APIException from e


class QRCreateView(views.APIView):
    """
    Get method for QR Create
    Post method for QR verify
    Delete method for Disabling OTP
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.QRCreateSerializer

    @staticmethod
    def _clear_user_otp(user_otp):
        user_otp.key = ""
        user_otp.is_active = False
        user_otp.save()

    def get(self, request, *args, **kwargs):
        generated_key = pyotp.random_base32()
        current_user = self.request.user
        qr_key = pyotp.totp.TOTP(generated_key).provisioning_uri(
            name=current_user.email, issuer_name=settings.PROJECT_NAME
        )
        return response.Response(
            {"qr_key": qr_key, "generated_key": generated_key},
            status=status.HTTP_200_OK,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        generated_key = serializer.validated_data.get("generated_key")
        otp = serializer.validated_data.get("otp")
        current_user = self.request.user
        user_otp = models.OTPModel.objects.get(user=current_user)

        totp = pyotp.TOTP(generated_key)
        if totp.verify(otp):
            user_otp.key = helper.encrypt(str(generated_key))
            user_otp.is_active = True
            user_otp.save()
            return response.Response(
                {"detail": "Accepted"},
                status=status.HTTP_200_OK,
            )
        else:
            print(totp.now())
            self._clear_user_otp(user_otp)
            raise exceptions.NotAcceptable(detail="OTP is Wrong or Expired!!!")

    def delete(self, request, *args, **kwargs):
        current_user = self.request.user
        user_otp = models.OTPModel.objects.get(user=current_user)
        self._clear_user_otp(user_otp)
        return response.Response({"message": "OTP Removed"})


# Password Related Views


class PasswordValidateView(views.APIView):
    """
    View for validating password
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.PasswordValidateSerializer

    def post(self, request, *args, **kwargs):
        current_user = self.request.user
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)

        if authenticate(
            request=request,
            username=current_user.email,
            password=serializer.validated_data.get("password"),
        ):
            return response.Response(
                {"message": "Password Accepted"}, status=status.HTTP_200_OK
            )
        return response.Response(
            {"message": "Wrong Password"},
            status=status.HTTP_406_NOT_ACCEPTABLE,
        )


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.ChangePasswordSerializer

    @staticmethod
    def _logout_on_password_change(request):
        resp = response.Response(
            {"detail": "Password updated successfully"},
            status=status.HTTP_200_OK,
        )
        if settings.REST_AUTH.get("SESSION_LOGIN", False):
            logout(request)
        unset_jwt_cookies(resp)
        return resp

    def _change_password(self, request, user, password):
        password_validation.validate_password(password=password, user=user)
        user.set_password(password)
        user.save()
        if settings.REST_AUTH.get("LOGOUT_ON_PASSWORD_CHANGE", True):
            self._logout_on_password_change(request=request)
        return response.Response(
            {"detail": "Password updated successfully"},
            status=status.HTTP_200_OK,
        )

    def update(self, request, *args, **kwargs):
        user = self.request.user
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Check old password
        old_password = serializer.validated_data.get("old_password")
        if not user.check_password(old_password):
            return response.Response(
                {"old_password": ["Wrong password."]},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        # set_password also hashes the password that the user will get
        password = serializer.validated_data.get("password")
        retype_password = serializer.validated_data.get("retype_password")

        if password != retype_password:
            raise exceptions.NotAcceptable(detail="Passwords do not match")
        try:
            self._change_password(
                request=request,
                user=user,
                password=password,
            )

        except ValidationError as e:
            return response.Response(
                {"detail": e},
                status=status.HTTP_403_FORBIDDEN,
            )


class ResetPasswordView(views.APIView):
    """
    View for getting email or sms for password reset
    post: username: ""
    """

    serializer_class = serializers.ResetPasswordSerializer
    authentication_classes = []
    permission_classes = []
    throttle_classes = (AnonUserRateThrottle,)

    @staticmethod
    def generate_link(*args):
        payload = {
            "user": str(args[0].id),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=30),
            "is_email": True,
        }

        return f"{args[1]}/auth/reset-password/{helper.encrypt(helper.encode_token(payload=payload))}/"

    def email_sender_helper(
        self, user, origin, organization_logo, attachment: BinaryIO = None
    ):
        url = self.generate_link(user, origin)
        context = {
            "url": url,
            "organization_logo": organization_logo,
        }
        # TODO Mail sender function called for later
        # task.send_mail_task.delay(
        #     subject=helper.encrypt("Forget Password"),
        #     body=helper.encrypt(f"To reset your password please click this link {url}"),
        #     html_message=helper.encrypt(
        #         render_to_string(template_name="forget_password.html", context=context)
        #     ),
        #     attachment=attachment.read() if attachment else None,
        #     attachment_name=attachment.name if attachment else None,
        #     from_email=helper.encrypt(settings.DEFAULT_FROM_EMAIL),
        #     recipient_list=(user.email,),
        #     # reply_to=("mail@gmail.com",),
        #     # cc=("mail1@gmail.com", "mail2@gmail.com"),
        #     # bcc=("mail3@gmail.com",),
        #     smtp_host=helper.encrypt(settings.EMAIL_HOST),
        #     smtp_port=helper.encrypt(settings.EMAIL_PORT),
        #     auth_user=helper.encrypt(settings.EMAIL_HOST_USER),
        #     auth_password=helper.encrypt(settings.EMAIL_HOST_PASSWORD),
        #     use_ssl=settings.EMAIL_USE_SSL,
        #     use_tls=settings.EMAIL_USE_TLS,
        #     already_encrypted=False,
        # )

        return response.Response({"detail": "Email Sent", "is_email": True})

    def post(self, *args, **kwargs):
        try:
            origin = self.request.headers["origin"]
        except Exception as e:
            raise exceptions.PermissionDenied() from e
        ser = self.serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)
        user = ser.user

        if user.email:
            organization_logo = (
                "https://nexisltd.com/_next/static/media/logo.396c4947.svg"
            )
            return self.email_sender_helper(user, origin, organization_logo)

        raise exceptions.PermissionDenied(
            detail="No Email found!!!",
        )


class ResetPasswordCheckView(views.APIView):
    """
    View for checking if the url is expired or not
    post: token: ""
    """

    authentication_classes = []
    permission_classes = []
    serializer_class = serializers.ResetPasswordCheckSerializer

    def post(self, *args, **kwargs):
        ser = self.serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)

        try:
            helper.decode_token(token=helper.decrypt(str(ser.data.get("token"))))

        except Exception as e:
            raise exceptions.APIException(detail=e) from e
        return response.Response({"data": "Accepted"})


class ResetPasswordConfirmView(views.APIView):
    """
    View for resetting password after checking the token
    post: token: "", password: ""
    """

    serializer_class = serializers.ResetPasswordConfirmSerializer
    authentication_classes = []
    permission_classes = []

    def post(self, *args, **kwargs):
        ser = self.serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)

        try:
            return self._change_password(ser)
        except Exception as e:
            raise exceptions.APIException(detail=e) from e

    @staticmethod
    def _change_password(ser):
        decoded = helper.decode_token(token=helper.decrypt(str(ser.data.get("token"))))

        if ser.validated_data.get("password") != ser.validated_data.get(
            "retype_password"
        ):
            raise exceptions.NotAcceptable(detail="Passwords doesn't match!!!")

        user = models.User.objects.get(id=decoded.get("user"))
        password_validation.validate_password(
            password=ser.data.get("password"), user=user
        )
        user.set_password(ser.data.get("password"))
        user.save()
        return response.Response({"detail": "Password Changed Successfully"})


# Profile Related Views
class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = serializers.UserSerializer
    queryset = models.User.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        return self.request.user
