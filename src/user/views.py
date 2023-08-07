import datetime
import random

import jwt
import pyotp
from dj_rest_auth.jwt_auth import (
    set_jwt_access_cookie,
    set_jwt_cookies,
    set_jwt_refresh_cookie,
    unset_jwt_cookies,
)
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, password_validation  # noqa
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.template.loader import render_to_string
from rest_framework import (  # noqa
    exceptions,
    generics,
    permissions,
    response,
    status,
    views,
)
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from helper import helper
from helper.mail import mail_sender
from user import models, serializers


class MyTokenObtainPairView(TokenObtainPairView):
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

    serializer_class = serializers.MyTokenObtainPairSerializer

    @staticmethod
    def _direct_login(request, user, serializer):
        """
        Method for login without OTP
        """
        if settings.REST_SESSION_LOGIN:
            login(request, user)
        resp = response.Response()
        # resp.set_cookie(
        #     key=settings.JWT_AUTH_REFRESH_COOKIE,
        #     value=serializer.validated_data[settings.JWT_AUTH_REFRESH_COOKIE],
        #     httponly=settings.JWT_AUTH_HTTPONLY,
        #     samesite=settings.JWT_AUTH_SAMESITE,
        #     expires=(
        #        timezone.now() + settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]
        #   ),
        # )
        # resp.set_cookie(
        #     key=settings.JWT_AUTH_COOKIE,
        #     value=serializer.validated_data[settings.JWT_AUTH_COOKIE],
        #     httponly=settings.JWT_AUTH_HTTPONLY,
        #     samesite=settings.JWT_AUTH_SAMESITE,
        #     expires=(
        #       timezone.now() + settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]
        #   ),
        # )
        set_jwt_cookies(
            response=resp,
            access_token=serializer.validated_data.get(
                settings.JWT_AUTH_COOKIE,
            ),
            refresh_token=serializer.validated_data.get(
                settings.JWT_AUTH_REFRESH_COOKIE,
            ),
        )
        resp.data = serializer.validated_data
        resp.status_code = status.HTTP_200_OK
        return resp

    @staticmethod
    def _otp_login(user):
        """
        Method for returning secret key if OTP is active for user
        """
        refresh_token = RefreshToken.for_user(user)
        fer_key = helper.encode(str(refresh_token))
        return response.Response(
            {"secret": fer_key},
            status=status.HTTP_202_ACCEPTED,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = authenticate(
                request=request,
                username=request.data.get("username"),
                password=request.data.get("password"),
            )
            # user = models.User.objects.get(email=request.data["email"])
            try:
                otp = generics.get_object_or_404(models.OTPModel, user=user)
                if otp.is_active:
                    return self._otp_login(user=user)
                return self._direct_login(
                    request=request, user=user, serializer=serializer
                )

            except TokenError as e:
                raise InvalidToken(e.args[0]) from e
        except Exception:
            return response.Response(
                serializer.validated_data, status=status.HTTP_200_OK
            )


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
        if settings.REST_SESSION_LOGIN:
            logout(request)
        unset_jwt_cookies(resp)
        return resp

    def _change_password(self, request, user, password):
        password_validation.validate_password(password=password, user=user)
        user.set_password(password)
        user.save()
        if settings.LOGOUT_ON_PASSWORD_CHANGE:
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
        if settings.REST_SESSION_LOGIN:
            login(request, current_user)
        resp = response.Response()

        set_jwt_cookies(
            response=resp,
            access_token=refresh.access_token,
            refresh_token=refresh,
        )

        resp.data = {
            settings.JWT_AUTH_REFRESH_COOKIE: str(refresh),
            settings.JWT_AUTH_COOKIE: str(refresh.access_token),
        }
        resp.status_code = status.HTTP_200_OK
        return resp

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        secret = serializer.validated_data.get("secret")
        otp = serializer.validated_data.get("otp")
        decrypted = helper.decode(str(secret))
        data = jwt.decode(
            jwt=decrypted,
            key=settings.SECRET_KEY,
            algorithms=settings.SIMPLE_JWT["ALGORITHM"],
        )
        current_user = models.User.objects.get(id=data["user_id"])
        current_user_key = helper.decode(str(current_user.user_otp.key))
        print(current_user_key)
        totp = pyotp.TOTP(current_user_key)
        print(totp.now())
        if totp.verify(otp):
            return self._otp_login(current_user=current_user, request=request)
        else:
            raise exceptions.NotAcceptable(detail="OTP is Wrong or Expired!!!")


class MyTokenRefreshView(generics.GenericAPIView):
    """
    View for get new access token for a valid refresh token
    """

    serializer_class = serializers.TokenRefreshSerializer

    @staticmethod
    def _set_cookie(resp, serializer):
        if refresh := serializer.validated_data.get(
            settings.JWT_AUTH_REFRESH_COOKIE
        ):  # noqa
            set_jwt_refresh_cookie(
                response=resp,
                refresh_token=refresh,
            )
        set_jwt_access_cookie(
            response=resp,
            access_token=serializer.validated_data.get(
                settings.JWT_AUTH_COOKIE
            ),  # noqa
        )

    def post(self, request, *args, **kwargs):
        refresh = request.COOKIES.get(
            settings.JWT_AUTH_REFRESH_COOKIE
        ) or request.data.get(settings.JWT_AUTH_REFRESH_COOKIE)

        serializer = self.serializer_class(
            data={settings.JWT_AUTH_REFRESH_COOKIE: refresh}
        )
        serializer.is_valid(raise_exception=True)
        resp = response.Response()
        self._set_cookie(resp=resp, serializer=serializer)
        resp.data = serializer.validated_data
        resp.status_code = status.HTTP_200_OK
        return resp


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
            user_otp.key = helper.encode(str(generated_key))
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


class NewUserView(generics.ListCreateAPIView):
    """
    New User Create View
    """

    serializer_class = serializers.NewUserSerializer
    queryset = models.User.objects.all()
    permission_classes = []
    authentication_classes = []

    # permission_classes = [apipermissions.IsSuperUser]

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_user = serializer.save()
        user_data = serializer.data
        tokens = RefreshToken.for_user(new_user)
        refresh = str(tokens)
        access = str(tokens.access_token)

        return response.Response(
            {
                "user_data": user_data,
                "refresh_token": refresh,
                "access_token": access,
            },
            status=status.HTTP_201_CREATED,
        )


class ResetPasswordView(views.APIView):
    """
    View for getting email or sms for password reset
    post: username: ""
    """

    serializer_class = serializers.ResetPasswordSerializer
    authentication_classes = []
    permission_classes = []

    @staticmethod
    def generate_link(*args):
        payload = {
            "user": str(args[0].id),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=30),
            "is_email": True,
        }

        return f"{args[1]}/auth/reset-password/{helper.encode(helper.create_token(payload=payload))}/"

    def email_sender_helper(
        self,
        user,
        origin,
        organization_logo,
    ):
        context = {
            "url": self.generate_link(user, origin),
            "organization_logo": organization_logo,
        }
        mail_sender(
            subject="Forgot Password",
            body=f"To reset your password please click this link {self.generate_link(user, origin)}",
            html_message=render_to_string(template_name="email.html", context=context),
            # attachment=files,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=(user.email,),
            # reply_to=("mail@gmail.com",),
            # cc=("mail1@gmail.com", "mail2@gmail.com"),
            # bcc=("mail3@gmail.com",),
            smtp_host=settings.EMAIL_HOST,
            smtp_port=settings.EMAIL_PORT,
            auth_user=settings.EMAIL_HOST_USER,
            auth_password=settings.EMAIL_HOST_PASSWORD,
            use_ssl=settings.EMAIL_USE_SSL,
            use_tls=settings.EMAIL_USE_TLS,
        )

        # task.send_mail_task.delay(
        #     subject="Reset Password",
        #     to_mail=user.email,
        #     from_mail=settings.DEFAULT_FROM_EMAIL,
        #     html_msg="password-reset-link.html",
        #     txt_msg="password-reset-link.txt",
        #     context=context,
        #     plain_msg=None,
        # )
        return response.Response({"detail": "Email Sent", "is_email": True})

    def post(self, *args, **kwargs):
        try:
            origin = self.request.headers["origin"]
        except Exception as e:
            raise exceptions.PermissionDenied() from e
        ser = self.serializer_class(data=self.request.data)
        ser.is_valid(raise_exception=True)

        user = models.User.objects.get(
            Q(email=ser.validated_data.get("username"))
            | Q(username=ser.validated_data.get("username"))
        )

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
            data = jwt.decode(
                jwt=helper.decode(str(ser.data.get("token"))),
                key=settings.SECRET_KEY,
                algorithms="HS256",
            )

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
        decoded = jwt.decode(
            jwt=helper.decode(str(ser.data.get("token"))),
            key=settings.SECRET_KEY,
            algorithms="HS256",
        )

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
