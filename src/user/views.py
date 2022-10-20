import contextlib

import jwt
import pyotp
from cryptography.fernet import Fernet
from dj_rest_auth.jwt_auth import set_jwt_cookies, unset_jwt_cookies
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, password_validation
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework import exceptions, generics, permissions, response, status, views
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from user import apipermissions, backends, models, serializers
from user.backends import EmailPhoneUsernameAuthenticationBackend as EoP


class MyTokenObtainPairView(TokenObtainPairView):
    """
    JWT Custom Token Claims View
    """

    serializer_class = serializers.MyTokenObtainPairSerializer

    @staticmethod
    def direct_login(request, user, serializer):
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
        #     expires=(timezone.now() + settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]),
        # )
        # resp.set_cookie(
        #     key=settings.JWT_AUTH_COOKIE,
        #     value=serializer.validated_data[settings.JWT_AUTH_COOKIE],
        #     httponly=settings.JWT_AUTH_HTTPONLY,
        #     samesite=settings.JWT_AUTH_SAMESITE,
        #     expires=(timezone.now() + settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]),
        # )
        set_jwt_cookies(
            response=resp,
            access_token=serializer.validated_data[settings.JWT_AUTH_COOKIE],
            refresh_token=serializer.validated_data[settings.JWT_AUTH_REFRESH_COOKIE],
        )
        resp.data = serializer.validated_data
        resp.status_code = status.HTTP_200_OK
        return resp

    @staticmethod
    def otp_login(user):
        """
        Method for returning secret key if OTP is active for user
        """
        key = bytes(settings.SECRET_KEY, "utf-8")
        refresh_token = RefreshToken.for_user(user)

        fer_key = Fernet(key).encrypt(bytes(str(refresh_token), "utf-8"))

        return response.Response({"secret": fer_key}, status=status.HTTP_202_ACCEPTED)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        user = models.User.objects.get(email=request.data["email"])
        try:
            serializer.is_valid(raise_exception=True)
            otp = models.OTPModel.objects.get(user=user)
            if otp.is_active:
                return self.otp_login(user=user)
            return self.direct_login(request=request, user=user, serializer=serializer)

        except TokenError as e:
            raise InvalidToken(e.args[0]) from e
        # try:
        #     user = backends.EmailPhoneUsernameAuthenticationBackend.authenticate(
        #         request=request,
        #         username=request.data.get("username"),
        #         password=request.data.get("password"),
        #     )
        #     # user = models.User.objects.get(email=request.data["email"])
        #     try:
        #         serializer.is_valid(raise_exception=True)
        #         otp = models.OTPModel.objects.get(user=user)
        #         if otp.is_active:
        #             return self.otp_login(user=user)
        #         return self.direct_login(
        #             request=request, user=user, serializer=serializer
        #         )

        #     except TokenError as e:
        #         raise InvalidToken(e.args[0]) from e
        # except Exception as e:
        #     serializer.is_valid(raise_exception=True)
        #     return response.Response(
        #         serializer.validated_data, status=status.HTTP_200_OK
        #     )


class PasswordValidateView(views.APIView):
    """
    View for validating password
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        current_user = self.request.user
        password = self.request.data["password"]
        if user := authenticate(username=current_user.email, password=password):
            return response.Response(
                {"message": "Password Accepted"}, status=status.HTTP_200_OK
            )
        return response.Response(
            {"message": "Wrong Password"}, status=status.HTTP_406_NOT_ACCEPTABLE
        )


class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """

    serializer_class = serializers.ChangePasswordSerializer
    model = models.User
    permission_classes = [permissions.IsAuthenticated]

    @staticmethod
    def logout_on_password_change(request):
        resp = response.Response(
            {"detail": "Password updated successfully"}, status=status.HTTP_200_OK
        )
        if settings.REST_SESSION_LOGIN:
            logout(request)
        unset_jwt_cookies(resp)
        return resp

    def get_object(self, queryset=None):
        return self.request.user

    def update(self, request, *args, **kwargs):
        obj = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not obj.check_password(serializer.data.get("old_password")):
                return response.Response(
                    {"old_password": ["Wrong password."]},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            # set_password also hashes the password that the user will get
            password = serializer.data.get("password")
            retype_password = serializer.data.get("retype_password")

            if password != retype_password:
                raise exceptions.NotAcceptable(detail="Passwords do not match")
            try:
                password_validation.validate_password(
                    password=password, user=self.request.user
                )
                obj.set_password(password)
                obj.save()

                return (
                    self.logout_on_password_change(request=request)
                    if settings.LOGOUT_ON_PASSWORD_CHANGE
                    else response.Response(
                        {"detail": "Password updated successfully"},
                        status=status.HTTP_200_OK,
                    )
                )

            except ValidationError as e:
                return response.Response(
                    {"detail": e}, status=status.HTTP_403_FORBIDDEN
                )
        raise exceptions.ValidationError(detail=serializer.errors)


class OTPLoginView(views.APIView):
    """
    View for Login with OTP
    """

    authentication_classes = []
    permission_classes = []
    serializer_class = serializers.OTPLoginSerializer

    @staticmethod
    def otp_login(current_user, request):
        refresh = RefreshToken.for_user(current_user)
        refresh["email"] = current_user.email
        if settings.REST_SESSION_LOGIN:
            login(request, current_user)
        resp = response.Response()
        # resp.set_cookie(
        #     key=settings.JWT_AUTH_REFRESH_COOKIE,
        #     value=refresh,
        #     httponly=settings.JWT_AUTH_HTTPONLY,
        #     samesite=settings.JWT_AUTH_SAMESITE,
        #     expires=(
        #             timezone.now() + settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]
        #     ),
        # )
        # resp.set_cookie(
        #     key=settings.JWT_AUTH_COOKIE,
        #     value=refresh.access_token,
        #     httponly=settings.JWT_AUTH_HTTPONLY,
        #     samesite=settings.JWT_AUTH_SAMESITE,
        #     expires=(timezone.now() + settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]),
        # )
        set_jwt_cookies(
            response=resp, access_token=refresh.access_token, refresh_token=refresh
        )

        resp.data = {
            settings.JWT_AUTH_REFRESH_COOKIE: str(refresh),
            settings.JWT_AUTH_COOKIE: str(refresh.access_token),
        }
        resp.status_code = status.HTTP_200_OK
        return resp

    def post(self, request, *args, **kwargs):
        ser = self.serializer_class(data=request.data)
        ser.is_valid(raise_exception=True)
        secret = bytes(ser.validated_data.get("secret"), "utf-8")
        otp = ser.validated_data.get("otp")
        key = bytes(settings.SECRET_KEY, "utf-8")
        decrypted = Fernet(key).decrypt(secret).decode("utf-8")

        data = jwt.decode(
            decrypted, settings.SECRET_KEY, settings.SIMPLE_JWT["ALGORITHM"]
        )

        current_user = models.User.objects.get(id=data["user_id"])
        current_user_key = (
            Fernet(key).decrypt(str(current_user.user_otp.key).encode()).decode()
        )
        print(current_user_key)
        totp = pyotp.TOTP(current_user_key)

        print(totp.now())
        if totp.verify(otp):
            return self.otp_login(current_user=current_user, request=request)
            # return response.Response({settings.JWT_AUTH_REFRESH_COOKIE: str(refresh), settings.JWT_AUTH_COOKIE: str(refresh.access_token)},
            #                          status=status.HTTP_200_OK)
        else:
            return response.Response(
                {"detail": "Wrong Token"}, status=status.HTTP_406_NOT_ACCEPTABLE
            )


class MyTokenRefreshView(generics.GenericAPIView):
    """
    View for get new access token for a valid refresh token
    """

    serializer_class = serializers.TokenRefreshSerializer

    def post(self, request, *args, **kwargs):
        ser = self.serializer_class(
            data={
                settings.JWT_AUTH_REFRESH_COOKIE: request.COOKIES.get(
                    settings.JWT_AUTH_REFRESH_COOKIE
                )
                or request.data.get(settings.JWT_AUTH_REFRESH_COOKIE)
            }
        )
        try:
            ser.is_valid(raise_exception=True)
            resp = response.Response()
            with contextlib.suppress(Exception):
                resp.set_cookie(
                    key=settings.JWT_AUTH_REFRESH_COOKIE,
                    value=ser.validated_data[settings.JWT_AUTH_REFRESH_COOKIE],
                    httponly=settings.JWT_AUTH_HTTPONLY or True,
                    samesite=settings.JWT_AUTH_SAMESITE or "Lax",
                    expires=(
                        timezone.now() + settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]
                    ),
                )
            resp.set_cookie(
                key=settings.JWT_AUTH_COOKIE,
                value=ser.validated_data[settings.JWT_AUTH_COOKIE],
                httponly=settings.JWT_AUTH_HTTPONLY or True,
                samesite=settings.JWT_AUTH_SAMESITE or "Lax",
                expires=(timezone.now() + settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]),
            )
            resp.data = ser.validated_data
            resp.status_code = status.HTTP_200_OK
            return resp
            # return response.Response(ser.validated_data)
        except Exception as e:
            raise exceptions.AuthenticationFailed(detail=e) from e


class OTPCheckView(views.APIView):
    """
    Check if OTP is active for user or not
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        try:
            user_otp = models.OTPModel.objects.filter(user=self.request.user).first()
            return response.Response({"detail": user_otp.is_active})
        except Exception as e:
            raise exceptions.APIException from e


class QRCreateView(views.APIView):
    """
    Get method for QR Create
    Post method for QR verify
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.QRCreateSerializer

    def get(self, request, *args, **kwargs):
        generated_key = pyotp.random_base32()
        current_user = self.request.user
        qr_key = pyotp.totp.TOTP(generated_key).provisioning_uri(
            name=current_user.email, issuer_name="Oxygen Django"
        )
        return response.Response(
            {"qr_key": qr_key, "generated_key": generated_key},
            status=status.HTTP_200_OK,
        )

    def post(self, request, *args, **kwargs):
        ser = self.serializer_class(data=request.data)
        ser.is_valid(raise_exception=True)
        generated_key = ser.validated_data.get("generated_key")
        otp = ser.validated_data.get("otp")
        current_user = self.request.user
        user_otp = models.OTPModel.objects.get(user=current_user)

        totp = pyotp.TOTP(generated_key)
        if totp.verify(otp):
            user_otp.key = (
                Fernet(str(settings.SECRET_KEY).encode())
                .encrypt(str(generated_key).encode("utf-8"))
                .decode()
            )
            user_otp.is_active = True
            user_otp.save()
            return response.Response({"detail": "Accepted"}, status=status.HTTP_200_OK)
        else:
            print(totp.now())
            user_otp.key = ""
            user_otp.is_active = False
            user_otp.save()
            raise exceptions.NotAcceptable()
            # return response.Response({'detail': 'Not Accepted'}, status=status.HTTP_406_NOT_ACCEPTABLE)

    def delete(self, request, *args, **kwargs):
        current_user = self.request.user
        user_otp = models.OTPModel.objects.get(user=current_user)
        user_otp.key = ""
        user_otp.is_active = False
        user_otp.save()
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
        user = request.data
        ser = self.serializer_class(data=user)
        ser.is_valid(raise_exception=True)
        new_user = ser.save()
        user_data = ser.data
        tokens = RefreshToken.for_user(new_user)
        refresh = str(tokens)
        access = str(tokens.access_token)

        return response.Response(
            {"user_data": user_data, "refresh_token": refresh, "access_token": access},
            status=status.HTTP_201_CREATED,
        )
