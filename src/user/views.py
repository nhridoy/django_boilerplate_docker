import jwt
import pyotp
from dj_rest_auth.jwt_auth import (
    set_jwt_access_cookie,
    set_jwt_cookies,
    set_jwt_refresh_cookie,
    unset_jwt_cookies,
)
from django.conf import settings
from django.contrib.auth import login, logout, password_validation
from django.core.exceptions import ValidationError
from rest_framework import permissions  # noqa
from rest_framework import exceptions, generics, response, status, views
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from helper import helper
from user import models, serializers
from user.backends import EmailPhoneUsernameAuthenticationBackend as EPUA


class MyTokenObtainPairView(TokenObtainPairView):
    """
    JWT Custom Token Claims View
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
                settings.JWT_AUTH_COOKIE
            ),  # noqa
            refresh_token=serializer.validated_data.get(
                settings.JWT_AUTH_REFRESH_COOKIE
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
            user = EPUA.authenticate(
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

        if EPUA.authenticate(
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
        # resp.set_cookie(
        #     key=settings.JWT_AUTH_REFRESH_COOKIE,
        #     value=refresh,
        #     httponly=settings.JWT_AUTH_HTTPONLY,
        #     samesite=settings.JWT_AUTH_SAMESITE,
        #     expires=(
        #       timezone.now() + settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"]
        #     ),
        # )
        # resp.set_cookie(
        #     key=settings.JWT_AUTH_COOKIE,
        #     value=refresh.access_token,
        #     httponly=settings.JWT_AUTH_HTTPONLY,
        #     samesite=settings.JWT_AUTH_SAMESITE,
        #     expires=(
        #       timezone.now() + settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]
        #   ),
        # )
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
            # return response.Response(
            #     {
            #         settings.JWT_AUTH_REFRESH_COOKIE: str(refresh),
            #         settings.JWT_AUTH_COOKIE: str(refresh.access_token),
            #     },
            #     status=status.HTTP_200_OK,
            # )
        else:
            return response.Response(
                {"detail": "Wrong Token"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )


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
    """

    permission_classes = [permissions.IsAuthenticated]
    serializer_class = serializers.QRCreateSerializer

    def _clear_user_otp(self, user_otp):
        user_otp.key = ""
        user_otp.is_active = False
        user_otp.save()

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
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        generated_key = serializer.validated_data.get("generated_key")
        otp = serializer.validated_data.get("otp")
        current_user = self.request.user
        user_otp = models.OTPModel.objects.get(user=current_user)

        totp = pyotp.TOTP(generated_key)
        if totp.verify(otp):
            user_otp.key = helper.encode(str(generated_key)).decode()
            user_otp.is_active = True
            user_otp.save()
            return response.Response(
                {"detail": "Accepted"},
                status=status.HTTP_200_OK,
            )
        else:
            print(totp.now())
            self._clear_user_otp(user_otp)
            raise exceptions.NotAcceptable()
            # return response.Response(
            #     {"detail": "Not Accepted"},
            #     status=status.HTTP_406_NOT_ACCEPTABLE,
            # )

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
        user = request.data
        serializer = self.serializer_class(data=user)
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
