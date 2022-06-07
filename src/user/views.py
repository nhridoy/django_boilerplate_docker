import pyotp
from django.contrib.auth.hashers import make_password
from django.conf import settings
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.views import TokenObtainPairView
from user import models, serializers, apipermissions
from rest_framework import generics, status, response, permissions, views
import string, random, jwt
from cryptography.fernet import Fernet


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    JWT Custom Token Claims Serializer
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['name'] = user.full_name
        token['email'] = user.email
        token['is_superuser'] = user.is_superuser
        token['is_staff'] = user.is_staff

        return token


class MyTokenObtainPairView(TokenObtainPairView):
    """
    JWT Custom Token Claims View
    """
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        user = models.User.objects.get(email=request.data['email'])
        try:
            serializer.is_valid(raise_exception=True)
            otp = models.OTPModel.objects.get(user=user)
            if not otp.is_active:
                return response.Response(serializer.validated_data, status=status.HTTP_200_OK)
            else:
                key = bytes(settings.SECRET_KEY, 'utf-8')
                refresh_token = RefreshToken.for_user(user)

                fer_key = Fernet(key).encrypt(bytes(str(refresh_token), 'utf-8'))

                return response.Response({'secret': fer_key}, status=status.HTTP_202_ACCEPTED)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        # return response.Response(serializer.validated_data, status=status.HTTP_200_OK)


class OTPView(views.APIView):
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        key = bytes(settings.SECRET_KEY, 'utf-8')
        secret = bytes(self.request.data['secret'], 'utf-8')
        otp = self.request.data['otp']
        decrypted = Fernet(key).decrypt(secret).decode('utf-8')

        data = jwt.decode(decrypted, settings.SECRET_KEY, settings.SIMPLE_JWT['ALGORITHM'])

        current_user = models.User.objects.get(id=data['user_id'])
        totp = pyotp.TOTP(current_user.user_otp.key)

        print(totp.now())
        if totp.verify(otp):
            refresh = RefreshToken.for_user(current_user)
            refresh['email'] = current_user.email
            return response.Response({'refresh': str(refresh), 'access': str(refresh.access_token)},
                                     status=status.HTTP_200_OK)
        else:
            return response.Response({'message': 'Wrong Token'}, status=status.HTTP_406_NOT_ACCEPTABLE)


class QRCreateView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        generated_key = pyotp.random_base32()
        current_user = self.request.user
        qr_key = pyotp.totp.TOTP(generated_key).provisioning_uri(name=current_user.email, issuer_name='Nexis Limited')
        return response.Response({'qr_key': qr_key, 'generated_key': generated_key}, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        qr_key = self.request.data['qr_key']
        generated_key = self.request.data['generated_key']
        otp = self.request.data['otp']
        current_user = self.request.user
        user_otp = models.OTPModel.objects.get(user=current_user)

        totp = pyotp.TOTP(generated_key)
        if totp.verify(otp):
            user_otp.key = generated_key
            user_otp.otp_qr = qr_key
            user_otp.save()
            return response.Response({"message": 'Accepted'}, status=status.HTTP_200_OK)
        else:
            user_otp.key = ''
            user_otp.otp_qr = ''
            user_otp.save()
            return response.Response({'message': totp.now()}, status=status.HTTP_406_NOT_ACCEPTABLE)


class NewUserView(generics.ListCreateAPIView):
    """
    New User Create View
    """
    serializer_class = serializers.NewUserSerializer
    queryset = models.User.objects.all()

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

        return response.Response({'user_data': user_data, 'refresh_token': refresh, 'access_token': access},
                                 status=status.HTTP_201_CREATED)
