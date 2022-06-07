from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView
)
from user import views

urlpatterns = [
    path('token/', views.MyTokenObtainPairView.as_view()),
    path('otp/', views.OTPView.as_view()),
    path('qr-create/', views.QRCreateView.as_view()),
    path('token/refresh/', TokenRefreshView.as_view()),
    path('token/verify/', TokenVerifyView.as_view()),
    path('create_user/', views.NewUserView.as_view()),
]