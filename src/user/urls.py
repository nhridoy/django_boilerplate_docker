from django.urls import path
from rest_framework_simplejwt.views import TokenVerifyView

from user import views

urlpatterns = [
    path("login/", views.MyTokenObtainPairView.as_view()),
    path("otp-login/", views.OTPLoginView.as_view()),
    path("otp-check/", views.OTPCheckView.as_view()),
    path("password-validate/", views.PasswordValidateView.as_view()),
    path("change-password/", views.ChangePasswordView.as_view()),
    path("qr-create/", views.QRCreateView.as_view()),
    path("token/refresh/", views.MyTokenRefreshView.as_view()),
    path("token/verify/", TokenVerifyView.as_view()),
    # path('registration/', views.NewUserView.as_view()),
]
