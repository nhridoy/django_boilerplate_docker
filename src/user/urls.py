from dj_rest_auth.views import LogoutView
from django.urls import path
from rest_framework_simplejwt.views import TokenVerifyView

from user import views

urlpatterns = []

login_urlpatterns = [
    path("login/", views.LoginView.as_view()),
    path("logout/", LogoutView.as_view()),
    path("otp-login/", views.OTPLoginView.as_view()),
    path("otp-check/", views.OTPCheckView.as_view()),
    path("qr-create/", views.OTPCreateView.as_view()),
    path("token/refresh/", views.TokenRefreshView.as_view()),
    path("token/verify/", TokenVerifyView.as_view()),
]

password_urlpatterns = [
    path("password-validate/", views.PasswordValidateView.as_view()),
    path("change-password/", views.ChangePasswordView.as_view()),
    path("password-reset/", views.ResetPasswordView.as_view()),
    path("password-reset-check/", views.ResetPasswordCheckView.as_view()),
    path("password-reset-confirm/", views.ResetPasswordConfirmView.as_view()),
]

signup_urlpatterns = [
    path(
        "registration/",
        views.NewUserView.as_view(
            {
                "post": "create",
            }
        ),
    ),
    path(
        "resend-verification-email/",
        views.NewUserView.as_view(
            {
                "post": "resend_email",
            }
        ),
    ),
    path(
        "verify-email/<str:token>/",
        views.NewUserView.as_view(
            {
                "get": "verify_email",
            }
        ),
    ),
]

user_urlpatterns = [
    path(
        "user/",
        views.UserProfileView.as_view(),
        name="user-retrieve-update-api",
    ),
]

urlpatterns += login_urlpatterns
urlpatterns += password_urlpatterns
urlpatterns += signup_urlpatterns
urlpatterns += user_urlpatterns
