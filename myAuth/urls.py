from django.urls import path
from .views import (
    logup,
    user_login,
    user_logout,
    ActivateAccountView,
    RequestResetEmail,
    SetNewPassword,
)


urlpatterns = [
    path("logup/", logup, name="logup"),
    path("login/", user_login, name="login"),
    path("logout/", user_logout, name="logout"),
    path("activate/<uidb64>/<token>/", ActivateAccountView.as_view(), name="activate"),
    path("reset/", RequestResetEmail.as_view(), name="reset"),
    path("reset/<uidb64>/<token>", SetNewPassword.as_view(), name="set_new_password"),
]
