from django.shortcuts import render, HttpResponse, redirect
from django.contrib.auth.models import User
from django.views.generic import View
from django.contrib.auth import authenticate, login, logout as auth_logout, logout
from django.contrib import messages

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import NoReverseMatch
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError

from django.contrib.auth.tokens import PasswordResetTokenGenerator

import threading

from django.core.mail import send_mail, EmailMultiAlternatives, EmailMessage
from django.core.mail import BadHeaderError, send_mail
from django.core import mail, exceptions
from django.conf import settings
from .utils import generate_token


class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        threading.Thread.__init__(self)

    def run(self):
        self.email_message.send()


def logup(request):
    if request.method == "POST":
        first_name = request.POST["inputFirstName"]
        last_name = request.POST["inputLastName"]
        email = request.POST["inputEmail"]
        password = request.POST["inputPassword"]
        confirm_password = request.POST["inputConfirmPassword"]
        if password != confirm_password:
            messages.warning(request, "Password Doesn't Match...!!!")
            return render(request, "myAuth/logup.html")
        try:
            if User.objects.get(username=email):
                messages.warning(
                    request,
                    "Email is already registered. Please try with another email !!!",
                )
                return render(request, "myAuth/logup.html")
        except Exception as identifier:
            pass
        user = User.objects.create_user(email, email, password)
        user.first_name = first_name
        user.last_name = last_name

        user.is_active = False

        user.save()
        current_site = get_current_site(request)
        email_subject = "Activate Your Account"
        message = render_to_string(
            "myAuth/activate.html",
            {
                "user": user,
                "domain": "http://127.0.0.1:8000",
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "token": generate_token.make_token(user),
            },
        )

        email_message = EmailMessage(
            email_subject, message, settings.EMAIL_HOST_USER, [email]
        )
        EmailThread(email_message).start()

        messages.info(request, "Activate your account by clicking link given below...!")

        return redirect("login")
    return render(request, "myAuth/logup.html")


def user_login(request):
    if request.method == "POST":
        username = request.POST["inputEmail"]
        userpass = request.POST["inputPassword"]
        user = authenticate(username=username, password=userpass)

        if user is not None:
            login(request, user)
            messages.success(request, "login success")
            return render(request, "myApp/index.html")

        else:
            messages.error(request, "something went wrong")
            return redirect("login")
    return render(request, "myAuth/login.html")


def user_logout(request):
    logout(request)
    messages.success(request, "Logged out successfully...!")
    return redirect("/auth/login/")


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        print(f"uidb64: {uidb64}")
        print(f"token: {token}")
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            print(f"uid: {uid}")
            user = User.objects.get(pk=uid)
            print(f"user: {user}")
        except Exception as identifier:
            user = None
        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.success(request, "Account activated successfully")
            return redirect("/auth/login/")
        return render(request, "myAuth/activatefail.html")


class RequestResetEmail(View):
    def get(self, request):
        return render(request, "myAuth/reset_password.html")

    def post(self, request):
        email = request.POST['email']
        user = User.objects.filter(email=email)

        if user.exists():
            current_site = get_current_site(request)
            email_subject = "[Reset Your Password]"
            message = render_to_string(
                "myAuth/reset_user_password.html",
                {
                    "domain": "127.0.0.1:8000",
                    "uid": urlsafe_base64_encode(force_bytes(user[0].pk)),
                    "token": PasswordResetTokenGenerator().make_token(user[0]),
                }
            )
            email_message = EmailMessage(
                email_subject, message, settings.EMAIL_HOST_USER, [email]
            )

            EmailThread(email_message).start()

            messages.info(request, "We have sent an email to reset your password...!")
            return render(request, "myAuth/reset_password.html")


class SetNewPassword(View):
    def get(self, request, uidb64, token):
        context={
            'uidb64': uidb64,
            'token': token,
        }

        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.warning(request, "Password Reset Link is Invalid....!")
                return render(request, 'myAuth/reset_password.html')
        except DjangoUnicodeDecodeError as identifier:
            pass
        return render(request, 'myAuth/set_new_password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
        }
        password = request.POST["pass1"]
        confirm_password = request.POST["pass2"]
        if password != confirm_password:
            messages.warning(request, "Password Doesn't Match...!!!")
            return render(request, "myAuth/reset_password.html", context)

        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()
            messages.success(request, "Password Reset Success Please Login With New Password")
            return redirect('/auth/login/')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, "something went wrong...!")
            return render(request, 'auth/set_new_password.html', context)
