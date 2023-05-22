from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required


def home(request):
    return HttpResponse("welcome to HomePage")


@login_required(login_url='login')
def index(request):
    return render(request, "myApp/index.html")
