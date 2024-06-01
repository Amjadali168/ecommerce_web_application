from django.shortcuts import render, redirect, HttpResponse
from django.contrib.auth.models import User
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from .utils import generate_token, TokenGenerator
from django.utils.encoding import force_bytes

# Create your views here.
def signup(request):
    if request.method=="POST":
        email=request.POST['email']
        password = request.POST['pass1']
        confirm_password = request.POST['pass2']
        if password != confirm_password :
            messages.warning(request,"password incorrect.")
            return render(request, 'signup.html')
        try:
            if User.objects.get(username=email):
                messages.warning(request,"email already exists.")
                return render(request, 'signup.html')
        except Exception as identifier:
            pass

        user = User.objects.create_user(email, email, password)
        user.save()
        email_subject = "Activate Your Account"
        message = render_to_string('activate.html',{
            'user':user,
            'domain':'127.0.0.1:800',
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),
            'token':generate_token.make_token(user)
        })
        return HttpResponse("User Created!!", email)
    return render(request, "signup.html")

def handlelogin(request):
    return render(request, "login.html")


def handlelogout(request):
    return redirect('/auth/login')
