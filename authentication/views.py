from django.contrib.auth import authenticate, login, logout
from django.views.decorators.http import require_http_methods, require_GET, require_POST

from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from ac import settings
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
import logging
from .tokens import generate_token
from django.core.mail import EmailMessage

# Get an instance of a logger
logger = logging.getLogger(__name__)

def home(request):
    return render(request, 'authentication/index.html')

def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass1')
        pass2 = request.POST.get('pass2')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists')
            return redirect('home')

        if len(username) > 10:
            messages.error(request, 'Username too long')
            return redirect('home')

        if pass1 != pass2:
            messages.error(request, 'Passwords do not match')
            return redirect('home')

        if not username.isalnum():
            messages.error(request, 'Username must be alphanumeric')
            return redirect('home')

        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        messages.success(request, "Account was created for " + username + ". We have sent you a confirmation email. Please click to activate your account.")

        subject = "Welcome to my email - Ayush's email"
        email_message = (
            "Hello " + myuser.first_name + "!!\n"
            "Just keep going with your work and never forget who you are and to whom "
            "you have been admired and nurtured and powered and believe me, just believe me "
            "I am here for you and the universe is here for you so just keep going and never ever "
            "doubt yourself and don't you worry about anything."
        )
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]

        try:
            send_mail(subject, email_message, from_email, to_list, fail_silently=False)
        except Exception as e:
            logger.error(f'Error sending email: {e}')
            messages.error(request, 'There was an error sending the confirmation email. Please try again later.')

        current_site = get_current_site(request)
        email_subject = "Confirm your email at my website"
        message2 = render_to_string('email_confirmation.html', {
            'name': myuser.first_name,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token': generate_token.make_token(myuser),
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
            #fail_silently=False,
        )
        email.send()

        return redirect('signin')

    return render(request, 'authentication/signup.html')

def signin(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        pass1 = request.POST.get('pass1')

        user = authenticate(username=username, password=pass1)

        if user is not None:
            messages.success(request, 'You are successfully logged in')

            login(request, user)
            fname = user.first_name
            return render(request, 'authentication/index.html', {'fname': fname})

        else:
            messages.error(request, 'Username OR password is incorrect')
            return redirect('home')

    return render(request, 'authentication/signin.html')

def signout(request):
    logout(request)
    messages.success(request, "Successfully logged out")
    return redirect('home')

def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser, token):
        myuser.is_active = True
        myuser.save()
        messages.success(request, 'Your account has been activated successfully')
        login(request, myuser)
        return redirect('home')
    else:
        messages.error(request, 'Activation failed')
        return render(request, 'activation_failed.html')
