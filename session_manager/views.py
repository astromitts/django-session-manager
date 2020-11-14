from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout, REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.shortcuts import render, redirect, resolve_url
from django.template import loader
from django.views import View
from django.urls import reverse

from urllib.parse import urlparse

from session_manager.forms import CreateUserForm, LoginUserForm
from session_manager.models import SessionManager


class AuthenticatedView(View):
    """ Base class thay boots you from a view if you are not logged in
        also does some other variable assignments that are commonly required

        Wow LoginRequiredMixin was not working at all so I had to copy a bunch of it here :\
    """
    login_url = '/login/'
    permission_denied_message = 'Login required'
    raise_exception = False
    redirect_field_name = REDIRECT_FIELD_NAME

    def get_login_url(self):
        """
        Override this method to override the login_url attribute.
        """
        login_url = self.login_url or settings.LOGIN_URL
        if not login_url:
            raise ImproperlyConfigured(
                '{0} is missing the login_url attribute. Define {0}.login_url, settings.LOGIN_URL, or override '
                '{0}.get_login_url().'.format(self.__class__.__name__)
            )
        return str(login_url)


    def get_redirect_field_name(self):
        """
        Override this method to override the redirect_field_name attribute.
        """
        return self.redirect_field_name

    def handle_no_permission(self):
        if self.raise_exception or self.request.user.is_authenticated:
            raise PermissionDenied(self.permission_denied_message)

        path = self.request.build_absolute_uri()
        resolved_login_url = resolve_url(self.get_login_url())
        # If the login url is the same scheme and net location then use the
        # path as the "next" url.
        login_scheme, login_netloc = urlparse(resolved_login_url)[:2]
        current_scheme, current_netloc = urlparse(path)[:2]
        if (
            (not login_scheme or login_scheme == current_scheme) and
            (not login_netloc or login_netloc == current_netloc)
        ):
            path = self.request.get_full_path()
            return redirect_to_login(
                path,
                resolved_login_url,
                self.get_redirect_field_name(),
            )

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)

    def setup(self, request, *args, **kwargs):
        super(AuthenticatedView, self).setup(request, *args, **kwargs)

        if not request.user.is_authenticated:
            return self.handle_no_permission()
        try:
            self.appuser = User.objects.get(email=request.user.email)
        except ValueError:
            return self.handle_no_permission()


class CreateUserView(View):
    def setup(self, request, *args, **kwargs):
        super(CreateUserView, self).setup(request, *args, **kwargs)
        self.template = loader.get_template('session_manager/register.html')
        self.context = {}

    def get(self, request, *args, **kwargs):
        form = CreateUserForm()
        self.context.update({
            'form': form,
        })
        return HttpResponse(self.template.render(self.context, request))

    def post(self, request, *args, **kwargs):
        form = CreateUserForm(request.POST)
        if form.is_valid:
            if SessionManager.user_exists(email=request.POST['email']):
                messages.error(request, 'A user with this email address already exists.')
                self.context.update({
                    'form': form,
                })
                return HttpResponse(self.template.render(self.context, request))
            else:
                user = SessionManager.create_user(
                    email=request.POST['email'],
                    username=request.POST['username'],
                    password=request.POST['password']
                )
                messages.success(request, 'Registration complete! Please log in to continue.')
                return redirect(reverse('session_manager_login'))
        else:
            self.context.update({
                'form': form,
            })
            return HttpResponse(self.template.render(self.context, request))


class LoginUserView(View):
    def setup(self, request, *args, **kwargs):
        super(LoginUserView, self).setup(request, *args, **kwargs)
        self.template = loader.get_template('session_manager/login.html')
        self.context = {}

    def get(self, request, *args, **kwargs):
        form = LoginUserForm()
        self.context.update({
            'form': form,
        })
        return HttpResponse(self.template.render(self.context, request))

    def post(self, request, *args, **kwargs):
        form = LoginUserForm(request.POST)
        if form.is_valid:
            user, error_reason = SessionManager.check_user_login(
                email=request.POST['email'],
                password=request.POST['password']
            )
            if not user:
                messages.error(request, error_reason)
                self.context.update({
                    'form': form,
                })
                return HttpResponse(self.template.render(self.context, request))
            else:
                login(request, user)
                return redirect(reverse(settings.LOGIN_SUCCESS_REDIRECT))
        else:
            messages.error(request, 'Something went wrong. Please correct errors below.')
            self.context.update({
                'form': form,
            })
            return HttpResponse(self.template.render(self.context, request))


class LogOutUserView(View):
    def get(self, request, *args, **kwargs):
        logout(request)
        messages.success(request, 'Logged out.')
        return redirect(reverse('session_manager_login'))


class Index(AuthenticatedView):
    def get(self, request, *args, **kwargs):
        template = loader.get_template('session_manager/index.html')
        return HttpResponse(template.render({}, request))


