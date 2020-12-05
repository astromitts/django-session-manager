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

from session_manager.forms import CreateUserForm, LoginUserForm, ResetPasswordForm
from session_manager.models import SessionManager, UserToken


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


class CreateUserView(View):
    """ Views for a new user registration
    """
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
        if form.is_valid():
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
    """ Views for logging in an existing user, either via form post
        or token URL
    """
    def setup(self, request, *args, **kwargs):
        super(LoginUserView, self).setup(request, *args, **kwargs)
        self.template = loader.get_template('session_manager/login.html')
        self.context = {}

    def get(self, request, *args, **kwargs):
        # check if a login token was provided
        if request.GET.get('token') and request.GET.get('user'):
            token, token_error_message = UserToken.get_token(token=request.GET['token'], username=request.GET['user'], token_type='login')
            if token:
                if token.is_valid:
                    # a valid token/user combination was given, so log in and delete the token
                    login(request, token.user)
                    messages.success(request, 'Log in successful.')
                    token.delete()
                    request.session['user_is_authenticated'] = True
                    return redirect(reverse(settings.LOGIN_SUCCESS_REDIRECT))
                else:
                    # provided token was found, but it is expired
                    # clean up the token
                    token.delete()
                    messages.error(request, 'Token is expired.')
            else:
                # no matching token was found for provided user/token
                messages.error(request, token_error_message)

        # no token was provided, or it was invalid, so just render the login form
        form = LoginUserForm()
        self.context.update({
            'form': form,
        })
        return HttpResponse(self.template.render(self.context, request))

    def post(self, request, *args, **kwargs):
        # we should only get here if they submitted the form instead of a token in the URL
        # standard Django form handling here
        form = LoginUserForm(request.POST)
        if form.is_valid():
            user, error_reason = SessionManager.check_user_login(
                username_or_email=request.POST['username_or_email'],
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
                messages.success(request, 'Log in successful.')
                request.session['user_is_authenticated'] = True
                if request.session.get('login_redirect_from'):
                    return redirect(request.session.get('login_redirect_from'))
                else:
                    return redirect(reverse(settings.LOGIN_SUCCESS_REDIRECT))
        else:
            messages.error(request, 'Something went wrong. Please correct errors below.')
            self.context.update({
                'form': form,
            })
            return HttpResponse(self.template.render(self.context, request))


class ResetPasswordWithTokenView(View):
    """ View that allows a user to reset their password via a token,
        without needing to log in
    """
    def setup(self, request, *args, **kwargs):
        super(ResetPasswordWithTokenView, self).setup(request, *args, **kwargs)
        self.template = loader.get_template('session_manager/generic_form.html')
        self.context = {}
        # get the token and error message, needed for both GET and POST
        self.token, self.token_error_message = UserToken.get_token(
            token=request.GET.get('token'),
            username=request.GET.get('user'),
            token_type='reset'
        )

    def get(self, request, *args, **kwargs):
        # If we find a valid token, show the reset form with the user's ID passed to it
        if self.token:
            if self.token.is_valid:
                form = ResetPasswordForm(initial={'user_id': self.token.user.id})
                self.context.update({'form': form})
            else:
                messages.error(request, 'Token is expired.')
        else:
            messages.error(request, self.token_error_message)
        return HttpResponse(self.template.render(self.context, request))

    def post(self, request, *args, **kwargs):
        form = ResetPasswordForm(request.POST)
        # if a valid token was given and the form is valid, reset user's password
        # and redirect to login
        if self.token:
            if self.token.is_valid:
                if form.is_valid():
                    user = SessionManager.get_user_by_id(request.POST['user_id'])
                    user.set_password(request.POST['password'])
                    user.save()
                    messages.success(request, 'Password reset. Please log in to continue.')
                    self.token.delete()
                    return redirect(reverse('session_manager_login'))
            else:
                messages.error(request, 'Token is expired.')
        else:
            messages.error(request, self.token_error_message)
        self.context.update({'form': form})
        return HttpResponse(self.template.render(self.context, request))


class ResetPasswordFromProfileView(AuthenticatedView):
    """ View that allows a user to reset their password when logged in
    """
    def setup(self, request, *args, **kwargs):
        super(ResetPasswordFromProfileView, self).setup(request, *args, **kwargs)
        self.template = loader.get_template('session_manager/generic_form.html')
        self.context = {}

    def get(self, request, *args, **kwargs):
        form = ResetPasswordForm(initial={'user_id': self.request.user.id})
        self.context.update({'form': form})
        return HttpResponse(self.template.render(self.context, request))

    def post(self, request, *args, **kwargs):
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            user = self.request.user
            user.set_password(request.POST['password'])
            user.save()
            messages.success(request, 'Your password has been reset. Please log in again to continue.')
            return redirect(reverse(settings.PW_RESET_SUCCESS_REDIRECT))
        self.context.update({'form': form})
        return HttpResponse(self.template.render(self.context, request))


class LogOutUserView(View):
    def get(self, request, *args, **kwargs):
        logout(request)
        messages.success(request, 'Logged out.')
        request.session['user_is_authenticated'] = False
        return redirect(reverse('session_manager_login'))


class Index(AuthenticatedView):
    def get(self, request, *args, **kwargs):
        template = loader.get_template('session_manager/index.html')
        return HttpResponse(template.render({}, request))


