from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.urls import reverse

from datetime import datetime, timedelta
import pytz

import hashlib
import random
import string

from session_manager.utils import twentyfourhoursfromnow


class SessionManager(models.Model):
    class Meta:
        abstract = True

    @classmethod
    def user_exists(cls, email):
        user_qs = User.objects.filter(email=email)
        return user_qs.exists()

    @classmethod
    def get_user_by_username(cls, username):
        return User.objects.filter(username=username).first()

    @classmethod
    def get_user_by_id(cls, pk):
        return User.objects.get(pk=pk)

    @classmethod
    def create_user(cls, email, username, password):
        new_user = User(
            email=email,
            username=username,
        )
        new_user.save()
        new_user.set_password(password)
        new_user.save()
        return new_user

    @classmethod
    def check_user_login(cls, email, password):
        user = User.objects.filter(email=email).first()
        if not user:
            return (None, 'User matching email does not exist.')
        else:
            if user.check_password(password):
                return (user, None)
            else:
                return (None, 'Password incorrect.')


class UserToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=64, blank=True)
    token_type = models.CharField(
        max_length=20,
        unique=True,
        choices=(
            ('reset', 'reset'),
            ('login', 'login'),

        )
    )
    expiration = models.DateTimeField(blank=True, default=twentyfourhoursfromnow)

    def _generate_login_token(self):
        token_base = '{}-{}-{}'.format(
            self.user.email,
            datetime.now(),
            ''.join(random.choices(string.ascii_uppercase + string.digits, k = 60))
        )
        token_hash = hashlib.sha256(token_base.encode())
        return token_hash.hexdigest()

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self._generate_login_token()
        super(UserToken, self).save(*args, **kwargs)

    @property
    def path(self):
        if self.token_type == 'login':
            return '{}?token={}&user={}'.format(reverse('session_manager_login'), self.token, self.user.username)
        else:
            return '{}?token={}&user={}'.format(reverse('session_manager_reset_password'), self.token, self.user.username)

    @property
    def link(self):
        return '{}{}'.format(settings.HOST, self.path)

    def __str__(self):
        return 'UserToken Object: {} // User: {} // type: {} // expires: {}'.format(self.pk, self.user.email, self.token_type, self.expiration)

    @classmethod
    def get_token(cls, token, username, token_type):
        user = SessionManager.get_user_by_username(username)
        if not user:
            return (None, 'User matching username not found.')
        token = cls.objects.filter(user=user, token=token, token_type=token_type).first()
        if not token:
            return (None, 'Token not found.')
        else:
            return (token, None)

    @property
    def is_valid(self):
        utc=pytz.UTC
        if self.expiration >= utc.localize(datetime.now()):
            return True
        else:
            return False
