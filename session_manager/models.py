from django.contrib.auth.models import User
from django.db import models
from datetime import datetime, timedelta

import random
import string

from session_manager.utils import twentyfourhoursfromnow


class SessionManager(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=64)
    expiration = models.DateTimeField(default=twentyfourhoursfromnow)

    def generate_login_token(self):
        token_base = '{}-{}-{}'.format(
            self.user.email,
            datetime.now(),
            ''.join(random.choices(string.ascii_uppercase + string.digits, k = 60))
        )
        token_hash = hashlib.sha256(token_base.encode())
        return token_hash.hexdigest()

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = self.generate_login_token()
        super(LoginToken, self).save(*args, **kwargs)

    @classmethod
    def user_exists(cls, email):
        user_qs = User.objects.filter(email=email)
        return user_qs.exists()

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
            return (None, 'User matching email does not exist')
        else:
            if user.check_password(password):
                return (user, None)
            else:
                return (None, 'Password incorrect')
