from django.contrib.auth.models import User
from django.db import models
from datetime import datetime, timedelta

import random
import string

from session_manager.utils import twentyfourhoursfromnow


class LoginToken(models.Model):
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
