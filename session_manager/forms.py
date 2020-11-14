from django.forms import ModelForm, PasswordInput, CharField, HiddenInput
from django.contrib.auth.models import User


class CreateUserForm(ModelForm):

    class Meta:
        model = User
        fields = ['email', 'username', 'password']
        widgets = {
            'password': PasswordInput(),
        }


class ResetPasswordForm(ModelForm):
    user_id = CharField(widget=HiddenInput())
    class Meta:
        model = User
        fields = ['password', 'user_id']
        widgets = {
            'password': PasswordInput(),
            'user_id': HiddenInput()
        }


class LoginUserForm(ModelForm):
    class Meta:
        model = User
        fields = ['email', 'password']
        widgets = {
            'password': PasswordInput(),
        }
