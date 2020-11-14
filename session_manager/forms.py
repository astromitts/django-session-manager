from django.forms import ModelForm, PasswordInput, CharField
from django.contrib.auth.models import User


class CreateUserForm(ModelForm):

    class Meta:
        model = User
        fields = ['email', 'username', 'password']
        widgets = {
            'password': PasswordInput(),
        }


class LoginUserForm(ModelForm):
    class Meta:
        model = User
        fields = ['email', 'password']
        widgets = {
            'password': PasswordInput(),
        }
