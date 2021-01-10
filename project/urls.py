from django.contrib import admin
from django.urls import path

from usermanager.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', CreateUserView.as_view(), name='user_register'),
    path('login/', LoginUserView.as_view(), name='user_login'),
    path('logout/', LogOutUserView.as_view(), name='user_logout'),
    path('sendresetpassword/', SendPasswordResetLink.as_view(), name='user_send_reset_password_link'),
    path('sendregistrationlink/', SendRegistrationLink.as_view(), name='user_send_registration_link'),
    path('resetpassword/', ResetPasswordWithTokenView.as_view(), name='user_token_reset_password'),
    path('profile/resetpassword/', ResetPasswordFromProfileView.as_view(), name='user_profile_reset_password'),
    path('profile/update/', UpdateProfileView.as_view(), name='user_profile_update'),
    path('profile/', Profile.as_view(), name='user_profile'),
    path('end-user-license-agreement/', Eula.as_view(), name='eula'),
    path('privacy-policy/', PrivacyPolicy.as_view(), name='privacy_policy'),
]
