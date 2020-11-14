from django.contrib import admin
from django.urls import path

from session_manager.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', CreateUserView.as_view(), name='session_manager_register'),
    path('login/', LoginUserView.as_view(), name='session_manager_login'),
    path('logout/', LogOutUserView.as_view(), name='session_manager_logout'),
    path('resetpassword/', ReserPasswordView.as_view(), name='session_manager_reset_password'),
    path('session/', Index.as_view(), name='session_manager_index'),
]
