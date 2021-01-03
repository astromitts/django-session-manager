from django.conf import settings


def session_manager_app_context(request=None):
    return {
        'APP_NAME': settings.APP_NAME,
    }
