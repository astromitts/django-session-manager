from django.conf import settings


def user_manager_app_context(request=None):
    return {
    	'HOST': settings.HOST,
        'APP_NAME': settings.APP_NAME,
        'APP_NAME_LEGAL': settings.APP_NAME_LEGAL,
        'EMAIL_REPLY_TO': settings.EMAIL_REPLY_TO,
    }
