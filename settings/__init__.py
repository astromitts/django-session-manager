"""
Django settings for app project.

Generated by 'django-admin startproject' using Django 3.1.3.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.1/ref/settings/
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '=yj_)+y+pee^&7am1n$d3t+)y!2b==n-)c&6sd-tau8h$9kunl'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'usermanager',
    'base',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'usermanager.middleware.session_request_validation',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'usermanager.context_processors.user_manager_app_context'
            ],
        },
    },
]

WSGI_APPLICATION = 'project.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': str(BASE_DIR / 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.1/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'base/static')

# Session Manager Settings
LOGIN_SUCCESS_REDIRECT = 'user_profile'
PW_RESET_SUCCESS_REDIRECT = 'user_profile'
DEFAULT_ERROR_TEMPLATE = 'usermanager/error.html'
MAKE_USERNAME_EMAIL = False

# Middleware authentication settings
MIDDLEWARE_DEBUG = False
AUTHENTICATION_EXEMPT_VIEWS = [
    'user_register',
    'user_login',
    'user_token_reset_password',
    'user_send_reset_password_link',
    'user_send_registration_link',
    'eula',
    'privacy_policy',
]
AUTHENTICATION_REQUIRED_REDIRECT = 'user_login'
EULA_PP_UPDATE_VIEW = 'user_update_eula_pp'

# display settings
APP_NAME = "Bo's Django Template"
DISPLAY_AUTH_SUCCESS_MESSAGES = True

# EULA Settings
CURRENT_EULA_VERSION = 'eula-v1-09-01-2021'
CURRENT_PRIVACY_POLICY_VERSION = 'privacy-policy-v1-09-01-2021'
APP_NAME_LEGAL = "BosDjangoTemplate.example"


# email settings
LOG_EMAILS = True
SEND_EMAILS = False
EMAILS_FROM = 'admin@example.com'
EMAIL_REPLY_TO = 'info@example.com'
SENDGRID_API_KEY = None
PREVIEW_EMAILS_IN_APP = True


HOST = 'http://127.0.0.1:8000'
