from django.contrib import admin

from usermanager.models import EmailLog, UserManager, UserToken


class UserTokenAdmin(admin.ModelAdmin):
    fields = [
        'user',
        'token',
        'token_type',
        'expiration',
        'link',
    ]
    readonly_fields = ['link', ]


class UserManagerAdmin(admin.ModelAdmin):
    fields = [
        'email',
        'registration_status',
        'registration_type',
        'eula_version',
        'eula_timestamp',
        'privacy_policy_version',
        'privacy_policy_timestamp'
    ]
    readonly_fields = ['email', ]

admin.site.register(UserToken, UserTokenAdmin)
admin.site.register(UserManager, UserManagerAdmin)
admin.site.register(EmailLog)
