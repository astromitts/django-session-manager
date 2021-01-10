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

admin.site.register(UserToken, UserTokenAdmin)
admin.site.register(EmailLog)
