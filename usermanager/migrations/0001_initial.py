# Generated by Django 3.1.3 on 2021-01-10 16:20

import datetime
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import usermanager.utils


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='EmailLog',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email_type', models.CharField(max_length=50)),
                ('to_email', models.EmailField(max_length=254)),
                ('from_email', models.EmailField(max_length=254)),
                ('subject', models.CharField(max_length=300)),
                ('body', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='UserToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(blank=True, max_length=64)),
                ('token_type', models.CharField(choices=[('reset', 'reset'), ('login', 'login'), ('registration', 'registration')], max_length=20)),
                ('expiration', models.DateTimeField(blank=True, default=usermanager.utils.TimeDiff.fourtyeighthoursfromnow)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserManager',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('registration_status', models.CharField(choices=[('pre-registered', 'pre-registered'), ('invited', 'invited'), ('complete', 'complete')], default='pre-registered', max_length=25)),
                ('registration_type', models.CharField(choices=[('website', 'website'), ('invitation', 'invitation')], default='website', max_length=25)),
                ('eula_version', models.CharField(default='eula-v1-09-01-2021', max_length=100)),
                ('eula_timestamp', models.DateTimeField(default=datetime.datetime.now)),
                ('privacy_policy_version', models.CharField(default='privacy-policy-v1-09-01-2021', max_length=100)),
                ('privacy_policy_timestamp', models.DateTimeField(default=datetime.datetime.now)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
