from django.conf import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from session_manager.models import EmailLog
from django.template.loader import render_to_string


class SessionManagerEmailer(object):

    @classmethod
    def send_email(cls, email_type, to_email, subject, html_body):
        if settings.LOG_EMAILS:
            email_log = EmailLog(
                email_type=email_type,
                to_email=to_email,
                from_email=settings.EMAILS_FROM,
                subject=subject,
                body=html_body
            )
            email_log.save()

        if settings.SEND_EMAILS and settings.SENDGRID_API_KEY:
            message = Mail(
                from_email=settings.EMAILS_FROM,
                to_emails=to_email,
                subject=subject,
                html_content=html_body
            )
            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
            response = sg.send(message)
            return response

    @classmethod
    def _send_app_registration_link(cls, subject, email_type, to_email, token):
        body = render_to_string(
            'session_manager/emails/registration_link.html',
            context={'token_link': token.link, 'host': settings.HOST},
        )
        cls.send_email(
            email_type,
            to_email,
            subject,
            body
        )

    @classmethod
    def send_app_registration_link(cls, to_user, token):
        email_type = 'Self Registration'
        subject = 'Your registration link has arrived!'
        to_email = to_user.email
        cls._send_app_registration_link(subject, email_type, to_email, token)

    @classmethod
    def send_app_invitation_link(cls, to_user, from_user, organization, token):
        email_type = 'Org Invitation'
        to_email = to_user.email
        subject = '{} {} has invited you to join {}'.format(
            from_user.first_name, from_user.last_name, settings.APP_NAME
        )
        cls._send_app_registration_link(subject, email_type, to_email, token)
