# Django Session Manager
This template repository comes with register, log in,
and log out views to get a jump start on building a 
Django project that requires user authentication.

It can generate login tokens for passwordless logins 
and password reset tokens. 

It relies on Send Grid to send emails to users giving
them registration or login credentials.

Extend or override the template files to customize.

### Settings
LOGIN_SUCCESS_REDIRECT (String)
urls.py path name of the view to redirect users to after
successful log in

APP_NAME (String)
Just for displaying in email output

DISPLAY_AUTH_SUCCESS_MESSAGES (Boolean)
Personal preference here - if you want Django success messages
added to templates on successful login (required for tests)

## SessionManagerEmailer
Handler for sending emails via SendGrid. This app enforces a
registration flow that looks like:
	1) Submit your email address
	2) Back-end creates and saves a User object for that email
	3) Back-end sends an email* to given email address containing
	   a valid registration token embedded in a link
	4) User clicks the link
	5) Back-end validates link - if valid, presents registration form
	6) User completes registration form is allowed to log in

\*The template for this email is in templates/session_manager/emails

For development and testing purposes, there is an EmailLog model
which you can use to bypass sending actual emails and just check
the content and settings of emails that would otherwise be sent.

### Settings
LOG_EMAILS (Boolean)
Turn on/off to log emails either in place of or along with sending
actual emails.

SEND_EMAILS (Boolean)
Turn on to enable sending emails via Send Grid

EMAILS_FROM (String)
The from email address for your app

SENDGRID_API_KEY (String)
Valid API key for a verified sender in Send Grid


## Middleware
Session manager middleware handles redirecting
unauthenticated users from accessing views that require
authentication, as well as rendering an error page for 
404s and uncaught exceptions to give a good UX.

### Settings
MIDDLEWARE_DEBUG (Boolean)
Set to True to bypass the middleware authentication/error 
handling

DEFAULT_ERROR_TEMPLATE (String)
Static path to the HTML template to use to display error
messages to users. The following context is passed to it 
from the middleware function:
status_code: Int, HTML status code of the error
error_message: String, error message to display on page

AUTHENTICATION_REQUIRED_REDIRECT (String)
urls.py path name of the view to redirect unauthenticated
users to when they attempt to access a restricted page

## Tests

All view logic should be covered via tests.py, to run:
`python manage.py test`
