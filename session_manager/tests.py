from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User


class SessionManagerTestCase(TestCase):

    def setUp(self, *args, **kwargs):
        super(SessionManagerTestCase, self).setUp(*args, **kwargs)
        self.register_url = reverse('session_manager_register')
        self.login_url = reverse('session_manager_login')

    def assertMessageInContext(self, request, message_text):
        messages = [msg.message for msg in request.context['messages']._loaded_messages]
        self.assertIn(message_text, messages)

    def _create_user(self, email, username=None, password=None):
        user = User(email=email)
        if username:
            user.username=username
        else:
            user.username=email
        user.save()
        if password:
            user.set_password(password)
            user.save()
        return user


class TestRegistrationFlow(SessionManagerTestCase):

    def test_register_user_happy_path(self):
        register_get = self.client.get(self.register_url)
        self.assertEqual(register_get.status_code, 200)

        post_data = {
            'email': 'test@example.com',
            'username': 'tester',
            'password': 't3st3r@dmin'
        }

        register_post = self.client.post(self.register_url, post_data, follow=True)
        self.assertEqual(register_post.status_code, 200)
        self.assertMessageInContext(register_post, 'Registration complete! Please log in to continue.')

        new_user = User.objects.get(email=post_data['email'])
        self.assertEqual(new_user.username, post_data['username'])
        self.assertTrue(new_user.check_password(post_data['password']))

    def test_user_already_exists(self):
        post_data = {
            'email': 'test@example.com',
            'username': 'tester',
            'password': 't3st3r@dmin'
        }
        self._create_user(**post_data)
        register_post = self.client.post(self.register_url, post_data)
        self.assertEqual(register_post.status_code, 200)
        self.assertMessageInContext(register_post, 'A user with this email address already exists.')

    def test_login_happy_path(self):
        post_data = {
            'email': 'test@example.com',
            'password': 't3st3r@dmin'
        }
        self._create_user(**post_data)
        login_request = self.client.post(self.login_url, post_data, follow=True)
        self.assertEqual(login_request.status_code, 200)
        self.assertMessageInContext(login_request, 'Log in successful.')

    def test_login_no_user(self):
        post_data = {
            'email': 'test@example.com',
            'password': 't3st3r@dmin'
        }
        login_request = self.client.post(self.login_url, post_data, follow=True)
        self.assertEqual(login_request.status_code, 200)
        self.assertMessageInContext(login_request, 'User matching email does not exist.')

    def test_login_badpassword(self):
        post_data = {
            'email': 'test@example.com',
            'password': 't3st3r@dmin'
        }
        self._create_user(**post_data)
        post_data['password'] = 'badpassword'
        login_request = self.client.post(self.login_url, post_data, follow=True)
        self.assertEqual(login_request.status_code, 200)
        self.assertMessageInContext(login_request, 'Password incorrect.')
