import facebook
import random
import string

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password

from google.oauth2 import id_token
from google.auth.transport import requests

from rest_framework import generics, status, permissions
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import UserVerification
from .serializers import (
    UserSerializer, SignUpSerializer, LoginSerializer, RequestEmailVerificationSerializer,
    FacebookLoginSerializer, RequestPasswordResetSerializer, ResetPasswordSerializer,
    GoogleLoginSerializer
    )

User = get_user_model()


class MeView(generics.RetrieveAPIView):

    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAuthenticated, )

    def get(self, request, *args, **kwargs):
        user = request.user
        ser = UserSerializer(user)

        return Response(data=ser.data, status=status.HTTP_200_OK)


class SignUpView(generics.CreateAPIView):

    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = (permissions.AllowAny, )


class VerifyEmailView(generics.RetrieveAPIView):

    permission_classes = (permissions.AllowAny, )

    def get(self, request, verification_key):
        verification = UserVerification.objects.get(verification_key=verification_key)
        if verification.is_expired:
            verification.user.send_email_verification_email()
            return Response("The password reset link used is expired. Kindly check your email for a new reset link.")

        activated_user = self.activate_email(verification_key)
        if activated_user:
            serialized_user = UserSerializer(activated_user).data
            return Response(data=serialized_user, status=status.HTTP_200_OK)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def activate_email(self, verification_key):
        return User.objects.verify_email(verification_key)


class RequestEmailVerificationView(generics.CreateAPIView):

    permission_classes = (permissions.IsAuthenticated, )
    serializer_class = RequestEmailVerificationSerializer

    def post(self, request, *args, **kwargs):
        token = request.auth
        user = request.user
        try:
            if user.email_verified:
                return Response("This email ({}) is already verified.".format(user.email), status=200)
            user.send_email_verification_email()
            return Response("Successfully sent verification email.", status=status.HTTP_200_OK)
        except Exception as e:
            return Response(str(e), status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetView(generics.CreateAPIView):

    permission_classes = (permissions.AllowAny, )
    serializer_class = RequestPasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.data['email']
        # TODO do we communicate when no account linked to the email is found?

        try:
            user = User.objects.get(email=email)
            user.send_password_reset_email()
            return Response("Successfully sent password reset email.", status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response()


class ResetPasswordView(generics.CreateAPIView):

    permission_classes = (permissions.AllowAny, )
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        reset_token = serializer.data['reset_token']
        password = serializer.data['password']
        password_confirm = serializer.data['password_confirm']

        try:
            verification = UserVerification.objects.get(verification_key=reset_token)
            if verification.is_expired:
                verification.user.send_password_reset_email()
                return Response("The password reset link used is expired. Kindly check your email for a new reset link.")

            validate_password(password)
            if password_confirm != password:
                return Response('Sorry, the passwords did not match', status=status.HTTP_400_BAD_REQUEST)

            user = verification.user
            user.set_password(password)
            user.save()
            return Response("The password has been reset.", status=status.HTTP_200_OK)
        except UserVerification.DoesNotExist:
            return Response("The reset token does not exist or has expired. Kindly request a new one.", status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.CreateAPIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = LoginSerializer

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            msg = "Please provide both the email and password to log in."
            return Response(data=msg, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)

            if not user.check_password(password):
                msg = 'Invalid user and mail and password combination.'
                return Response(data=msg, status=status.HTTP_400_BAD_REQUEST)

            token, _ = Token.objects.get_or_create(user=user)

            user_ser = UserSerializer(user)
            user_data = user_ser.data
            user_data['token'] = token.key

            resp = { 'token': token.key }

            return Response(data=resp, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            msg = 'Invalid email and password combination.'
            return Response(data=msg, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):

    permission_classes = (permissions.AllowAny, )

    def post(self, request, *args, **kwargs):
        return self.logout(request)

    def logout(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            pass

        return Response("Successfully logged out.", status=status.HTTP_200_OK)


class GoogleLoginView(generics.CreateAPIView):

    permission_classes = (permissions.AllowAny, )
    serializer_class = GoogleLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = request.data.get('access_token')

        try:
            user_info = id_token.verify_oauth2_token(token, requests.Request(), settings.GOOGLE_CLIENT_ID)

            if user_info['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                return Response('Wrong token issuer.')

            googleid = user_info['sub']
            try:
                user = User.objects.get(google_id=googleid)
            except User.DoesNotExist:
                password = User.objects.make_random_password()
                user = User(
                    first_name=user_info.get('given_name'),
                    last_name=user_info.get('family_name'),
                    email=user_info.get('email'),
                    google_id=googleid,
                    date_joined=timezone.now(),
                )
                # TODO: GENDER??
                user.set_password(password)
                user.save()
            token, _ = Token.objects.get_or_create(user=user)
            # user_data['token'] = token.key

            return Response(data={'token': token.key}, status=status.HTTP_200_OK)

        except ValueError:
            return Response('The token provided is invalid.', status=400)


class FacebookLoginView(generics.CreateAPIView):
    permission_classes = (permissions.AllowAny, )
    serializer_class = FacebookLoginSerializer

    def post(self, request, *args, **kwargs):
        # import pdb; pdb.set_trace()
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.data['access_token']
        try:
            graph = facebook.GraphAPI(access_token=token)
            user_info = graph.get_object(
                id='me',
                fields=('first_name, middle_name, last_name, id, '
                'currency, hometown, location, locale, '
                'email, gender, interested_in, picture.type(large),'
                ' birthday, cover')
                )

        except facebook.GraphAPIError as e:
            return Response(
                data={'error': 'Unable to authenticate with facebook'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(facebook_id=user_info.get('id'))
        except User.DoesNotExist:
            password = User.objects.make_random_password()
            user = User(
                first_name=user_info.get('first_name'),
                last_name=user_info.get('last_name'),
                other_names=user_info.get('middle_name'),
                email=user_info.get('email'),
                facebook_id=user_info.get('id'),
                date_joined=timezone.now(),
            )
            if not user.email:
                rand_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=9))
                user.email = rand_str + '@gmail.com'
                user.has_fake_email = True

            user.set_password(password)
            user.save()

        user_ser = UserSerializer(user)
        user_data = user_ser.data
        token, _ = Token.objects.get_or_create(user=user)
        # user_data['token'] = token.key

        return Response(data={'token': token.key}, status=status.HTTP_200_OK)
