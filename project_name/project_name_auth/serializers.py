from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import (
    validate_password, MinimumLengthValidator, UserAttributeSimilarityValidator,
    CommonPasswordValidator
)
from django.contrib.auth.tokens import default_token_generator
from django.db import transaction
from rest_framework import serializers
from rest_framework.authtoken.models import Token

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):


    class Meta:
        model = User
        exclude = ('password', )


class SignUpSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True, write_only=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(required=True, write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = (
            'first_name', 'last_name', 'username', 'dob', 'email',
            'password', 'password_confirm'
        )


    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Sorry, this email already exists.")
        return value

    def validate_user_password(self, password):
        data = self.get_initial()
        password_confirm = data.get('password_confirm')

        if password_confirm != password:
            raise serializers.ValidationError('Sorry, the passwords did not match')

        validate_password(password)

        return password

    @transaction.atomic
    def create(self, validated_data):
        data = {
            'first_name': validated_data.get('first_name'),
            'last_name': validated_data.get('last_name'),
            'email': validated_data.get('email'),
            'username': validated_data.get('username'),
            'dob': validated_data.get('dob'),
            # 'user_type': validated_data.get('user_type'),
            # 'phone_number': validated_data.get('phone_number'),
            'password': validated_data.get('password')
        }

        try:
            self.validate_user_password(validated_data.get('password'))
        except Exception as e:
            raise serializers.ValidationError(e)

        user = User.objects.create_user(**data)
        user.send_welcome_email()
        user.send_email_verification_email()

        return validated_data


class LoginSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(required=True, write_only=True)
    password = serializers.CharField(required=True, write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['email', 'password']


class RequestEmailVerificationSerializer(serializers.Serializer):

    email = serializers.EmailField(required=True)


class RequestPasswordResetSerializer(serializers.Serializer):

    email = serializers.EmailField(required=True)


class ResetPasswordSerializer(serializers.Serializer):

    reset_token = serializers.CharField(required=True)
    password = serializers.CharField(required=True, style={'input_type': 'password'})
    password_confirm = serializers.CharField(required=True, style={'input_type': 'password'})


class FacebookLoginSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)


class GoogleLoginSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)

