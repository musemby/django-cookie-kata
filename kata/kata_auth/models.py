import copy
import datetime
import hashlib
import re

from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.mail import send_mail
from django.db import models, transaction
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone, crypto
from rest_framework.authtoken.models import Token

VERIFICATION_TYPES = (
    ('EMAIL_VERIFICATION', 'Email verification'),
    ('PASSWORD_RESET', 'Password reset'),
)

SHA1_RE = re.compile('^[a-f0-9]{40}$')


class UserManager(BaseUserManager):

    def create_user(self, **fields):
        user_fields = copy.copy(fields)
        password = user_fields.pop('password')
        user = self.model(**user_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, **fields):
        user = self.create_user(**fields)
        user.is_staff = True
        user.save(using=self._db)

        return user

    @transaction.atomic
    def verify_email(self, token):
        if SHA1_RE.search(token.lower()):
            try:
                user_verification = UserVerification.objects.get(verification_key=token)
                if user_verification.is_expired:
                    raise ValidationError("The token provided is expired. Please request another token.")
            except UserVerification.ObjectDoesNotExist:
                return None

            user = user_verification.user
            user.email_verified = True
            user.save()

            user_verification.verified_on = timezone.now()
            user_verification.save()

            return user
        return None


class UserProfile(models.Model):
    user = models.OneToOneField('KataUser', on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=255)
    bio = models.CharField(max_length=250, null=True, blank=True)


class KataUser(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    other_names = models.CharField(max_length=255, blank=True, null=True)
    username = models.CharField(max_length=255, unique=True, blank=True, null=True)
    email = models.EmailField(unique=True, max_length=255)
    dob = models.DateTimeField(null=True, blank=True)
    date_joined = models.DateTimeField(default=timezone.now)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False, null=True, blank=True)
    email_verified = models.BooleanField(default=False)
    facebook_id = models.CharField(max_length=255, blank=True, null=True)
    google_id = models.CharField(max_length=255, blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    # REQUIRED_FIELDS = ['email']

    def __str__(self):
        return "{} {}".format(self.first_name, self.last_name)

    @property
    def full_name(self):
        return "{} {}".format(self.first_name, self.last_name)


    def create_verification_key(self, verification_type):
        hash_input = (crypto.get_random_string(5) + self.email).encode('utf-8')
        token = hashlib.sha1(hash_input).hexdigest()

        verif, _ = UserVerification.objects.get_or_create(
            user=self, verification_type=verification_type, verification_key=token
        )
        return verif

    def send_welcome_email(self):
        subject = "Welcome aboard."
        msg = """Hello {},
            Your account has been successfully created.
        """.format(self.first_name)

        send_mail(subject, msg, settings.DEFAULT_FROM_EMAIL, [self.email])

    def send_email_verification_email(self):
        subject = "Account Verification"
        user_ver = self.create_verification_key(verification_type='EMAIL_VERIFICATION')
        link = '{}{}'.format(settings.EMAIL_VERIFICATION_LINK, user_ver.verification_key)

        msg = """Hello {},
            Kindly click this link to verify your account: {}
        """.format(self.first_name, link)

        send_mail(subject, msg, settings.DEFAULT_FROM_EMAIL, [self.email])

    def send_password_reset_email(self):
        subject = "Skika Password Reset"
        user_key = self.create_verification_key(verification_type='PASSWORD_RESET')
        link = '{}?reset_token={}'.format(settings.PASSWORD_RESET_URL, user_key.verification_key)

        msg = """
            Hello {},

            You are receiving this email because a request to reset your Skika account password was made.
            Kindly click on this link to reset your password {}.

            If you did not initiate this request, please ignore this email.
        """.format(self.first_name, link)

        send_mail(subject, msg, settings.DEFAULT_FROM_EMAIL, [self.email])


class UserVerification(models.Model):
    user = models.ForeignKey(KataUser, on_delete=models.CASCADE, related_name='user_verification')
    verification_key = models.CharField(max_length=40)
    created_on = models.DateTimeField(default=timezone.now)
    verified_on = models.DateTimeField(blank=True, null=True)
    verification_type = models.CharField(max_length=255, choices=VERIFICATION_TYPES)

    @property
    def is_expired(self):
        EXPIRY_PERIOD = self.verification_type + '_EXPIRY'
        expiry_date = self.created_on + datetime.timedelta(hours=getattr(settings, EXPIRY_PERIOD))
        return timezone.now() >= expiry_date


