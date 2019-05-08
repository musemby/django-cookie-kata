from django.urls import path
from django.conf.urls import include, url

from . import views

urlpatterns = [
    # path('login/', views.login_view, name='login'),
    url(r'^sign-up/$', views.SignUpView.as_view(), name='signup'),
    url(r'^login/$', views.LoginView.as_view(), name='login'),
    url(r'^logout/$', views.LogoutView.as_view(), name='logout'),
    url(r'^me/$', views.MeView.as_view(), name='me'),
    url(r'^facebook-login/$', views.FacebookLoginView.as_view(), name='facebook_login'),
    url(r'^google-login/$', views.GoogleLoginView.as_view(), name='google_login'),
    url(r'^request-email-verification/$', views.RequestEmailVerificationView.as_view(), name='request_email_verification'),
    url(r'^request-password-reset/$', views.RequestPasswordResetView.as_view(), name='request_password_reset'),
    url(r'^verify-email/(?P<verification_key>.+)/$', views.VerifyEmailView.as_view(), name='verify_email'),
    url(r'^reset-password/$', views.ResetPasswordView.as_view(), name='reset_password'),
]
