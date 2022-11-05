from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers, fields
from . models import Timezone
from . validators import validate_email, validate_phone

class LoginSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField()
    password = serializers.CharField()

class RegisterSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=50)
    email = serializers.EmailField(validators=[validate_email])
    phone = serializers.CharField(max_length=15, validators=[validate_phone])
    tz = serializers.SlugRelatedField(slug_field='name', queryset=Timezone.objects.all(), error_messages={'does_not_exist': 'Timezone does not exist!'})
    password = serializers.CharField(validators=[validate_password])
    terms_agreement = serializers.BooleanField()

class ResendOtpSerializer(serializers.Serializer):
    phone = serializers.CharField(max_length=15)

class ResendActivationEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

class VerifyPhoneSerializer(serializers.Serializer):
    phone = serializers.CharField()
    otp = serializers.IntegerField()

class RefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

class CheckPasswordResetOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.IntegerField()

class SetNewPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(validators=[validate_password])
    otp = serializers.IntegerField()

