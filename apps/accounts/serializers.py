from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers, fields
from . models import Timezone
from . validators import validate_email, validate_phone, phone_regex_pattern

class LoginSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField()
    password = serializers.CharField()

class RegisterSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=50)
    email = serializers.EmailField(validators=[validate_email])
    phone = serializers.CharField(max_length=15, validators=[validate_phone, phone_regex_pattern])
    tz = serializers.SlugRelatedField(slug_field='name', queryset=Timezone.objects.all(), error_messages={'does_not_exist': 'Timezone does not exist!'})
    password = serializers.CharField(validators=[validate_password])
    terms_agreement = serializers.BooleanField()

    # Can do this in validators.py though but just showing you another way
    def validate_terms_agreement(self, value):
        if value != True:
            raise ValidationError('You must agree to terms')
        return value

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

class SetNewPasswordSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(validators=[validate_password])

