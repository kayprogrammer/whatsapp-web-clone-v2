from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.pagination import PageNumberPagination
from apps.common.custom_methods import IsAuthenticatedCustom

from . serializers import *
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.generics import ListAPIView, ListCreateAPIView, RetrieveUpdateAPIView, RetrieveUpdateDestroyAPIView, GenericAPIView, CreateAPIView
from . models import Jwt, User
from . authentication import Authentication
from . senders import Util, email_verification_generate_token, password_reset_generate_token

from datetime import datetime, timedelta
import jwt
import random
import string

#-------------------------------------------------------------------------------------------------
#----------------JWT AUTH AND TOKENS CREATION----------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

def get_random(length):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


def get_access_token(payload):
    return jwt.encode(
        {"exp": datetime.utcnow() + timedelta(minutes=5), **payload},
        settings.SECRET_KEY,
        algorithm="HS256"
    )


def get_refresh_token():
    return jwt.encode(
        {"exp": datetime.utcnow() + timedelta(hours=24), "data": get_random(10)},
        settings.SECRET_KEY,
        algorithm="HS256"
    )


def decodeJWT(bearer):
    if not bearer:
        return None

    token = bearer[7:]
    decoded = jwt.decode(token, key=settings.SECRET_KEY)
    if decoded:
        try:
            return User.objects.get(id=decoded["user_id"])
        except Exception:
            return None
#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------------
#----------------REGISTER LOGIN LOGOUT----------------------------------------------------------
#-----------------------------------------------------------------------------------------------
class RegisterView(APIView):
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.create_user(**serializer.validated_data)
    
        Util.send_verification_email(user)
        
        return Response({"success": "Registration successful. Check email for verification code."}, status=201)

class LoginView(APIView):
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = authenticate(
            username=serializer.validated_data['email_or_phone'],
            password=serializer.validated_data['password']
        )
       
        if not user:
            return Response({"error": {
                "invalid_credentials" :"Invalid credentials"
            }}, status=400)

        if not user.is_email_verified:
            return Response({"error": {
                "email_not_verified" :"You must verify your email first"
            }}, status=401)

        if not user.is_phone_verified:
            return Response({"error": {
                "phone_not_verified" :"You must verify your phone number first"
            }}, status=401)
            
        Jwt.objects.filter(user=user).delete()

        access = get_access_token({"user_id": str(user.id), "name":user.name, "email":user.email, "phone":user.phone, 'avatar': user.avatarURL, 'timezone': user.tz.name })

        refresh = get_refresh_token()
        # print(type(access))
        Jwt.objects.create(
            user=user, access=access, refresh=refresh
        )

        return Response({"access": access, "refresh": refresh}, status=201)

class RefreshView(APIView):
    serializer_class = RefreshSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            active_jwt = Jwt.objects.get(
                refresh=serializer.validated_data["refresh"])
        except Jwt.DoesNotExist:
            return Response({"error": "refresh token not found"}, status="400")
        if not Authentication.verify_token(serializer.validated_data["refresh"]):
            return Response({"error": "Token is invalid or has expired"})

        access = get_access_token({"user_id": active_jwt.user.id, "name":active_jwt.user.name, "email": active_jwt.user.email, 'phone': active_jwt.user.phone, 'avatar': active_jwt.user.avatarURL, 'timezone': active_jwt.user.tz.name })

        refresh = get_refresh_token()


        active_jwt.access = access
        active_jwt.refresh = refresh
        active_jwt.save()

        print('There was a refresh')
        return Response({"access": access, "refresh": refresh}, status=201)

class LogoutView(APIView):
    permission_classes = (IsAuthenticatedCustom, )

    def post(self, request):
        user_id = request.user.id

        Jwt.objects.filter(user_id=user_id).delete()

        return Response("logged out successfully", status=200)

#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------
#----------------ACCOUNT VERIFICATION ----------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

class VerifyEmail(APIView):
    def get(self, request, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(kwargs.get('uidb64')))
            user = User.objects.get(id=uid)

        except Exception as e:
            user = None

        if user and email_verification_generate_token.check_token(user, kwargs.get('token')):
            user.is_email_verified = True
            user.save()
            Util.send_sms_otp(user)
            return Response({'success': 'Email verified'}, status=200)

        return Response({'error': 'Link is broken, expired or has already been used'})

class VerifyPhone(APIView):
    serializer_class = VerifyPhoneSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.data['phone']
        otp = serializer.data['otp']
        user_obj = User.objects.filter(phone=phone)
        if not user_obj.exists():
            return Response({"error": {
                "invalid_phone" :"Invalid Phone Number"
            }}, status=422)
        user = user_obj.first()
        if user.otp != otp:
            return Response({"error": {
                "invalid_otp" :"Invalid OTP"
            }}, status=422)
        if user.is_phone_verified:
            return Response({"error": {
                "phone_already_verified" :"Phone Number already verified. Proceed to login!"
            }}, status=422)

        user.is_phone_verified = True
        user.otp = None
        user.save()
        Util.send_welcome_email(user)
        return Response({'success': 'Phone Number verified!'}, status=200)

class ResendPhoneOtp(APIView):
    serializer_class = ResendOtpSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        print(serializer)
        serializer.is_valid(raise_exception=True)
        phone = serializer.data['phone']
        user = User.objects.filter(phone=phone)
        if not user.exists():
            return Response({"error": {
                "invalid_phone" :"Invalid Phone Number"
            }}, status=422)
        if user[0].is_phone_verified == True:
            return Response({"error": {
                "phone_already_verified" :"Phone number already verified. Proceed to login!"
            }}, status=422)
        user = user.get()
        Util.send_sms_otp(user)
        return Response({'success': 'New otp sent!'}, status=200)

class ResendEmailActivation(APIView):
    serializer_class = ResendActivationEmailSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        user = User.objects.filter(email=email)
        if not user.exists():
            return Response({"error": {
                "invalid_email" :"Invalid Email Address"
            }}, status=422)
        if user[0].is_email_verified == True:
            return Response({"error": {
                "email_already_verified" :"Email address already verified. Proceed to login!"
            }}, status=422)
        user = user.get()
        Util.send_verification_email(user)
        return Response({'success': 'Activation link sent to email!'}, status=200)

#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------
#----------------PASSWORD RESET----------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

class RequestPasswordResetEmail(APIView):
    serializer_class = ResetPasswordEmailRequestSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        user = User.objects.filter(email=email)
        if not user.exists():
            return Response({"error": "Invalid email!"}, status=422)
        user = user.get()
        Util.send_password_reset_email(user)
        return Response({'success': 'Password email sent!'}, status=200)    

class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        serializer.is_valid(raise_exception=True)
        try:
            uid = force_str(urlsafe_base64_decode(serializer.data['uid']))
            user = User.objects.get(id=uid)

        except Exception as e:
            user = None

        if not user or not password_reset_generate_token.check_token(user, serializer.data['token']):
            return Response({'error': 
                {'token_error': 'Link is broken, expired or has already been used'}
            }, status=400)

        user.set_password(serializer.data['new_password'])
        user.save()
        return Response({'success': 'Password reset success!'}, status=200)

#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------
