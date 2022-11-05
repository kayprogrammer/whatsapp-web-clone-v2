from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.db.models import Q
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
from . senders import Util, generate_token

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

#-------------------------------------------------------------------------------------------------
#----------------REGISTER LOGIN AUTH----------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

class RegisterView(APIView):
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.create_user(**serializer.validated_data)
    
        Util.send_verification_email(request, user)
        
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
            }}, status=400)

        if not user.is_phone_verified:
            return Response({"error": {
                "phone_not_verified" :"You must verify your phone number first"
            }}, status=400)
            
        Jwt.objects.filter(user_id=user.id).delete()

        access = get_access_token({"user_id": user.id, "name":user.name, "email":user.email, "phone":user.phone, 'avatar': user.avatarURL, 'timezone': user.tz.name })

        refresh = get_refresh_token()

        Jwt.objects.create(
            user_id=user.id, access=access.decode(), refresh=refresh.decode()
        )
#         authtoken = {"access": access, "refresh": refresh}
#         response = Response() get_access_token({"user_id": user.id, "first_name":user.first_name, "last_name":user.last_name, "is_tutor":user.is_tutor, 'avatar': user.avatarUrl, 'hours': user.student.hours.filter(valid=True, status="UNUSED") if hasattr(user.student) else 0})
#         response.set_cookie(key = "authtoken", value = authtoken, max_age=300, httponly=True)
#         csrf.get_token(request)
#         response.data = {'jwt':authtoken}
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


        active_jwt.access = access.decode()
        active_jwt.refresh = refresh.decode()
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
    def get(self, request):
        try:
            uid = force_str(urlsafe_base64_decode(self.kwargs.get('uidb64')))
            user = User.objects.get(id=uid)

        except Exception as e:
            user = None

        if user and generate_token.check_token(user, self.kwargs.get('token')):
            user.is_email_verified = True
            user.save()
            Util.send_sms_otp(user)
            return Response({'success': 'Email verified'}, status=200)

        return Response({'error': 'Link is broken or has already been used'})

class VerifyPhone(APIView):
    serializer_class = VerifyPhoneSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            phone = serializer.data['email']
            otp = serializer.data['otp']
            user_obj = User.objects.filter(phone=phone)
            if not user_obj.exists():
                return Response({"error": {
                    "invalid_phone" :"Invalid Phone Number"
                }}, status=400)
            user = user_obj.first()
            if user.otp != otp:
                return Response({"error": {
                    "invalid_otp" :"Invalid OTP"
                }}, status=400)
            if user.is_phone_verified:
                return Response({"error": {
                    "phone_already_verified" :"Phone Number already verified. Proceed to login!"
                }}, status=400)

            user.is_phone_verified = True
            user.otp = None
            user.save()
            Util.send_welcome_email(request, user)
            return Response({'success': 'Phone Number verified!'}, status=200)

class ResendPhoneOtp(APIView):
    serializer_class = ResendOtpSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        print(serializer)
        if serializer.is_valid(raise_exception=True):
            phone = serializer.data['phone']
            user = User.objects.filter(phone=phone)
            if not user.exists():
                return Response({"error": {
                    "invalid_phone" :"Invalid Phone Number"
                }}, status=400)
            if user[0].is_phone_verified == True:
                return Response({"error": {
                    "phone_already_verified" :"Phone number already verified. Proceed to login!"
                }}, status=400)
            Util.send_sms_otp(user)
            return Response({'success': 'New otp sent!'}, status=200)

class ResendEmailActivation(APIView):
    serializer_class = ResendActivationEmailSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        print(serializer)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data['email']
            user = User.objects.filter(email=email)
            if not user.exists():
                return Response({"error": {
                    "invalid_email" :"Invalid Email Address"
                }}, status=400)
            if user[0].is_email_verified == True:
                return Response({"error": {
                    "email_already_verified" :"Email address already verified. Proceed to login!"
                }}, status=400)

            Util.send_verification_email(request, user)
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
        print(serializer)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data['email']
            user = User.objects.filter(email=email)
            if not user.exists():
                return Response({"error": "Invalid email!"}, status=400)
            Util.send_password_change_otp(user[0].email)
            return Response({'success': 'Password Otp sent!'}, status=200)

class CheckPasswordResetOtp(APIView):
    serializer_class = CheckPasswordResetOtpSerializer
    permission_classes = (AllowAny,)
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            
            email = serializer.data['email']
            otp = serializer.data['otp']
            user_obj = User.objects.filter(email=email)
            if not user_obj.exists():
                return Response({"error": "Invalid email!"}, status=400)
            user = user_obj.first()
            if user.otp.code != otp:
                return Response({'error': 'Invalid otp!'}, status=400)
            if user.otp.check_otp_expiration == True:
                user.otp.code = None
                user.otp.save()
                return Response({'error': 'Otp has expired!. Request new otp'}, status=400)
            
            return Response({'success': 'Correct Otp'}, status=200)
    

class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            print(serializer)
            email = serializer.data['email']
            otp = serializer.data['otp']
            password = serializer.data['password']
            user_obj = User.objects.filter(email=email)
            if not user_obj.exists():
                return Response({"error": "Invalid email!"}, status=400)
            user = user_obj.first()
            if user.otp.code != otp:
                return Response({'error': 'Invalid otp!'}, status=400)
            if user.otp.check_otp_expiration == True:
                user.otp.code = None
                user.otp.save()
                return Response({'error': 'Otp session expired!. Request new otp'}, status=400)
            
            user.set_password(password)
            user.otp.code = None
            user.otp.save()
            user.save()
            return Response({'success': 'Password reset success!'}, status=200)

#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------
