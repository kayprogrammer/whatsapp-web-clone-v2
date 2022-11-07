from django.urls import path
from . import views

urlpatterns = [
    # REGISTER AUTHENTICATION AND AUTHORIZATION
    path('register/', views.RegisterView.as_view()),
    path('login/', views.LoginView.as_view()),
    path('refresh/', views.RefreshView.as_view()),
    path('logout/', views.LogoutView.as_view()),

    # EMAIL ACTIVATION AND PHONE VERIFICATION
    path('verify-email/<uidb64>/<token>', views.VerifyEmail.as_view(), name="verify-email"),
    path('verify-phone/', views.VerifyPhone.as_view(), name="verify-phone"),
    path('resend-activation-email/', views.ResendEmailActivation.as_view()),
    path('resend-phone-otp/', views.ResendPhoneOtp.as_view(), name="resend-otp"),

    # PASSWORD RESET
    path('request-password-reset-email/', views.RequestPasswordResetEmail.as_view()),
    path('set-new-password/', views.SetNewPasswordAPIView.as_view()),
]