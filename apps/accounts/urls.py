from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.RegisterView.as_view()),
    path('login/', views.LoginView.as_view()),
    path('refresh/', views.RefreshView.as_view()),
    path('logout/', views.LogoutView.as_view()),

    # EMAIL ACTIVATION AND PHONE VERIFICATION
    path('activate-user/<uidb64>/<token>', views.VerifyEmail.as_view(), name="activate"),
    path('verify-phone/', views.VerifyPhone.as_view(), name="verify-phone"),
    path('resend-activation-email/', views.ResendEmailActivation.as_view()),
    path('resend-phone-otp/', views.ResendPhoneOtp.as_view(), name="resend-otp"),

    # path('register/', views.RegisterView.as_view()),
    # path('register/', views.RegisterView.as_view()),
    # path('register/', views.RegisterView.as_view()),
    # path('register/', views.RegisterView.as_view()),

]