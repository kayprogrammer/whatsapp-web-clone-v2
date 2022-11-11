from rest_framework.permissions import BasePermission, SAFE_METHODS
from django.utils import timezone
from rest_framework.views import exception_handler
from rest_framework.response import Response
from apps.accounts.models import User

class IsAuthenticatedCustom(BasePermission):

    def has_permission(self, request, view):
        from apps.accounts.views import decodeJWT
        user = decodeJWT(request.META['HTTP_AUTHORIZATION'])
        if not user:
            return False
        request.user = user
        if request.user and request.user.is_authenticated:
            User.objects.filter(id=request.user.id).update(
                is_online=timezone.now())
            return True
        return False

class IsAdminCustom(BasePermission):

    def has_permission(self, request, view):
        from apps.accounts.views import decodeJWT
        user = decodeJWT(request.META['HTTP_AUTHORIZATION'])
        if not (user and user.is_staff):
            return False
        request.user = user
        if request.user and request.user.is_authenticated and request.user.is_staff:
            User.objects.filter(id=request.user.id).update(
                is_online=timezone.now())
            return True
        return False


class IsAuthenticatedOrReadCustom(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return True

        if request.user and request.user.is_authenticated:
            User.objects.filter(id=request.user.id).update(
                is_online=timezone.now())
            return True
        return False

def custom_exception_handler(exc, context):

    response = exception_handler(exc, context)

    if response is not None:
        return response

    exc_list = str(exc).split("DETAIL: ")

    return Response({"error": exc_list[-1]}, status=403)