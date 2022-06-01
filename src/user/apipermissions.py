from rest_framework import permissions


class IsSuperUser(permissions.BasePermission):
    """
    Allows access only to superusers.
    """

    # message = "You don't have access to view this page"

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and (
            (request.user.is_active and request.user.is_staff and request.user.is_superuser)))
