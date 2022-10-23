from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from user import models


# Register your models here.
class AdminUser(UserAdmin):
    ordering = ("-date_joined",)
    search_fields = ("username", "email", "phone_number")
    list_filter = (
        "is_active",
        "is_staff",
        "is_superuser",
    )
    list_display = ("username", "email", "date_joined", "is_active")
    fieldsets = (
        ("Login Info", {"fields": ("username", "email", "password")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                )
            },
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("username", "email", "password1", "password2"),
            },
        ),
    )


class AdminUserInformation(admin.ModelAdmin):
    ordering = ("-created_at",)
    search_fields = (
        "username",
        "email",
        "first_name",
        "last_name",
        "phone_number",
    )
    list_filter = ("is_active", "gender")
    list_display = (
        "user",
        "first_name",
        "last_name",
        "country",
        "is_active",
        "created_at",
    )
    fieldsets = (
        ("User", {"fields": ("user",)}),
        (
            "User Information",
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "gender",
                    "profile_pic",
                    "birth_date",
                )
            },
        ),
        (
            "Contact Information",
            {
                "fields": (
                    "address_one",
                    "address_two",
                    "city",
                    "zipcode",
                    "country",
                    "phone_number",
                )
            },
        ),
    )


admin.site.register(models.User, AdminUser)
admin.site.register(models.UserInformationModel, AdminUserInformation)
admin.site.register(models.OTPModel)
