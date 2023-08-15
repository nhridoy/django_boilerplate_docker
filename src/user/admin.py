from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from user import models


# Register your models here.
class AdminUser(UserAdmin):
    ordering = ("-date_joined",)
    search_fields = (
        "username",
        "email",
    )
    list_filter = (
        "is_active",
        "is_staff",
        "is_superuser",
    )
    list_display = (
        "username",
        "email",
        "date_joined",
        "is_email_verified",
        "is_active",
    )
    fieldsets = (
        (
            "Login Info",
            {
                "fields": (
                    "username",
                    "email",
                    "password",
                    "is_email_verified",
                )
            },
        ),
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
                "fields": (
                    "username",
                    "email",
                    "password1",
                    "password2",
                    "is_email_verified",
                ),
            },
        ),
    )


class AdminUserInformation(admin.ModelAdmin):
    ordering = ("-created_at",)
    autocomplete_fields = ("user",)
    search_fields = (
        "user__username",
        "user__email",
        "first_name",
        "last_name",
        "phone_number",
    )
    list_filter = ("status", "gender")
    list_display = (
        "user",
        "first_name",
        "last_name",
        "country",
        "status",
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


class AdminOTPModel(admin.ModelAdmin):
    exclude = ("status",)


admin.site.register(models.User, AdminUser)
admin.site.register(models.UserInformationModel, AdminUserInformation)
admin.site.register(models.OTPModel, AdminOTPModel)
