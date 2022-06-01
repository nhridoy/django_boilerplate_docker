from django.contrib import admin
from user import models
from django.contrib.auth.admin import UserAdmin


# Register your models here.
class AdminUser(UserAdmin):
    ordering = ('-date_joined',)
    search_fields = ('username', 'email', 'full_name', 'phone_number')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'gender')
    list_display = ('username', 'email', 'full_name', 'country', 'date_joined', 'is_active')
    fieldsets = (
        ('Login Info', {'fields': ('username', 'email', 'password')}),
        ('User Information',
         {'fields': (
             'full_name', 'gender', 'profile_pic', 'birth_date', 'address_one', 'address_two', 'city', 'zipcode',
             'country', 'phone_number',)}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser')}),

    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'full_name', 'password1', 'password2'),
        }),
    )


admin.site.register(models.User, AdminUser)