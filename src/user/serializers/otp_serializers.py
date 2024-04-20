from rest_framework import serializers

from user import models


class OTPCreateSerializer(serializers.Serializer):
    """
    Serializer for QR create view
    """

    generated_key = serializers.CharField()
    otp = serializers.IntegerField(write_only=True)


class OTPCheckSerializer(serializers.ModelSerializer):
    """
    Serializer for checking if OTP is active or not
    """

    # detail = serializers.BooleanField(read_only=True)

    class Meta:
        model = models.OTPModel
        fields = ["is_active"]
