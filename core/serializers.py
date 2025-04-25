from django.contrib.auth import authenticate
from rest_framework import serializers

from .models import (
    User,
    Property,
    AgentVerification,
    Booking,
    Gift,
    WithdrawalRequest,
    Wallet,
    Investment,
    ROIPayout,
    PrivateMembership,
    Review,
    Notification,
    Favorite,
    InstallmentPayment,
    WalletTransaction,
    HandymanService,
    HandymanProfile,
    ServiceRequest
)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'role',
                  'account_number', 'bank_name', 'primary_phone', 'secondary_phone']

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'role']
        extra_kwargs = {
            'role': {'required': False, 'default': 'customer'}
        }

    def validate_role(self, value):
        allowed_roles = ['customer', 'agent', 'investor', 'handyman']
        if value not in allowed_roles:
            raise serializers.ValidationError("You can only register as a customer, agent, investor, or handyman.")
        return value

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Invalid credentials")

class PropertySerializer(serializers.ModelSerializer):
    is_owner = serializers.SerializerMethodField()

    class Meta:
        model = Property
        fields = '__all__'
        read_only_fields = ['agent', 'is_approved', 'created_at', 'updated_at', 'is_verified']

    def get_is_owner(self, obj):
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            return obj.agent == request.user
        return False

    def validate_available_to(self, value):
        user = self.context['request'].user
        if value == 'members' and user.role not in ['admin', 'superadmin']:
            raise serializers.ValidationError("Only admins can mark properties as members-only.")
        return value

class AgentVerificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AgentVerification
        fields = '__all__'
        read_only_fields = ['status', 'user']

class BookingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Booking
        fields = '__all__'
        read_only_fields = ['user', 'status', 'total_price']


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = Wallet
        fields = ['balance', 'is_withdrawable']

class WithdrawalRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = WithdrawalRequest
        fields = '__all__'
        read_only_fields = ['agent', 'status', 'requested_at', 'created_at']

class GiftSerializer(serializers.ModelSerializer):
    sender_email = serializers.EmailField(source='sender.email', read_only=True)
    recipient_user_email = serializers.EmailField(source='recipient_user.email', read_only=True)
    property_title = serializers.CharField(source='property.title', read_only=True)

    class Meta:
        model = Gift
        fields = '__all__'
        read_only_fields = [
            'sender', 'recipient_user', 'gift_code',
            'accepted_at', 'declined_at', 'status',
            'created_at'
        ]

class InvestmentSerializer(serializers.ModelSerializer):
    property_title = serializers.CharField(source='property.title', read_only=True)

    class Meta:
        model = Investment
        fields = '__all__'
        read_only_fields = ['investor', 'investment_date']


class ROIPayoutSerializer(serializers.ModelSerializer):
    investment_id = serializers.IntegerField(source='investment.id', read_only=True)
    property_title = serializers.CharField(source='investment.property.title', read_only=True)
    investor_email = serializers.EmailField(source='investment.investor.email', read_only=True)

    class Meta:
        model = ROIPayout
        fields = ['id', 'investment_id', 'property_title', 'investor_email', 'payout_date', 'amount_paid']


class MembershipSerializer(serializers.ModelSerializer):
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = PrivateMembership
        fields = ['tier', 'start_date', 'end_date', 'is_active']


class ReviewSerializer(serializers.ModelSerializer):
    reviewer_email = serializers.EmailField(source='reviewer.email', read_only=True)
    property_title = serializers.CharField(source='property.title', read_only=True)
    agent_name = serializers.CharField(source='agent.full_name', read_only=True)

    class Meta:
        model = Review
        fields = '__all__'
        read_only_fields = ['reviewer', 'created_at']


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'message', 'created_at', 'is_read']


class FavoriteSerializer(serializers.ModelSerializer):
    property_title = serializers.CharField(source='property.title', read_only=True)

    class Meta:
        model = Favorite
        fields = ['id', 'property', 'property_title', 'created_at']
        read_only_fields = ['created_at']

class InstallmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = InstallmentPayment
        fields = '__all__'

class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = '__all__'

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email',
                  'account_number', 'bank_name', 'primary_phone', 'secondary_phone']

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField()


# Public agent/user info serializer
class PublicUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'primary_phone', 'secondary_phone']


class HandymanServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = HandymanService
        fields = '__all__'


class HandymanProfileSerializer(serializers.ModelSerializer):
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()
    services_list = serializers.SerializerMethodField()

    class Meta:
        model = HandymanProfile
        fields = '__all__'
        read_only_fields = ['user', 'status', 'submitted_at']

    def get_user_name(self, obj):
        return f"{obj.user.first_name} {obj.user.last_name}".strip()

    def get_services_list(self, obj):
        return HandymanServiceSerializer(obj.services.all(), many=True).data


class ServiceRequestSerializer(serializers.ModelSerializer):
    customer_name = serializers.SerializerMethodField()
    handyman_name = serializers.SerializerMethodField()
    service_name = serializers.CharField(source='service.name', read_only=True)

    class Meta:
        model = ServiceRequest
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']

    def get_customer_name(self, obj):
        return f"{obj.customer.first_name} {obj.customer.last_name}".strip()

    def get_handyman_name(self, obj):
        return f"{obj.handyman.first_name} {obj.handyman.last_name}".strip()