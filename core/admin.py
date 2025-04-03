from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, Property, AgentVerification, Booking, Wallet,
    WithdrawalRequest, Gift, Investment, ROIPayout,
    PrivateMembership, Review, Notification, Favorite,
    InstallmentPayment, WalletTransaction,
    PendingGift, PendingBooking, PendingInvestment
)

# === USER ADMIN ===
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'role', 'is_active', 'is_staff')
    list_filter = ('role', 'is_staff', 'is_active')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'primary_phone', 'secondary_phone')}),
        ('Bank Details', {'fields': ('account_number', 'bank_name')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'role', 'is_staff', 'is_active')}
        ),
    )

# === PROPERTY ADMIN ===
@admin.register(Property)
class PropertyAdmin(admin.ModelAdmin):
    list_display = ('title', 'location', 'property_type', 'is_verified', 'is_approved', 'agent', 'created_at')
    list_filter = ('location', 'property_type', 'is_verified', 'is_approved')
    search_fields = ('title', 'description')
    readonly_fields = ('created_at', 'updated_at')

# === AGENT VERIFICATION ===
@admin.register(AgentVerification)
class AgentVerificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'status', 'submitted_at')
    list_filter = ('status',)
    readonly_fields = ('submitted_at',)

# === BOOKING ===
@admin.register(Booking)
class BookingAdmin(admin.ModelAdmin):
    list_display = ('user', 'property', 'check_in', 'check_out', 'status', 'payment_method', 'total_price')
    list_filter = ('status', 'payment_method')
    search_fields = ('user__email', 'property__title')

# === WALLET ===
@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ('user', 'balance', 'is_withdrawable')
    search_fields = ('user__email',)

# === WITHDRAWALS ===
@admin.register(WithdrawalRequest)
class WithdrawalRequestAdmin(admin.ModelAdmin):
    list_display = ('agent', 'amount', 'status', 'requested_at')
    list_filter = ('status',)

# === GIFTS ===
@admin.register(Gift)
class GiftAdmin(admin.ModelAdmin):
    list_display = ('sender', 'recipient_email', 'gifted_property', 'status', 'check_in', 'check_out')
    list_filter = ('status',)
    search_fields = ('sender__email', 'recipient_email')

# === INVESTMENTS ===
@admin.register(Investment)
class InvestmentAdmin(admin.ModelAdmin):
    list_display = ('investor', 'property', 'amount_invested', 'plan_years', 'roi_percentage', 'active')
    list_filter = ('plan_years', 'active')
    search_fields = ('investor__email', 'property__title')

# === ROI PAYOUTS ===
@admin.register(ROIPayout)
class ROIPayoutAdmin(admin.ModelAdmin):
    list_display = ('investment', 'amount_paid', 'payout_date')
    search_fields = ('investment__investor__email',)

# === MEMBERSHIP ===
@admin.register(PrivateMembership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ('user', 'tier', 'start_date', 'end_date')
    list_filter = ('tier',)

# === REVIEWS ===
@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ('reviewer', 'review_type', 'rating', 'created_at')
    list_filter = ('review_type', 'rating')

# === NOTIFICATIONS ===
@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'message', 'is_read', 'created_at')
    list_filter = ('is_read',)

# === FAVORITES ===
@admin.register(Favorite)
class FavoriteAdmin(admin.ModelAdmin):
    list_display = ('user', 'property', 'created_at')

# === INSTALLMENTS ===
@admin.register(InstallmentPayment)
class InstallmentAdmin(admin.ModelAdmin):
    list_display = ('investment', 'due_date', 'amount_due', 'is_paid', 'date_paid')
    list_filter = ('is_paid',)

# === WALLET TRANSACTIONS ===
@admin.register(WalletTransaction)
class WalletTransactionAdmin(admin.ModelAdmin):
    list_display = ('user', 'amount', 'transaction_type', 'description', 'timestamp')
    list_filter = ('transaction_type',)

# === PENDING GIFT ===
@admin.register(PendingGift)
class PendingGiftAdmin(admin.ModelAdmin):
    list_display = ('sender', 'recipient_email', 'gifted_property', 'is_paid', 'created_at')

# === PENDING BOOKING ===
@admin.register(PendingBooking)
class PendingBookingAdmin(admin.ModelAdmin):
    list_display = ('user', 'property', 'check_in', 'check_out', 'is_paid', 'created_at')

# === PENDING INVESTMENT ===
@admin.register(PendingInvestment)
class PendingInvestmentAdmin(admin.ModelAdmin):
    list_display = ('user', 'property', 'amount_invested', 'plan_years', 'is_paid', 'created_at')
