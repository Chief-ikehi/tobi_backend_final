from django.contrib import admin
from .models import User, Property, Gift, Investment, Wallet, Review, Notification, AgentVerification, InstallmentPayment, ROIPayout
from .models import PendingGift, Booking

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'role', 'is_active', 'is_staff')
    search_fields = ('email',)
    list_filter = ('role',)

admin.site.register(Property)
admin.site.register(Gift)
admin.site.register(Investment)
admin.site.register(Wallet)
admin.site.register(Review)
admin.site.register(Notification)
admin.site.register(AgentVerification)
admin.site.register(InstallmentPayment)
admin.site.register(ROIPayout)
admin.site.register(Booking)
admin.site.register(PendingGift)
