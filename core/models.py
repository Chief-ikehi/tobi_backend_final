from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.conf import settings
import uuid
from django.db.models.signals import pre_save
from django.dispatch import receiver
from datetime import date

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'superadmin')

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = [
        ('customer', 'Customer'),
        ('investor', 'Investor'),
        ('agent', 'Agent'),
        ('admin', 'Admin'),
        ('superadmin', 'Superadmin'),
    ]

    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    account_number = models.CharField(max_length=20, blank=True, null=True)
    bank_name = models.CharField(max_length=100, blank=True, null=True)
    primary_phone = models.CharField(max_length=20, blank=True, null=True)
    secondary_phone = models.CharField(max_length=20, blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='customer')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

class Property(models.Model):
    PROPERTY_TYPE_CHOICES = [
        ('shortlet', 'Shortlet'),
        ('investment', 'Investment'),
        ('hybrid', 'Hybrid'),
    ]

    LOCATION_CHOICES = [
        ('ikoyi', 'Ikoyi'),
        ('vi', 'Victoria Island'),
    ]

    AVAILABLE_TO_CHOICES = [
        ('all', 'All Users'),
        ('members', 'Private Members Only')
    ]

    agent = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='listed_properties')
    title = models.CharField(max_length=255)
    description = models.TextField()
    location = models.CharField(max_length=20, choices=LOCATION_CHOICES)
    property_type = models.CharField(max_length=20, choices=PROPERTY_TYPE_CHOICES)

    price_per_night = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    investment_cost = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    roi_percentage = models.FloatField(null=True, blank=True)

    commission_percentage = models.FloatField(default=5.0)
    amenities = models.TextField(help_text="Comma-separated list", blank=True)
    images = models.JSONField(default=list, help_text="List of image URLs")
    virtual_tour_url = models.URLField(blank=True, null=True)
    proof_of_listing = models.URLField(blank=True, null=True)

    available_to = models.CharField(
        max_length=10,
        choices=AVAILABLE_TO_CHOICES,
        default='all'
    )

    is_verified = models.BooleanField(default=False)
    is_approved = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} ({self.location})"

def user_directory_path(instance, filename):
    return f'agents/{instance.user.id}/{filename}'

class AgentVerification(models.Model):
    STATUS_CHOICES = [
        ('unverified', 'Unverified'),
        ('pending', 'Pending Review'),
        ('verified', 'Verified'),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='verification')

    valid_id = models.FileField(upload_to=user_directory_path)
    cac_certificate = models.FileField(upload_to=user_directory_path)
    business_proof = models.FileField(upload_to=user_directory_path)
    authorization_letter = models.FileField(upload_to=user_directory_path)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='unverified')
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"AgentVerification({self.user.email})"

class Booking(models.Model):
    PAYMENT_CHOICES = [
        ('flutterwave', 'Flutterwave'),
        ('wallet', 'Wallet Credit'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('cancelled', 'Cancelled'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='bookings')
    property = models.ForeignKey(Property, on_delete=models.CASCADE, related_name='bookings')

    check_in = models.DateField()
    check_out = models.DateField()
    payment_method = models.CharField(max_length=20, choices=PAYMENT_CHOICES)
    total_price = models.DecimalField(max_digits=12, decimal_places=2)
    status = models.CharField(
        max_length=20,
        choices=[('pending', 'Pending'), ('confirmed', 'Confirmed'), ('cancelled', 'Cancelled')],
        default='confirmed'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Booking({self.user.email} - {self.property.title})"

    class Meta:
        ordering = ['-created_at']

class Wallet(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="wallet")
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)
    is_withdrawable = models.BooleanField(default=False)  # True for agents, False for investors

    def __str__(self):
        return f"{self.user.email} Wallet: ₦{self.balance}"

class WithdrawalRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('declined', 'Declined'),
    ]

    agent = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="withdrawal_requests")
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.agent.email} requested ₦{self.amount}"

class Gift(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('declined', 'Declined'),
        ('expired', 'Expired'),
    ]

    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_gifts")
    recipient_email = models.EmailField()
    recipient_user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="received_gifts")

    gifted_property = models.ForeignKey(Property, on_delete=models.CASCADE)
    check_in = models.DateField()
    check_out = models.DateField()
    message = models.TextField(blank=True, null=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    declined_at = models.DateTimeField(null=True, blank=True)

    gift_code = models.CharField(max_length=100, unique=True)

    @property
    def is_expired(self):
        return date.today() > self.check_out and self.status == 'pending'

    def __str__(self):
        return f"Gift to {self.recipient_email} - {self.status}"

@receiver(pre_save, sender=Gift)
def set_gift_code(sender, instance, **kwargs):
    if not instance.gift_code:
        instance.gift_code = str(uuid.uuid4())

class Investment(models.Model):
    investor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='investments')
    property = models.ForeignKey(Property, on_delete=models.CASCADE)
    amount_invested = models.DecimalField(max_digits=15, decimal_places=2)
    investment_date = models.DateField(auto_now_add=True)
    roi_percentage = models.FloatField(default=5.0)  # Monthly ROI %
    active = models.BooleanField(default=True)
    plan_years = models.IntegerField(default=2)  # Either 2 or 3
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.investor.email} - {self.property.title} - ₦{self.amount_invested}"


class ROIPayout(models.Model):
    investment = models.ForeignKey(Investment, on_delete=models.CASCADE, related_name='roi_payouts')
    payout_date = models.DateField(auto_now_add=True)
    amount_paid = models.DecimalField(max_digits=15, decimal_places=2)

    def __str__(self):
        return f"{self.investment.investor.email} - {self.amount_paid} on {self.payout_date}"


class PrivateMembership(models.Model):
    TIER_CHOICES = [
        ('silver', 'Silver'),
        ('gold', 'Gold'),
        ('platinum', 'Platinum'),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='membership')
    tier = models.CharField(max_length=20, choices=TIER_CHOICES)
    start_date = models.DateField(auto_now_add=True)
    end_date = models.DateField()

    def __str__(self):
        return f"{self.user.email} - {self.tier.upper()} member"

    @property
    def is_active(self):
        from datetime import date
        return self.end_date >= date.today()

class Review(models.Model):
    REVIEW_TYPE_CHOICES = [
        ('property', 'Property'),
        ('agent', 'Agent'),
    ]

    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    review_type = models.CharField(max_length=20, choices=REVIEW_TYPE_CHOICES)
    property = models.ForeignKey(Property, null=True, blank=True, on_delete=models.CASCADE)
    agent = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.CASCADE, related_name='agent_reviews')

    rating = models.IntegerField()  # 1 to 5
    comment = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.review_type == 'property':
            return f"{self.reviewer.email} rated property {self.property.title}"
        else:
            return f"{self.reviewer.email} rated agent {self.agent.email}"

class Notification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"To {self.user.email}: {self.message[:30]}"

class Favorite(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='favorites')
    property = models.ForeignKey(Property, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'property')  # Prevent duplicate favorites

    def __str__(self):
        return f"{self.user.email} → {self.property.title}"

class InstallmentPayment(models.Model):
    investment = models.ForeignKey('Investment', on_delete=models.CASCADE, related_name='installments')
    due_date = models.DateField()
    amount_due = models.DecimalField(max_digits=15, decimal_places=2)
    is_paid = models.BooleanField(default=False)
    date_paid = models.DateField(null=True, blank=True)

    def __str__(self):
        return f"{self.investment.investor.email} | Due: {self.due_date} | Paid: {self.is_paid}"

class WalletTransaction(models.Model):
    TRANSACTION_TYPES = [
        ('credit', 'Credit'),
        ('debit', 'Debit'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='wallet_transactions')
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPES)
    description = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.transaction_type} - ₦{self.amount}"

class PendingGift(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    recipient_email = models.EmailField()
    gifted_property = models.ForeignKey(Property, on_delete=models.CASCADE)
    check_in = models.DateField()
    check_out = models.DateField()
    message = models.TextField(blank=True, null=True)
    total_price = models.DecimalField(max_digits=10, decimal_places=2)
    payment_reference = models.CharField(max_length=255, blank=True, null=True)
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PendingGift to {self.recipient_email} for {self.gifted_property.title}"

class PendingBooking(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    property = models.ForeignKey(Property, on_delete=models.CASCADE)
    check_in = models.DateField()
    check_out = models.DateField()
    total_price = models.DecimalField(max_digits=12, decimal_places=2)
    payment_method = models.CharField(max_length=20, choices=[('flutterwave', 'Flutterwave')])
    payment_reference = models.CharField(max_length=255, unique=True)
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PendingBooking({self.user.email}) → {self.property.title}"

class PendingInvestment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    property = models.ForeignKey(Property, on_delete=models.CASCADE)
    amount_invested = models.DecimalField(max_digits=12, decimal_places=2)
    plan_years = models.PositiveIntegerField(default=2)
    payment_reference = models.CharField(max_length=255, unique=True)
    is_paid = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"PendingInvestment({self.user.email} → {self.property.title})"