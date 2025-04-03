from datetime import datetime
from django.shortcuts import get_object_or_404
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from django.db.models.functions import TruncMonth
from django.db.models import Sum
from datetime import timedelta
from rest_framework.generics import RetrieveUpdateAPIView
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from .utils import notify
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions
from decimal import Decimal
from datetime import date
import uuid
from django.conf import settings
import requests
from dateutil.parser import parse as parse_date
from rest_framework.decorators import api_view, permission_classes
from rest_framework import status

MEMBERSHIP_PERKS = {
    "silver": [
        "5% discount on bookings",
        "Early access to new properties",
        "Access to exclusive booking slots",
        "Monthly newsletter with offers",
        "₦20,000 birthday credit",
        "Priority customer support",
        "1 free booking reschedule per month"
    ],
    "gold": [
        "All Silver benefits",
        "₦5M shortlet credit per investment",
        "Access to exclusive investment deals",
        "ROI tracking dashboard",
        "Personalized investment recommendations"
    ],
    "platinum": [
        "All Gold benefits",
        "Lifetime booking credit",
        "Gift properties without restriction",
        "Priority over other members for bookings",
        "Skip property approval (direct listing)",
        "Dedicated account manager",
        "Earn agent-level commissions on referrals"
    ]
}

from .models import (
    User,
    Property,
    Booking,
    Wallet,
    WithdrawalRequest,
    Gift,
    Investment,
    ROIPayout,
    PrivateMembership,
    Review,
    Notification,
    Favorite,
    AgentVerification,
    InstallmentPayment,
    WalletTransaction,
    PendingGift,
    PendingBooking,
    PendingInvestment
)

from .serializers import (
    UserSerializer,
    RegisterSerializer,
    LoginSerializer,
    PropertySerializer,
    AgentVerificationSerializer,
    BookingSerializer,
    WithdrawalRequestSerializer,
    GiftSerializer,
    WalletSerializer,
    InvestmentSerializer,
    ROIPayoutSerializer,
    MembershipSerializer,
    ReviewSerializer,
    NotificationSerializer,
    FavoriteSerializer,
    InstallmentSerializer,
    WalletTransactionSerializer,
    UserProfileSerializer,
    ChangePasswordSerializer,
    PublicUserSerializer
)

from .permissions import (
    IsAgent,
    IsAdmin,
    IsSuperAdmin
)

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        tokens = get_tokens_for_user(user)
        return Response({
            "user": UserSerializer(user).data,
            "tokens": tokens
        })

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        tokens = get_tokens_for_user(user)
        return Response({
            "user": UserSerializer(user).data,
            "tokens": tokens
        })

class ProfileView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        user = self.get_object()
        role_routes = {
            'customer': '/dashboard',
            'agent': '/dashboard',
            'investor': '/dashboard',
            'admin': '/dashboard',
            'superadmin': '/dashboard'
        }
        dashboard_path = role_routes.get(user.role, '/dashboard')

        return Response({
            'user': UserSerializer(user).data,
            'dashboard': dashboard_path
        })

class PropertyViewSet(viewsets.ModelViewSet):
    serializer_class = PropertySerializer

    def get_permissions(self):
        user = self.request.user

        if self.action == 'create':
            if not user.is_authenticated:
                return [permissions.IsAuthenticated()]
            if user.role in ['agent', 'admin', 'superadmin']:
                return [permissions.IsAuthenticated()]
            raise PermissionDenied("Only verified agents, admins, or superadmin can list properties.")

        elif self.action in ['update', 'partial_update']:
            return [permissions.IsAuthenticated()]

        elif self.action == 'destroy':
            if not user.is_authenticated or user.role not in ['admin', 'superadmin']:
                raise PermissionDenied("Only admins or superadmin can delete properties.")
            return [permissions.IsAuthenticated()]

        elif self.action in ['approve', 'list_all']:
            return [IsAdmin()]  # Define this elsewhere

        elif self.action in ['list', 'retrieve', 'my_listings']:
            return [permissions.AllowAny()]

        return super().get_permissions()

    def get_queryset(self):
        user = self.request.user
        action = getattr(self, 'action', None)

        # Default: show only approved + public listings
        queryset = Property.objects.filter(is_approved=True, available_to='all')

        if not user.is_authenticated:
            return queryset

        # AGENTS
        if user.role == 'agent':
            if action in ['retrieve', 'update', 'partial_update', 'destroy']:
                # Allow agents to access their own properties (even unapproved)
                return Property.objects.filter(agent=user)

            # Else (list or filters): public approved listings
            queryset = Property.objects.filter(is_approved=True)

            # Filter out member-only if not Silver+
            try:
                membership = PrivateMembership.objects.get(user=user)
                if membership.tier not in ['silver', 'gold', 'platinum']:
                    queryset = queryset.exclude(available_to='members')
            except PrivateMembership.DoesNotExist:
                queryset = queryset.exclude(available_to='members')

            return queryset

        # REGULAR USERS
        if user.role not in ['admin', 'superadmin']:
            queryset = Property.objects.filter(is_approved=True)
            try:
                membership = PrivateMembership.objects.get(user=user)
                if membership.tier not in ['silver', 'gold', 'platinum']:
                    queryset = queryset.exclude(available_to='members')
            except PrivateMembership.DoesNotExist:
                queryset = queryset.exclude(available_to='members')
            return queryset

        # ADMINS & SUPERADMINS
        queryset = Property.objects.all()

        # Apply optional query param filters
        params = self.request.query_params
        prop_type = params.get('type')
        location = params.get('location')
        min_price = params.get('min_price')
        max_price = params.get('max_price')
        only_favorites = params.get('only_favorites') == 'true'

        if prop_type and prop_type != 'all':
            queryset = queryset.filter(property_type=prop_type)

        if location:
            queryset = queryset.filter(location__icontains=location)

        if min_price:
            try:
                queryset = queryset.filter(price_per_night__gte=float(min_price))
            except ValueError:
                pass

        if max_price:
            try:
                queryset = queryset.filter(price_per_night__lte=float(max_price))
            except ValueError:
                pass

        if only_favorites and user.is_authenticated:
            queryset = queryset.filter(favorites__user=user)

        return queryset

    def perform_create(self, serializer):
        user = self.request.user

        if user.role == 'agent':
            if not hasattr(user, 'verification') or user.verification.status != 'verified':
                raise PermissionDenied("Agent not verified.")
            serializer.save(agent=user, is_approved=False)

        elif user.role in ['admin', 'superadmin']:
            serializer.save(agent=user, is_approved=True)

        else:
            raise PermissionDenied("Only verified agents, admins, or superadmin can list properties.")

    def perform_update(self, serializer):
        user = self.request.user
        instance = serializer.instance

        if user.role == 'agent':
            if instance.agent != user:
                raise PermissionDenied("You can only update your own properties.")
            if not hasattr(user, 'verification') or user.verification.status != 'verified':
                raise PermissionDenied("You must be verified to update a property.")
            serializer.save(is_approved=False)

        elif user.role in ['admin', 'superadmin']:
            serializer.save()

        else:
            raise PermissionDenied("You are not allowed to update this property.")

    def destroy(self, request, *args, **kwargs):
        user = request.user
        if user.role not in ['admin', 'superadmin']:
            raise PermissionDenied("Only admins and superadmin can delete properties.")
        return super().destroy(request, *args, **kwargs)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context.update({"request": self.request})
        return context

    @action(detail=False, methods=['get'])
    def my_listings(self, request):
        user = request.user

        if not user.is_authenticated:
            raise PermissionDenied("Authentication required.")

        if user.role not in ['agent', 'admin', 'superadmin']:
            raise PermissionDenied("Only agents, admins, or superadmin can view their listings.")

        properties = Property.objects.filter(agent=user)
        serializer = self.get_serializer(properties, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        prop = self.get_object()
        prop.is_approved = True
        prop.save()
        if prop.is_approved:
            notify(prop.agent, f"Your property '{prop.title}' has been approved and is now live.")
        return Response({'status': 'approved'})

    @action(detail=False, methods=['get'], url_path='by-agent/(?P<agent_id>[^/.]+)')
    def by_agent(self, request, agent_id=None):
        user = request.user
        if not user.is_authenticated or user.role not in ['admin', 'superadmin']:
            raise PermissionDenied("Only admins and superadmin can use this view.")

        properties = Property.objects.filter(agent_id=agent_id)
        serializer = self.get_serializer(properties, many=True)
        return Response(serializer.data)



class AgentVerificationView(generics.CreateAPIView):
    serializer_class = AgentVerificationSerializer
    permission_classes = [IsAgent]

    def post(self, request, *args, **kwargs):
        if hasattr(request.user, 'verification'):
            return Response({"detail": "You’ve already submitted verification."}, status=400)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user, status='pending')
        return Response(serializer.data, status=201)

class BookingView(generics.CreateAPIView):
    serializer_class = BookingSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        data = request.data.copy()

        try:
            property_id = int(data['property'])
            check_in = data['check_in']
            check_out = data['check_out']
            payment_method = data['payment_method']
        except KeyError:
            raise ValidationError("Missing fields: 'property', 'check_in', 'check_out', 'payment_method'")

        # Ensure property exists and is approved
        try:
            prop = Property.objects.get(id=property_id, is_approved=True)
        except Property.DoesNotExist:
            raise ValidationError("Property not found or not approved.")

        # Only shortlet or hybrid properties can be booked
        if prop.property_type not in ['shortlet', 'hybrid']:
            raise ValidationError("This property cannot be booked.")

        # Parse dates
        try:
            check_in_date = datetime.strptime(check_in, "%Y-%m-%d").date()
            check_out_date = datetime.strptime(check_out, "%Y-%m-%d").date()
        except ValueError:
            raise ValidationError("Invalid date format. Use YYYY-MM-DD.")

        # Validate date range
        nights = (check_out_date - check_in_date).days
        if nights < 1:
            raise ValidationError("Must book at least one night.")

        # Check for overlapping bookings
        overlapping = Booking.objects.filter(
            property=prop,
            status__in=['pending', 'confirmed'],
            check_in__lt=check_out_date,
            check_out__gt=check_in_date
        ).exists()
        if overlapping:
            raise ValidationError("Selected dates are not available for this property.")

        # Calculate base price
        total_price = prop.price_per_night * nights

        # Apply discount for Silver/Gold/Platinum members
        discount_applied = None
        try:
            membership = PrivateMembership.objects.get(user=user)
            if membership.tier in ['silver', 'gold', 'platinum']:
                total_price *= Decimal(0.95)  # Apply 5% discount
                discount_applied = membership.tier
        except PrivateMembership.DoesNotExist:
            pass  # No membership found

        # Handle wallet payment
        if payment_method == 'wallet':
            if user.role != 'investor':
                raise ValidationError("Only investors can pay with wallet credit.")

            if not hasattr(user, 'wallet'):
                raise ValidationError("Wallet not found. You must invest before using wallet credit.")

            if user.wallet.balance < total_price:
                raise ValidationError("Insufficient wallet balance.")

            # Deduct from wallet
            user.wallet.balance -= total_price
            user.wallet.save()

        # Create booking
        booking = Booking.objects.create(
            user=user,
            property=prop,
            check_in=check_in_date,
            check_out=check_out_date,
            payment_method=payment_method,
            total_price=total_price,
            status='confirmed'
        )

        # AUTO COMMISSION PAYOUT TO AGENT
        agent_user = prop.agent
        if agent_user and agent_user.role == 'agent':
            commission_percent = prop.commission_percentage or 5.0
            commission_amount = (Decimal(commission_percent) / Decimal('100')) * total_price

            agent_wallet, _ = Wallet.objects.get_or_create(
                user=agent_user,
                defaults={'balance': Decimal('0.00'), 'is_withdrawable': True}
            )

            agent_wallet.balance += commission_amount
            agent_wallet.save()

        notify(user, f"Your booking for '{prop.title}' from {check_in} to {check_out} has been confirmed.")

        serializer = BookingSerializer(booking)
        return Response({
            "booking": serializer.data,
            "discount_applied": discount_applied
        }, status=201)

class CancelBookingView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, booking_id):
        try:
            booking = Booking.objects.get(id=booking_id, user=request.user)
        except Booking.DoesNotExist:
            raise ValidationError("Booking not found.")

        if booking.status != 'confirmed':
            return Response({"error": "Booking already cancelled or not active."}, status=400)

        now_date = datetime.now().date()
        if booking.check_in <= now_date + timedelta(days=1):
            return Response({"error": "Bookings can only be cancelled more than 24 hours in advance."}, status=400)

        booking.status = 'cancelled'
        booking.save()

        return Response({"message": "Booking cancelled. Admin will process refund manually."})

class UpdateBookingView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, booking_id):
        try:
            booking = Booking.objects.get(id=booking_id, user=request.user)
        except Booking.DoesNotExist:
            raise ValidationError("Booking not found.")

        if booking.status != 'confirmed':
            return Response({"error": "Only confirmed bookings can be updated."}, status=400)

        # Block updates less than 24h before original check-in
        from datetime import datetime
        now_date = datetime.now().date()
        if booking.check_in <= now_date + timedelta(days=1):
            return Response({"error": "Cannot update booking within 24 hours of check-in."}, status=400)

        # Parse new dates
        new_check_in = request.data.get("check_in")
        new_check_out = request.data.get("check_out")

        if not new_check_in or not new_check_out:
            return Response({"error": "check_in and check_out are required."}, status=400)

        from datetime import datetime
        check_in = datetime.strptime(new_check_in, "%Y-%m-%d").date()
        check_out = datetime.strptime(new_check_out, "%Y-%m-%d").date()

        if check_out <= check_in:
            return Response({"error": "check_out must be after check_in."}, status=400)

        # Check for date conflict with other bookings on same property
        conflict = Booking.objects.filter(
            property=booking.property,
            status='confirmed',
            check_in__lt=check_out,
            check_out__gt=check_in
        ).exclude(id=booking.id).exists()

        if conflict:
            return Response({"error": "New dates overlap with an existing booking."}, status=400)

        # Update booking
        nights = (check_out - check_in).days
        new_price = booking.property.price_per_night * nights

        booking.check_in = check_in
        booking.check_out = check_out
        booking.total_price = new_price
        booking.save()

        return Response({
            "message": "Booking dates updated successfully.",
            "total_price": new_price
        })

class CreateAdminView(APIView):
    permission_classes = [IsSuperAdmin]

    def post(self, request):
        data = request.data
        email = data.get("email")
        password = data.get("password")
        first_name = data.get("first_name", "")
        last_name = data.get("last_name", "")

        if not email or not password:
            return Response({"error": "Email and password are required."}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email already exists."}, status=400)

        admin_user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            role="admin",
            is_staff=True
        )

        return Response(UserSerializer(admin_user).data, status=201)

class WithdrawalRequestView(generics.CreateAPIView):
    serializer_class = WithdrawalRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        if user.role != 'agent':
            raise PermissionDenied("Only agents can request withdrawal.")

        if not hasattr(user, 'wallet') or not user.wallet.is_withdrawable:
            raise ValidationError("You do not have a withdrawable wallet.")

        if user.wallet.balance <= 0:
            raise ValidationError("No funds available for withdrawal.")

        amount = request.data.get("amount")
        if not amount:
            raise ValidationError("Amount is required.")

        amount = float(amount)
        if amount > user.wallet.balance:
            raise ValidationError("Requested amount exceeds wallet balance.")

        request_obj = WithdrawalRequest.objects.create(agent=user, amount=amount)
        return Response({
            "message": "Withdrawal request submitted.",
            "request_id": request_obj.id
        }, status=201)

class WalletView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        if not hasattr(user, 'wallet'):
            return Response({"error": "You do not have a wallet."}, status=404)

        serializer = WalletSerializer(user.wallet)
        return Response(serializer.data)

class CreateGiftView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data

        try:
            recipient_email = data['recipient_email']
            property_id = data['gifted_property']
            check_in = data['check_in']
            check_out = data['check_out']
            message = data.get('message', '')
        except KeyError:
            raise ValidationError("Missing required fields.")

        # Ensure property is valid
        try:
            prop = Property.objects.get(id=property_id, is_approved=True)
        except Property.DoesNotExist:
            raise ValidationError("Property not found or not approved.")

        if prop.property_type not in ['shortlet', 'hybrid']:
            raise ValidationError("Only shortlets and hybrid properties can be gifted.")

        from datetime import datetime
        check_in_date = datetime.strptime(check_in, "%Y-%m-%d").date()
        check_out_date = datetime.strptime(check_out, "%Y-%m-%d").date()

        if (check_out_date - check_in_date).days < 1:
            raise ValidationError("Must book at least one night.")

        # 🔐 Prevent duplicate gift
        duplicate = Gift.objects.filter(
            sender=user,
            recipient_email=recipient_email,
            gifted_property_id=property_id,
            check_in=check_in_date,
            check_out=check_out_date,
            status='pending'
        ).exists()

        if duplicate:
            return Response({"error": "You've already sent this gift."}, status=400)

        # Calculate total price
        nights = (check_out_date - check_in_date).days
        total_price = prop.price_per_night * nights

        # (Later: Add payment gateway logic)

        # Check if recipient is already registered
        try:
            recipient_user = User.objects.get(email=recipient_email)
        except User.DoesNotExist:
            recipient_user = None  # Recipient will use gift code later

        # Create gift
        gift = Gift.objects.create(
            sender=user,
            recipient_email=recipient_email,
            recipient_user=recipient_user,
            gifted_property=prop,
            check_in=check_in_date,
            check_out=check_out_date,
            message=message
        )

        # Notify sender and recipient
        notify(user, f"You’ve sent a gift to {recipient_email} for '{prop.title}' ({check_in} to {check_out}).")
        if recipient_user:
            notify(recipient_user, f"You’ve received a gift from {user.email} for '{prop.title}'.")

        return Response({
            "message": "Gift created successfully.",
            "gift_code": gift.gift_code,
            "status": gift.status
        })

class RespondToGiftView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        gift_id = request.data.get("gift_id")
        response = request.data.get("response")  # 'accept' or 'decline'

        if not gift_id or not response:
            raise ValidationError("Both 'gift_id' and 'response' are required.")

        try:
            gift = Gift.objects.get(id=gift_id)
        except Gift.DoesNotExist:
            return Response({"error": "Gift not found."}, status=404)

        if gift.recipient_email != request.user.email:
            return Response({"error": "You are not the intended recipient."}, status=403)

        if gift.status != "pending":
            return Response({"error": f"This gift has already been {gift.status}."}, status=400)

        if gift.is_expired:
            gift.status = "expired"
            gift.save()
            return Response({"error": "This gift has expired."}, status=400)

        if response == "accept":
            # Prevent duplicate booking
            existing_booking = Booking.objects.filter(
                user=request.user,
                property=gift.gifted_property,
                check_in=gift.check_in,
                check_out=gift.check_out
            ).exists()

            if existing_booking:
                return Response({"error": "You already have a booking for this property and date."}, status=400)

            # Calculate total price
            nights = (gift.check_out - gift.check_in).days
            total_price = gift.gifted_property.price_per_night * Decimal(nights)

            # Create booking
            booking = Booking.objects.create(
                user=request.user,
                property=gift.gifted_property,
                check_in=gift.check_in,
                check_out=gift.check_out,
                total_price=total_price,
                payment_method="wallet",  # even though sender paid, we mark it as wallet
                status="confirmed"
            )

            # Log a wallet transaction against the sender
            WalletTransaction.objects.create(
                user=gift.sender,
                amount=total_price,
                transaction_type="debit",
                description=f"Gifted booking for {request.user.email}"
            )

            # Update gift
            gift.status = "accepted"
            gift.accepted_at = timezone.now()
            gift.recipient_user = request.user
            gift.save()

            # Notify both users
            notify(request.user, f"You accepted a gift for '{gift.gifted_property.title}'. Booking confirmed.")
            notify(gift.sender, f"{request.user.email} accepted your gift for '{gift.gifted_property.title}'.")

            return Response({
                "message": "Gift accepted. Booking confirmed.",
                "booking_id": booking.id
            })

        elif response == "decline":
            gift.status = "declined"
            gift.declined_at = timezone.now()
            gift.save()

            notify(gift.sender, f"{request.user.email} declined your gift for '{gift.gifted_property.title}'.")
            return Response({"message": "Gift declined."})

        return Response({"error": "Invalid response option."}, status=400)

class ReassignGiftView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        gift_code = request.data.get("gift_code")
        new_email = request.data.get("new_recipient_email")

        if not gift_code or not new_email:
            raise ValidationError("gift_code and new_recipient_email are required.")

        try:
            gift = Gift.objects.get(gift_code=gift_code)
        except Gift.DoesNotExist:
            raise ValidationError("Gift not found.")

        if gift.sender != user:
            raise PermissionDenied("You are not allowed to reassign this gift.")

        if gift.status != 'pending':
            return Response({"error": f"This gift has already been {gift.status} and cannot be reassigned."}, status=400)

        if gift.is_expired:
            gift.status = 'expired'
            gift.save()
            return Response({"error": "Gift has expired and cannot be reassigned."}, status=400)

        if new_email == gift.recipient_email:
            return ValidationError("The new email must be different from the current recipient.")

        # Reassign the gift
        gift.recipient_email = new_email
        gift.recipient_user = None  # Reset recipient link
        gift.save()

        return Response({
            "message": "Gift reassigned successfully.",
            "new_recipient_email": new_email,
            "gift_code": gift.gift_code
        })

class InitiateGiftPaymentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data

        try:
            recipient_email = data['recipient_email']
            property_id = data['gifted_property']
            check_in = data['check_in']
            check_out = data['check_out']
            message = data.get('message', '')
        except KeyError:
            raise ValidationError("Missing required fields.")

        from dateutil.parser import parse as parse_date
        check_in_date = parse_date(check_in).date()
        check_out_date = parse_date(check_out).date()

        if (check_out_date - check_in_date).days < 1:
            raise ValidationError("Must book at least one night.")

        try:
            prop = Property.objects.get(id=property_id, is_approved=True)
        except Property.DoesNotExist:
            raise ValidationError("Invalid or unapproved property.")

        if prop.property_type not in ['shortlet', 'hybrid']:
            raise ValidationError("Only shortlet or hybrid properties can be gifted.")

        # Check for duplicates
        exists = PendingGift.objects.filter(
            sender=user,
            recipient_email=recipient_email,
            gifted_property=prop,
            check_in=check_in_date,
            check_out=check_out_date,
            is_paid=False
        ).exists()

        if exists:
            return Response({"error": "You already initiated this gift payment."}, status=400)

        # Calculate total
        nights = (check_out_date - check_in_date).days
        total_price = prop.price_per_night * nights

        # Generate unique tx_ref
        tx_ref = f"gift-{uuid.uuid4()}"

        # Save PendingGift
        pending = PendingGift.objects.create(
            sender=user,
            recipient_email=recipient_email,
            gifted_property=prop,
            check_in=check_in_date,
            check_out=check_out_date,
            message=message,
            total_price=total_price,
            payment_reference=tx_ref,
        )

        # Generate Flutterwave payment link
        payment_data = {
            "tx_ref": tx_ref,
            "amount": str(total_price),
            "currency": "NGN",
            "redirect_url": settings.FLUTTERWAVE_REDIRECT_URL,
            "customer": {
                "email": user.email,
                "name": f"{user.first_name} {user.last_name}"
            },
            "customizations": {
                "title": f"Gifting: {prop.title}",
                "description": f"Gift for {recipient_email}"
            }
        }

        flutter_url = "https://api.flutterwave.com/v3/payments"
        headers = {
            "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        response = requests.post(flutter_url, json=payment_data, headers=headers)

        if response.status_code != 200:
            pending.delete()
            return Response({"error": "Payment gateway error. Try again."}, status=500)

        return Response({
            "payment_link": response.json()['data']['link'],
            "tx_ref": tx_ref
        })

class VerifyGiftPaymentView(APIView):
    permission_classes = [permissions.AllowAny]  # frontend handles public verification

    def get(self, request):
        tx_ref = request.query_params.get("tx_ref")

        if not tx_ref:
            return Response({"error": "Transaction reference is required."}, status=400)

        try:
            pending = PendingGift.objects.get(payment_reference=tx_ref, is_paid=False)
        except PendingGift.DoesNotExist:
            return Response({"error": "Invalid or already processed gift payment."}, status=404)

        # Verify with Flutterwave
        url = f"https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref={tx_ref}"
        headers = {
            "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}"
        }

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return Response({"error": "Payment verification failed."}, status=502)

        result = response.json()

        if result['status'] != 'success' or result['data']['status'] != 'successful':
            return Response({"error": "Transaction not successful."}, status=400)

        # Check amount matches
        paid_amount = float(result['data']['amount'])
        if paid_amount < float(pending.total_price):
            return Response({"error": "Underpaid transaction."}, status=400)

        # Create Gift object
        gift = Gift.objects.create(
            sender=pending.sender,
            recipient_email=pending.recipient_email,
            gifted_property=pending.gifted_property,
            check_in=pending.check_in,
            check_out=pending.check_out,
            message=pending.message,
            status="pending",  # recipient still has to accept
            gift_code=str(uuid.uuid4())
        )

        # Mark pending gift complete
        pending.is_paid = True
        pending.save()

        # Send notification (optional)
        notify(pending.sender, f"Your gift to {pending.recipient_email} was sent successfully.")
        if gift.recipient_user:
            notify(gift.recipient_user, f"You received a gift from {pending.sender.email}.")

        return Response({
            "message": "Gift created successfully.",
            "gift_id": gift.id,
            "gift_code": gift.gift_code
        })

class AdminGiftListView(generics.ListAPIView):
    serializer_class = GiftSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role not in ['admin', 'superadmin']:
            raise PermissionDenied("Only admins and superadmin can view all gifts.")
        return Gift.objects.all().order_by('-created_at')

class InvestmentView(generics.CreateAPIView):
    serializer_class = InvestmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        if user.role != 'investor':
            raise PermissionDenied("Only investors can invest.")

        data = request.data
        property_id = data.get('property')
        amount = float(data.get('amount_invested', 0))
        plan_years = int(data.get('plan_years', 2))  # default to 2 years

        if plan_years not in [2, 3]:
            raise ValidationError("Plan must be 2 or 3 years.")

        if amount <= 0:
            raise ValidationError("Investment amount must be positive.")

        # Fetch the property
        try:
            prop = Property.objects.get(id=property_id, is_approved=True, property_type__in=['investment', 'hybrid'])
        except Property.DoesNotExist:
            raise ValidationError("Property not found or not eligible for investment.")

        property_cost = float(prop.investment_cost)
        min_required = 0.6 * property_cost

        if amount < min_required:
            raise ValidationError(f"Minimum investment is 60% of property cost: ₦{min_required:,.0f}")

        if amount > property_cost:
            raise ValidationError(f"You cannot invest more than 100% of the property cost: ₦{property_cost:,.0f}")

        # Determine membership tier
        if amount == property_cost:
            tier = 'platinum'
        else:
            tier = 'gold'

        # Create investment
        investment = Investment.objects.create(
            investor=user,
            property=prop,
            amount_invested=amount,
            roi_percentage=prop.roi_percentage or 5.0,
            plan_years=plan_years
        )

        notify(user, f"You’ve successfully invested ₦{amount} in '{prop.title}'. ₦5M booking credit added.")

        # Wallet credit
        wallet, _ = Wallet.objects.get_or_create(user=user, defaults={'balance': 0, 'is_withdrawable': False})
        wallet.balance += 5000000
        wallet.save()

        # Membership logic
        membership, created = PrivateMembership.objects.get_or_create(
            user=user,
            defaults={
                "tier": tier,
                "start_date": date.today(),
                "end_date": date.today() + timedelta(days=365)
            }
        )

        if not created:
            if membership.tier != 'platinum':
                membership.tier = tier
            membership.end_date = max(membership.end_date, date.today() + timedelta(days=365))
            membership.save()

        # Calculate monthly repayment (only if not full payment)
        remaining = property_cost - amount
        total_months = plan_years * 12
        monthly_payment = 0
        if tier == 'gold':
            monthly_payment = remaining / total_months

            for i in range(total_months):
                from dateutil.relativedelta import relativedelta
                due_date = date.today() + relativedelta(months=i + 1)
                InstallmentPayment.objects.create(
                    investment=investment,
                    due_date=due_date,
                    amount_due=round(monthly_payment, 2)
                )

        return Response({
            "message": f"Investment successful. ₦5M credit added. {tier.capitalize()} membership activated.",
            "investment_id": investment.id,
            "property_cost": property_cost,
            "amount_invested": amount,
            "remaining_balance": remaining,
            "plan_years": plan_years,
            "monthly_payment": round(monthly_payment, 2)
        }, status=201)

class ROIPayoutCreateView(generics.CreateAPIView):
    serializer_class = ROIPayoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        if user.role not in ['admin', 'superadmin']:
            raise PermissionDenied("Only admins can log ROI payouts.")

        investment_id = request.data.get("investment_id")
        try:
            investment = Investment.objects.get(id=investment_id)
        except Investment.DoesNotExist:
            raise ValidationError("Invalid investment ID.")

        # Calculate ROI payout
        roi_rate = investment.roi_percentage or 5.0
        roi_amount = (roi_rate / 100) * float(investment.amount_invested)

        # Create payout entry
        roi = ROIPayout.objects.create(investment=investment, amount_paid=roi_amount)

        notify(investment.investor,
               f"You received an ROI payout of ₦{roi.amount_paid} for '{investment.property.title}'.")

        return Response({
            "message": "ROI payout logged.",
            "amount_paid": roi.amount_paid,
            "payout_date": roi.payout_date
        })

class InvestorROIPayoutListView(generics.ListAPIView):
    serializer_class = ROIPayoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.role != 'investor':
            raise PermissionDenied("Only investors can view ROI payouts.")
        return ROIPayout.objects.filter(investment__investor=user).order_by('-payout_date')

class ROIGrowthChartView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'investor':
            raise PermissionDenied("Only investors can view ROI growth.")

        # Group payouts by month
        data = ROIPayout.objects.filter(investment__investor=user)\
            .annotate(month=TruncMonth('payout_date'))\
            .values('month')\
            .annotate(monthly_total=Sum('amount_paid'))\
            .order_by('month')

        # Format for frontend chart
        chart_data = [
            {
                "month": entry['month'].strftime('%Y-%m'),
                "amount": float(entry['monthly_total'])
            }
            for entry in data
        ]

        # Cumulative sum
        total_roi = sum(entry['amount'] for entry in chart_data)

        return Response({
            "chart_data": chart_data,
            "total_roi": total_roi
        })

class InvestmentROIPayoutHistoryView(generics.ListAPIView):
    serializer_class = ROIPayoutSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        investment_id = self.kwargs['investment_id']

        investment = get_object_or_404(Investment, id=investment_id)

        if investment.investor != user:
            raise PermissionDenied("You can only view ROI for your own investments.")

        return ROIPayout.objects.filter(investment=investment).order_by('-payout_date')

class MyMembershipView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        try:
            membership = user.membership
        except PrivateMembership.DoesNotExist:
            return Response({"tier": "none", "is_active": False})

        serializer = MembershipSerializer(membership)
        return Response(serializer.data)

class CreateReviewView(generics.CreateAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data

        review_type = data.get('review_type')
        rating = int(data.get('rating', 0))
        comment = data.get('comment', '')

        if review_type not in ['property', 'agent']:
            raise ValidationError("Invalid review type.")

        if rating < 1 or rating > 5:
            raise ValidationError("Rating must be between 1 and 5.")

        if review_type == 'property':
            property_id = data.get('property')
            try:
                prop = Property.objects.get(id=property_id)
            except Property.DoesNotExist:
                raise ValidationError("Property not found.")

            review = Review.objects.create(
                reviewer=user,
                review_type='property',
                property=prop,
                rating=rating,
                comment=comment
            )

        elif review_type == 'agent':
            agent_id = data.get('agent')
            try:
                agent_user = User.objects.get(id=agent_id, role='agent')
            except User.DoesNotExist:
                raise ValidationError("Agent not found.")

            review = Review.objects.create(
                reviewer=user,
                review_type='agent',
                agent=agent_user,
                rating=rating,
                comment=comment
            )

        serializer = ReviewSerializer(review)
        return Response(serializer.data, status=201)

class PropertyReviewListView(generics.ListAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        property_id = self.kwargs['property_id']
        return Review.objects.filter(review_type='property', property_id=property_id).order_by('-created_at')

class AgentReviewListView(generics.ListAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        agent_id = self.kwargs['agent_id']
        return Review.objects.filter(review_type='agent', agent_id=agent_id).order_by('-created_at')


class UserNotificationsView(generics.ListAPIView):
    serializer_class = NotificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user).order_by('-created_at')


class MarkNotificationReadView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, notification_id):
        try:
            notification = Notification.objects.get(id=notification_id, user=request.user)
        except Notification.DoesNotExist:
            raise ValidationError("Notification not found.")

        notification.is_read = True
        notification.save()
        return Response({"message": "Marked as read."})

class ToggleFavoriteView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        property_id = request.data.get('property')

        try:
            prop = Property.objects.get(id=property_id)
        except Property.DoesNotExist:
            raise ValidationError("Property not found.")

        # Enforce role-based restriction
        if user.role == 'customer' and prop.property_type == 'investment':
            raise PermissionDenied("Only investors can favorite investment properties.")

        favorite, created = Favorite.objects.get_or_create(user=user, property=prop)

        if not created:
            favorite.delete()
            return Response({"message": "Property unfavorited."})
        else:
            return Response({"message": "Property favorited."})

class MyFavoritesView(generics.ListAPIView):
    serializer_class = FavoriteSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Favorite.objects.filter(user=self.request.user).order_by('-created_at')

class SwitchRoleView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        new_role = request.data.get('role')

        valid_roles = ['customer', 'agent', 'investor']
        if new_role not in valid_roles:
            raise ValidationError("Invalid role.")

        # Prevent switching from admin/superadmin
        if user.role in ['admin', 'superadmin']:
            return Response({"error": "Admins cannot switch roles."}, status=403)

        user.role = new_role
        user.save()

        # Check agent verification status if switching to agent
        requires_verification = False
        if new_role == 'agent':
            try:
                verification = AgentVerification.objects.get(user=user)
                if verification.status != 'verified':
                    requires_verification = True
            except AgentVerification.DoesNotExist:
                requires_verification = True

        return Response({
            "message": f"Your role has been switched to {new_role}.",
            "requires_verification": requires_verification
        })

class MyInstallmentsView(generics.ListAPIView):
    serializer_class = InstallmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return InstallmentPayment.objects.filter(investment__investor=self.request.user).order_by('due_date')

class MarkInstallmentPaidView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, installment_id):
        user = request.user
        if user.role not in ['admin', 'superadmin']:
            raise PermissionDenied("Only admins can mark payments as paid.")

        try:
            inst = InstallmentPayment.objects.get(id=installment_id)
        except InstallmentPayment.DoesNotExist:
            raise ValidationError("Installment not found.")

        if inst.is_paid:
            return Response({"message": "This installment is already marked as paid."})

        inst.is_paid = True
        inst.date_paid = date.today()
        inst.save()

        return Response({"message": "Installment marked as paid."})

class WalletTransactionHistoryView(generics.ListAPIView):
    serializer_class = WalletTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return WalletTransaction.objects.filter(user=self.request.user).order_by('-timestamp')


from django.db.models import Q
class PropertyBookingCalendarView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, property_id):
        from datetime import date

        # Get confirmed or pending bookings for that property
        bookings = Booking.objects.filter(
            property_id=property_id,
            status__in=['confirmed', 'pending'],
            check_out__gte=date.today()  # Only future or current bookings
        ).values('check_in', 'check_out')

        # Format into date ranges
        booked_ranges = [
            {
                "check_in": booking["check_in"],
                "check_out": booking["check_out"]
            }
            for booking in bookings
        ]

        return Response({
            "property_id": property_id,
            "booked_ranges": booked_ranges
        })


class GrantSilverMembershipView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user

        # For now: only customer or investor can get Silver
        if user.role not in ['customer', 'investor']:
            raise ValidationError("Only regular users can subscribe to Silver membership.")

        # Duration based on plan
        plan = request.data.get("plan", "monthly")  # monthly or yearly

        if plan not in ['monthly', 'yearly']:
            raise ValidationError("Invalid plan. Must be 'monthly' or 'yearly'.")

        from datetime import date, timedelta
        duration = 30 if plan == 'monthly' else 365

        membership, created = PrivateMembership.objects.get_or_create(
            user=user,
            defaults={
                "tier": "silver",
                "start_date": date.today(),
                "end_date": date.today() + timedelta(days=duration)
            }
        )

        if not created:
            if membership.tier != 'platinum':  # Don't downgrade platinum
                membership.tier = 'silver'
            membership.end_date = max(membership.end_date, date.today() + timedelta(days=duration))
            membership.save()

        return Response({
            "message": f"{plan.capitalize()} Silver Membership Activated!",
            "start": membership.start_date,
            "end": membership.end_date,
            "tier": membership.tier
        })

class UserDashboardView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        today = date.today()

        # Bookings
        past = Booking.objects.filter(user=user, check_out__lt=today)
        current = Booking.objects.filter(user=user, check_in__lte=today, check_out__gte=today)
        upcoming = Booking.objects.filter(user=user, check_in__gt=today)

        # Favorites
        favorites = Favorite.objects.filter(user=user)

        # Gifts
        sent_gifts = Gift.objects.filter(sender=user)
        received_gifts = Gift.objects.filter(recipient_email=user.email)

        # Wallet
        wallet = getattr(user, 'wallet', None)

        # Membership
        membership = getattr(user, 'membership', None)

        # Investments
        investments = Investment.objects.filter(investor=user)

        total_invested = sum(inv.amount_invested for inv in investments)
        projected_roi = sum(
            inv.amount_invested * Decimal(str(inv.roi_percentage or 0)) / Decimal('100')
            for inv in investments
        )

        investment_tier = membership.tier if membership else None

        return Response({
            "user": {
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "primary_phone": user.primary_phone,
                "secondary_phone": user.secondary_phone,
                "account_number": user.account_number,
                "bank_name": user.bank_name,
                "role": user.role
            },
            "membership": {
                "tier": membership.tier if membership else None,
                "start": membership.start_date if membership else None,
                "end": membership.end_date if membership else None
            },
            "wallet_balance": wallet.balance if wallet else 0,
            "investment_summary": {
                "total_invested": total_invested,
                "projected_roi": projected_roi,
                "tier": investment_tier
            },
            "investments": InvestmentSerializer(investments, many=True).data,
            "bookings": {
                "past": BookingSerializer(past, many=True).data,
                "current": BookingSerializer(current, many=True).data,
                "upcoming": BookingSerializer(upcoming, many=True).data
            },
            "favorites": FavoriteSerializer(favorites, many=True).data,
            "gifts": {
                "sent": GiftSerializer(sent_gifts, many=True).data,
                "received": GiftSerializer(received_gifts, many=True).data
            }
        })

class UserProfileUpdateView(RetrieveUpdateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

class ChangePasswordView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user
        old_password = serializer.validated_data['old_password']
        new_password = serializer.validated_data['new_password']

        if not user.check_password(old_password):
            raise ValidationError("Old password is incorrect.")

        user.set_password(new_password)
        user.save()

        return Response({"message": "Password changed successfully."})

class MembershipPortalView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        try:
            membership = user.membership
        except PrivateMembership.DoesNotExist:
            return Response({
                "tier": None,
                "valid_until": None,
                "perks": []
            })

        perks = MEMBERSHIP_PERKS.get(membership.tier, [])
        return Response({
            "tier": membership.tier,
            "valid_until": membership.end_date,
            "perks": perks
        })

class AgentVerificationStatusView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        try:
            verification = AgentVerification.objects.get(user=user)
            return Response({
                "status": verification.status  # unverified, pending, or verified
            })
        except AgentVerification.DoesNotExist:
            return Response({
                "status": "unverified"
            })

class AgentMetricsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        if user.role != 'agent':
            return Response({"detail": "Only agents can access this."}, status=403)

        # Wallet
        wallet = getattr(user, 'wallet', None)
        wallet_balance = wallet.balance if wallet else 0

        # Listings
        properties = Property.objects.filter(agent=user)
        listings_count = properties.count()

        # Commission from bookings
        booking_commissions = Booking.objects.filter(property__agent=user)
        total_booking_commission = sum([
            b.total_price * Decimal((b.property.commission_percentage or 0)) / 100
            for b in booking_commissions
        ])

        # Commission from investments
        investment_commissions = Investment.objects.filter(property__agent=user)
        total_investment_commission = sum([
            inv.amount_invested * Decimal((inv.property.commission_percentage or 0)) / 100
            for inv in investment_commissions
        ])

        total_commission = total_booking_commission + total_investment_commission

        # Per-property summary
        property_stats = []
        for prop in properties:
            prop_bookings = Booking.objects.filter(property=prop).count()
            prop_commission = sum([
                b.total_price * Decimal((b.property.commission_percentage or 0)) / 100
                for b in Booking.objects.filter(property=prop)
            ]) + sum([
                i.amount_invested * Decimal((i.property.commission_percentage or 0)) / 100
                for i in Investment.objects.filter(property=prop)
            ])

            property_stats.append({
                "id": prop.id,
                "title": prop.title,
                "total_bookings": prop_bookings,
                "total_commission_earned": prop_commission
            })

        # Detailed history
        commission_history = []

        for b in booking_commissions:
            amount = b.total_price * Decimal((b.property.commission_percentage or 0)) / 100
            commission_history.append({
                "property": {"id": b.property.id, "title": b.property.title},
                "source": "booking",
                "amount": amount,
                "date": b.created_at.date() if hasattr(b, 'created_at') else None
            })

        for i in investment_commissions:
            amount = i.amount_invested * Decimal((i.property.commission_percentage or 0)) / 100
            commission_history.append({
                "property": {"id": i.property.id, "title": i.property.title},
                "source": "investment",
                "amount": amount,
                "date": i.created_at.date() if hasattr(i, 'created_at') else None
            })

        return Response({
            "wallet_balance": wallet_balance,
            "listings_count": listings_count,
            "total_commission_earned": total_commission,
            "properties": property_stats,
            "commission_history": sorted(commission_history, key=lambda x: x['date'], reverse=True)
        })

class AgentWithdrawalListView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'agent':
            return Response({'detail': 'Only agents can view withdrawals.'}, status=403)

        withdrawals = WithdrawalRequest.objects.filter(agent=user).order_by('-created_at')
        serializer = WithdrawalRequestSerializer(withdrawals, many=True)
        return Response(serializer.data)


class InitiateBookingPaymentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data

        try:
            property_id = data['property_id']
            check_in = data['check_in']
            check_out = data['check_out']
        except KeyError:
            raise ValidationError("Missing required fields.")

        try:
            prop = Property.objects.get(id=property_id, is_approved=True)
        except Property.DoesNotExist:
            raise ValidationError("Invalid or unapproved property.")

        if prop.property_type not in ['shortlet', 'hybrid']:
            raise ValidationError("Only shortlet or hybrid properties can be booked.")

        check_in_date = parse_date(check_in).date()
        check_out_date = parse_date(check_out).date()

        if (check_out_date - check_in_date).days < 1:
            raise ValidationError("Must book at least one night.")

        # Check for existing pending booking
        exists = PendingBooking.objects.filter(
            user=user,
            property=prop,
            check_in=check_in_date,
            check_out=check_out_date,
            is_paid=False
        ).exists()

        if exists:
            return Response({"error": "Booking payment already initiated for these dates."}, status=400)

        nights = (check_out_date - check_in_date).days
        total_price = prop.price_per_night * nights

        # Discount if user is a member
        if hasattr(user, 'membership'):
            total_price *= Decimal("0.95")

        tx_ref = f"booking-{uuid.uuid4()}"

        pending = PendingBooking.objects.create(
            user=user,
            property=prop,
            check_in=check_in_date,
            check_out=check_out_date,
            total_price=total_price,
            payment_method='flutterwave',
            payment_reference=tx_ref
        )

        # Generate Flutterwave link
        payload = {
            "tx_ref": tx_ref,
            "amount": str(total_price),
            "currency": "NGN",
            "redirect_url": settings.FLUTTERWAVE_REDIRECT_URL2,
            "customer": {
                "email": user.email,
                "name": f"{user.first_name} {user.last_name}",
                "phonenumber": getattr(user, 'primary_phone', 'N/A'),
            },
            "customizations": {
                "title": f"Booking: {prop.title}",
                "description": f"{nights} night(s) stay",
            }
        }

        headers = {
            "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        response = requests.post("https://api.flutterwave.com/v3/payments", json=payload, headers=headers)

        if response.status_code != 200:
            pending.delete()
            return Response({"error": "Payment gateway error. Try again."}, status=500)

        return Response({
            "payment_link": response.json()['data']['link'],
            "tx_ref": tx_ref
        })

class VerifyBookingPaymentView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        tx_ref = request.query_params.get("tx_ref")

        if not tx_ref:
            return Response({"error": "Missing transaction reference."}, status=400)

        try:
            pending = PendingBooking.objects.get(payment_reference=tx_ref, is_paid=False)
        except PendingBooking.DoesNotExist:
            return Response({"error": "Invalid or already processed transaction."}, status=404)

        # Verify with Flutterwave
        url = f"https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref={tx_ref}"
        headers = {
            "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}"
        }

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return Response({"error": "Payment verification failed."}, status=502)

        result = response.json()

        if result['status'] != 'success' or result['data']['status'] != 'successful':
            return Response({"error": "Transaction not successful."}, status=400)

        paid_amount = float(result['data']['amount'])
        if paid_amount < float(pending.total_price):
            return Response({"error": "Underpaid transaction."}, status=400)

        # Check property availability (again)
        overlaps = Booking.objects.filter(
            property=pending.property,
            check_in__lt=pending.check_out,
            check_out__gt=pending.check_in
        ).exists()

        if overlaps:
            return Response({"error": "This property has already been booked for these dates."}, status=409)

        # Create the actual booking
        booking = Booking.objects.create(
            user=pending.user,
            property=pending.property,
            check_in=pending.check_in,
            check_out=pending.check_out,
            total_price=pending.total_price,
            payment_method="flutterwave",
            status="confirmed"
        )

        '''
        # Optional: mark agent commission
        if pending.property.agent:
            commission_rate = pending.property.commission_percentage or 10  # in percent
            commission = (
                    pending.property.price_per_night
                    * (commission_rate / 100)
                    * (pending.check_out - pending.check_in).days
            )
        '''


        # Mark pending as paid
        pending.is_paid = True
        pending.save()

        notify(pending.user, f"Booking confirmed for {pending.property.title}")

        return Response({
            "message": "Booking confirmed",
            "booking_id": booking.id
        })

@api_view(['GET'])
@permission_classes([permissions.AllowAny])  # Public access
def public_user_profile(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        serializer = PublicUserSerializer(user)
        return Response(serializer.data)
    except User.DoesNotExist:
        return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

class InitiateInvestmentPaymentView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data

        try:
            property_id = data['property']
            amount_invested = float(data['amount_invested'])
            plan_years = int(data.get('plan_years', 2))
        except (KeyError, ValueError):
            raise ValidationError("Missing or invalid fields.")

        # Validate property
        try:
            prop = Property.objects.get(id=property_id, is_approved=True)
        except Property.DoesNotExist:
            raise ValidationError("Property not found or not approved.")

        if prop.property_type not in ['investment', 'hybrid']:
            raise ValidationError("Only investment or hybrid properties can be invested in.")

        total_cost = prop.investment_cost
        if not total_cost:
            raise ValidationError("Property has no investment cost.")

        amount_decimal = Decimal(str(amount_invested))

        if amount_decimal < Decimal('0.6') * total_cost:
            raise ValidationError("Minimum investment is 60% of property cost.")

        if amount_decimal > total_cost:
            raise ValidationError("You cannot invest more than the full cost.")

        # Generate payment reference

        tx_ref = f"invest-{uuid.uuid4()}"

        # Create PendingInvestment
        pending = PendingInvestment.objects.create(
            user=user,
            property=prop,
            amount_invested=amount_decimal,
            plan_years=plan_years,
            payment_reference=tx_ref,
        )

        # Prepare Flutterwave payment
        flutter_data = {
            "tx_ref": tx_ref,
            "amount": str(amount_decimal),
            "currency": "NGN",
            "redirect_url": settings.FLUTTERWAVE_REDIRECT_URL3,  # e.g. /invest/success
            "customer": {
                "email": user.email,
                "name": f"{user.first_name} {user.last_name}",
            },
            "customizations": {
                "title": "T.O.B.I Investment",
                "description": f"Investment in {prop.title}",
            }
        }

        flutter_url = "https://api.flutterwave.com/v3/payments"
        headers = {
            "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}",
            "Content-Type": "application/json"
        }

        response = requests.post(flutter_url, json=flutter_data, headers=headers)

        if response.status_code != 200:
            pending.delete()
            return Response({"error": "Failed to initiate payment."}, status=502)

        payment_link = response.json()['data']['link']

        return Response({
            "payment_link": payment_link,
            "tx_ref": tx_ref
        })

class VerifyInvestmentPaymentView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        tx_ref = request.query_params.get("tx_ref")
        if not tx_ref:
            return Response({"error": "Missing tx_ref"}, status=400)

        try:
            pending = PendingInvestment.objects.get(payment_reference=tx_ref, is_paid=False)
        except PendingInvestment.DoesNotExist:
            return Response({"error": "Invalid or already verified investment."}, status=404)

        # Verify payment with Flutterwave
        url = f"https://api.flutterwave.com/v3/transactions/verify_by_reference?tx_ref={tx_ref}"
        headers = {
            "Authorization": f"Bearer {settings.FLUTTERWAVE_SECRET_KEY}"
        }

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return Response({"error": "Flutterwave verification failed."}, status=502)

        result = response.json()
        if result['status'] != 'success' or result['data']['status'] != 'successful':
            return Response({"error": "Payment not successful."}, status=400)

        paid_amount = float(result['data']['amount'])
        if paid_amount < float(pending.amount_invested):
            return Response({"error": "Underpaid transaction."}, status=400)

        # Mark as paid
        pending.is_paid = True
        pending.save()

        # Begin actual investment logic
        user = pending.user
        prop = pending.property
        amount = float(pending.amount_invested)
        plan_years = pending.plan_years
        cost = float(prop.investment_cost)
        min_required = 0.6 * cost

        # Validate amount
        if amount < min_required:
            return Response({"error": f"Minimum investment is ₦{min_required:,.0f}"}, status=400)
        if amount > cost:
            return Response({"error": f"Cannot invest more than ₦{cost:,.0f}"}, status=400)

        # Determine membership tier
        tier = 'platinum' if amount == cost else 'gold'

        # ROI percentage
        roi_percentage = prop.roi_percentage or 5.0

        # Create investment
        investment = Investment.objects.create(
            investor=user,
            property=prop,
            amount_invested=amount,
            roi_percentage=roi_percentage,
            plan_years=plan_years
        )

        # Notify
        notify(user, f"You’ve successfully invested ₦{amount} in '{prop.title}'. ₦5M booking credit added.")

        # Wallet credit
        wallet, _ = Wallet.objects.get_or_create(user=user, defaults={'balance': 0, 'is_withdrawable': False})
        wallet.balance += 5000000
        wallet.save()

        # Membership logic
        membership, created = PrivateMembership.objects.get_or_create(
            user=user,
            defaults={
                "tier": tier,
                "start_date": date.today(),
                "end_date": date.today() + timedelta(days=365)
            }
        )

        if not created:
            if membership.tier != 'platinum':
                membership.tier = tier
            membership.end_date = max(membership.end_date, date.today() + timedelta(days=365))
            membership.save()

        # Installments
        remaining = cost - amount
        total_months = plan_years * 12
        monthly_payment = 0
        if tier == 'gold':
            monthly_payment = remaining / total_months
            for i in range(total_months):
                from dateutil.relativedelta import relativedelta
                due_date = date.today() + relativedelta(months=i + 1)
                InstallmentPayment.objects.create(
                    investment=investment,
                    due_date=due_date,
                    amount_due=round(monthly_payment, 2)
                )

        return Response({
            "message": f"Investment confirmed. ₦5M credit added. {tier.capitalize()} membership activated.",
            "investment_id": investment.id,
            "property_cost": cost,
            "amount_invested": amount,
            "remaining_balance": remaining,
            "plan_years": plan_years,
            "monthly_payment": round(monthly_payment, 2)
        })

