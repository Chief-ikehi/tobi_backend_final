from .models import Notification, WalletTransaction

def notify(user, message):
    Notification.objects.create(user=user, message=message)

def log_wallet_transaction(user, amount, txn_type, description):
    WalletTransaction.objects.create(
        user=user,
        amount=amount,
        transaction_type=txn_type,
        description=description
    )