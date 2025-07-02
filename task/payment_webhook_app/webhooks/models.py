from django.db import models
from django.contrib.auth.models import User
from django.db.models.fields.json import JSONField # For storing JSON payload

class WebhookSubscription(models.Model):
    """
    Stores the webhook URL provided by a user to receive payment notifications.
    Each user can have at most one active subscription.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True)
    webhook_url = models.URLField(max_length=500, verbose_name="Your Webhook URL for Payments")
    is_active = models.BooleanField(default=True, verbose_name="Receive Webhooks")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Webhook for {self.user.username}: {self.webhook_url}"

class PaymentEvent(models.Model):
    """
    Logs incoming payment webhook events received by the application.
    In a real app, you would likely associate this with a specific Booking/Transaction.
    """
    event_id = models.CharField(max_length=255, unique=True, null=True, blank=True,
                                help_text="Unique ID from the payment gateway (e.g., Stripe event ID)")
    payload = JSONField() # Stores the raw JSON data of the webhook
    received_at = models.DateTimeField(auto_now_add=True)
    processed = models.BooleanField(default=False, help_text="Indicates if the event has been processed by your logic")
    # In a real app, you might add 'user' or 'subscription' foreign keys here
    # to link it back to a specific user's subscription or a specific payment.

    def __str__(self):
        return f"Payment Event {self.event_id or self.pk} at {self.received_at.strftime('%Y-%m-%d %H:%M:%S')}"

    class Meta:
        ordering = ['-received_at'] # Order by most recently received