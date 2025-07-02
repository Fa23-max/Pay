import json
import requests # Make sure to install: pip install requests
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt # IMPORTANT: For webhook reception
from django.http import JsonResponse, HttpResponse
from django.contrib import messages # For displaying feedback messages

from .forms import CustomUserCreationForm, CustomAuthenticationForm, WebhookSubscriptionForm
from .models import WebhookSubscription, PaymentEvent

def register(request):
    """Handles user registration."""
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user) # Log the user in after registration
            messages.success(request, "Registration successful! Welcome.")
            return redirect('dashboard')
        else:
            messages.error(request, "Registration failed. Please correct the errors.")
    else:
        form = CustomUserCreationForm()
    return render(request, 'webhooks/register.html', {'form': form})

def user_login(request):
    """Handles user login."""
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if not user and '@' in username: # Try authenticating with email if username failed
                try:
                    user_by_email = User.objects.get(email=username)
                    user = authenticate(request, username=user_by_email.username, password=password)
                except User.DoesNotExist:
                    pass

            if user is not None:
                login(request, user)
                messages.success(request, f"Welcome back, {user.username}!")
                return redirect('dashboard')
            else:
                messages.error(request, "Invalid username/email or password.")
        else:
            messages.error(request, "Login failed. Please check your credentials.")
    else:
        form = CustomAuthenticationForm()
    return render(request, 'webhooks/login.html', {'form': form})

@login_required # Ensures only logged-in users can access this page
def user_logout(request):
    """Handles user logout."""
    logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('login') # Redirect to login page after logout

@login_required
def dashboard(request):
    """
    User dashboard to manage webhook subscription and view payment events.
    """
    # Get or create the webhook subscription for the current user
    user_webhook, created = WebhookSubscription.objects.get_or_create(user=request.user)

    if request.method == 'POST':
        form = WebhookSubscriptionForm(request.POST, instance=user_webhook)
        if form.is_valid():
            form.save()
            messages.success(request, "Webhook settings saved successfully!")
            return redirect('dashboard')
        else:
            messages.error(request, "Error saving webhook settings. Please check your URL.")
    else:
        form = WebhookSubscriptionForm(instance=user_webhook)

    # Display recent payment events for the logged-in user
    # IMPORTANT: In this simplified app, PaymentEvent is global.
    # In a real app, you'd filter these events to be relevant to the current user's payments
    # or subscriptions, potentially by adding a ForeignKey to PaymentEvent.
    recent_events = PaymentEvent.objects.all().order_by('-received_at')[:10]

    context = {
        'form': form,
        'user_webhook': user_webhook,
        'recent_events': recent_events
    }
    return render(request, 'webhooks/dashboard.html', context)

@csrf_exempt # IMPORTANT: Disable CSRF for webhook endpoint.
             # In production, implement signature verification instead!
def receive_payment_webhook(request):
    """
    Endpoint for receiving payment webhooks from a payment gateway.
    This simulates an external service sending payment notifications.
    """
    if request.method == 'POST':
        try:
            payload = json.loads(request.body.decode('utf-8'))
            event_id = payload.get('id') # Assuming gateway sends an 'id' for the event

            # --- SECURITY WARNING ---
            # In a real production application, you MUST verify the webhook's signature
            # sent by the payment gateway (e.g., Stripe-Signature header, PayPal-Signature).
            # This prevents malicious actors from sending fake payment events.
            # Example (conceptual):
            # expected_signature = request.headers.get('X-Signature')
            # if not verify_webhook_signature(request.body, expected_signature, YOUR_WEBHOOK_SECRET):
            #     return JsonResponse({'status': 'error', 'message': 'Invalid signature'}, status=403)
            # --- END SECURITY WARNING ---

            # Save the raw payload to our PaymentEvent log
            payment_event = PaymentEvent.objects.create(
                event_id=event_id,
                payload=payload,
                processed=False # Mark as unprocessed initially
            )

            print(f"[*] Received webhook event: {event_id}. Payload: {payload}")

            # --- SIMULATE FORWARDING TO USER'S SUBSCRIBED WEBHOOK ---
            # This part simulates your backend forwarding the event to the user's registered URL.
            # In a real system, you'd likely:
            # 1. Identify which user/subscription this payment event is for (e.g., from payload data).
            # 2. Retrieve that specific user's active webhook_url.
            # 3. Send the webhook.

            # For this demo, we'll just forward to ALL active webhook subscriptions.
            # This is NOT how you'd do it in production.
            subscribed_webhooks = WebhookSubscription.objects.filter(is_active=True)
            if subscribed_webhooks.exists():
                for sub in subscribed_webhooks:
                    try:
                        # Forward the exact payload received
                        # Set a short timeout for forwarding to avoid blocking
                        requests.post(sub.webhook_url, json=payload, timeout=5)
                        print(f"[+] Forwarded webhook to {sub.user.username}'s URL: {sub.webhook_url}")
                    except requests.exceptions.Timeout:
                        print(f"[-] Forwarding to {sub.webhook_url} timed out.")
                    except requests.exceptions.RequestException as e:
                        print(f"[-] Error forwarding webhook to {sub.webhook_url}: {e}")
            else:
                print("[-] No active webhook subscriptions to forward to.")
            # --- END SIMULATED FORWARDING ---

            # Return a 200 OK response to the sender (payment gateway)
            return JsonResponse({'status': 'success', 'message': 'Webhook received and logged.'})

        except json.JSONDecodeError:
            print("[!] Error: Invalid JSON payload received.")
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON payload'}, status=400)
        except Exception as e:
            print(f"[!] Error processing webhook: {e}")
            return JsonResponse({'status': 'error', 'message': f'Internal server error: {e}'}, status=500)
    else:
        # Only allow POST requests for the webhook endpoint
        return HttpResponse("Method Not Allowed", status=405)
