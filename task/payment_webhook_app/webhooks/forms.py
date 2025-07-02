from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import authenticate # Import authenticate for custom login form
from .models import WebhookSubscription

class CustomUserCreationForm(UserCreationForm):
    """
    Custom form for user registration.
    Extends Django's built-in UserCreationForm to include email.
    """
    email = forms.EmailField(required=True, help_text='Required. Enter a valid email address.')

    class Meta(UserCreationForm.Meta):
        model = User
        fields = UserCreationForm.Meta.fields + ('email',) # Add email field

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is already registered.")
        return email

class CustomAuthenticationForm(AuthenticationForm):
    """
    Custom form for user login.
    Extends Django's built-in AuthenticationForm to allow login with username or email.
    """
    username = forms.CharField(label="Username or Email")

    def clean(self):
        username = self.cleaned_data.get('username')
        password = self.cleaned_data.get('password')

        if username and password:
            # Try to authenticate with username first
            self.user_cache = authenticate(self.request, username=username, password=password)

            # If not authenticated, and username looks like an email, try with email
            if self.user_cache is None and '@' in username:
                try:
                    user_by_email = User.objects.get(email=username)
                    self.user_cache = authenticate(self.request, username=user_by_email.username, password=password)
                except User.DoesNotExist:
                    pass # User not found by email

            if self.user_cache is None:
                raise forms.ValidationError(
                    self.error_messages['invalid_login'],
                    code='invalid_login',
                    params={'username': self.username_field.verbose_name},
                )
        return self.cleaned_data

class WebhookSubscriptionForm(forms.ModelForm):
    """
    Form for users to subscribe or update their webhook URL.
    """
    class Meta:
        model = WebhookSubscription
        fields = ['webhook_url', 'is_active']
        widgets = {
            'webhook_url': forms.URLInput(attrs={'class': 'form-control', 'placeholder': 'https://your-webhook-endpoint.com/payments'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }
        labels = {
            'webhook_url': 'Your Webhook Endpoint URL',
            'is_active': 'Activate Webhook Subscription'
        }
