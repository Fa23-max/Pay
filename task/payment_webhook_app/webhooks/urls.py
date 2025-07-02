from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    # This is the endpoint where your payment gateway would send webhooks
    path('receive-webhook/', views.receive_payment_webhook, name='receive_webhook'),
]