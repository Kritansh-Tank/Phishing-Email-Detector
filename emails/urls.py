from django.urls import path
from .views import home_view, check_new_alerts

urlpatterns = [
    path('', home_view, name='home'),
    path("check-new-alerts/", check_new_alerts, name="check_new_alerts"),
]
