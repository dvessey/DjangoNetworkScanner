from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("scan-input/", views.scan_input, name="scan_input"),
    path("scan/", views.scan, name="scan")
]