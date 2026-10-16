from django.contrib import admin
from django.urls import include, path

admin.site.site_header = "ThreatDashboard administration"
admin.site.site_title = "ThreatDashboard"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("threats.urls")),
]
