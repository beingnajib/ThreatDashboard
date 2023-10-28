from django.urls import path
from .views import DataImportView, DataAnalysisView, ReportGenerationView

urlpatterns = [
    path('import/', DataImportView.as_view(), name='import'),
    path('analyze/', DataAnalysisView.as_view(), name='analyze'),
    path('report/', ReportGenerationView.as_view(), name='report'),
]
