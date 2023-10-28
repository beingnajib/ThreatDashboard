from django.test import TestCase
from .views import ReportGenerationView
from .models import AnalyzedData, GeneratedReport

class ReportGenerationViewTest(TestCase):
    def setUp(self):
        self.view = ReportGenerationView()

    def test_generate_report(self):
        AnalyzedData.objects.create(data="test data")
        response = self.client.get('/generate/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(GeneratedReport.objects.count(), 1)
