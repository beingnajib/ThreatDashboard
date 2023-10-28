from django.test import TestCase
from .views import DataAnalysisView
from .models import ImportedData, AnalyzedData

class DataAnalysisViewTest(TestCase):
    def setUp(self):
        self.view = DataAnalysisView()

    def test_analyze_data(self):
        ImportedData.objects.create(data="test data")
        response = self.client.get('/analyze/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AnalyzedData.objects.count(), 1)
