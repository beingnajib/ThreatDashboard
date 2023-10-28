from django.test import TestCase
from .views import analyze_data

class AnalyzeDataTest(TestCase):
    def test_analyze_data(self):
        request = self.factory.get('/analyze_data')
        response = analyze_data(request)
        self.assertEqual(response.status_code, 200)
