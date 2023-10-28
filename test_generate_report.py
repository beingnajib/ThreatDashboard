from django.test import TestCase
from .views import generate_report

class GenerateReportTest(TestCase):
    def test_generate_report(self):
        request = self.factory.post('/generate_report', {'report_name': 'Threat Report', 'format': 'pdf'})
        response = generate_report(request)
        self.assertEqual(response.status_code, 200)
