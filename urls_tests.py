from django.test import TestCase
from django.urls import reverse, resolve
from .views import DataImportView, DataAnalysisView, ReportGenerationView

class UrlsTest(TestCase):
    def test_import_url_resolves(self):
        url = reverse('import')
        self.assertEqual(resolve(url).func.view_class, DataImportView)

    def test_analyze_url_resolves(self):
        url = reverse('analyze')
        self.assertEqual(resolve(url).func.view_class, DataAnalysisView)

    def test_generate_url_resolves(self):
        url = reverse('generate')
        self.assertEqual(resolve(url).func.view_class, ReportGenerationView)
