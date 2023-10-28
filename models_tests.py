from django.test import TestCase
from .models import ImportedData, AnalyzedData, GeneratedReport

class ModelsTest(TestCase):
    def test_imported_data_model(self):
        data = ImportedData.objects.create(data="test data")
        self.assertEqual(str(data), "test data")

    def test_analyzed_data_model(self):
        data = AnalyzedData.objects.create(data="test data")
        self.assertEqual(str(data), "test data")

    def test_generated_report_model(self):
        report = GeneratedReport.objects.create(report="test report")
        self.assertEqual(str(report), "test report")
