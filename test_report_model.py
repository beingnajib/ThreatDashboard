from django.test import TestCase
from .models import Report

class ReportModelTest(TestCase):
    def setUp(self):
        self.report = Report.objects.create(report_name='Threat Report', date_created='2021-01-01', report_file='report.pdf')

    def test_report_creation(self):
        self.assertEqual(self.report.report_name, 'Threat Report')
        self.assertEqual(self.report.date_created, '2021-01-01')
        self.assertEqual(self.report.report_file, 'report.pdf')
