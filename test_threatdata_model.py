from django.test import TestCase
from .models import ThreatData

class ThreatDataModelTest(TestCase):
    def setUp(self):
        self.threat_data = ThreatData.objects.create(threat_type='Malware', threat_level='High', date_detected='2021-01-01')

    def test_threat_data_creation(self):
        self.assertEqual(self.threat_data.threat_type, 'Malware')
        self.assertEqual(self.threat_data.threat_level, 'High')
        self.assertEqual(self.threat_data.date_detected, '2021-01-01')
