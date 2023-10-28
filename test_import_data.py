from django.test import TestCase
from .views import import_data

class ImportDataTest(TestCase):
    def test_import_data(self):
        request = self.factory.post('/import_data', {'file': 'threats.csv'})
        response = import_data(request)
        self.assertEqual(response.status_code, 200)
