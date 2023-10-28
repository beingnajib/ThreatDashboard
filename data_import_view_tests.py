from django.test import TestCase
from .views import DataImportView
from .models import ImportedData
from django.core.files.uploadedfile import SimpleUploadedFile

class DataImportViewTest(TestCase):
    def setUp(self):
        self.view = DataImportView()

    def test_import_data(self):
        data_file = SimpleUploadedFile("test.csv", b"col1,col2\nval1,val2")
        response = self.client.post('/import/', {'data_file': data_file})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(ImportedData.objects.count(), 1)
