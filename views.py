from django.http import JsonResponse
from .models import ThreatData, Report
import pandas as pd
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from docx import Document
from openpyxl import Workbook

def import_data(request):
    if request.method == 'POST':
        file = request.FILES['file']
        data = pd.read_csv(file)
        for index, row in data.iterrows():
            ThreatData.objects.create(
                threat_type=row['threat_type'],
                threat_level=row['threat_level'],
                date_detected=row['date_detected']
            )
        return JsonResponse({'message': 'Data imported successfully'}, status=200)

def analyze_data(request):
    data = pd.DataFrame(list(ThreatData.objects.values()))
    # Perform data analysis here
    return JsonResponse(data.to_dict(), safe=False)

def generate_report(request):
    data = pd.DataFrame(list(ThreatData.objects.values()))
    # Generate report here
    return JsonResponse({'message': 'Report generated successfully'}, status=200)
