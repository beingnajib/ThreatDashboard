from rest_framework import serializers
from .models import ImportedData, AnalyzedData, GeneratedReport

class ImportedDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = ImportedData
        fields = '__all__'

class AnalyzedDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = AnalyzedData
        fields = '__all__'

class GeneratedReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = GeneratedReport
        fields = '__all__'
