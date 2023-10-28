from django.db import models

class ThreatData(models.Model):
    threat_type = models.CharField(max_length=100)
    threat_level = models.IntegerField()
    date_detected = models.DateTimeField()

class Report(models.Model):
    report_name = models.CharField(max_length=100)
    date_created = models.DateTimeField(auto_now_add=True)
    report_file = models.FileField(upload_to='reports/')
