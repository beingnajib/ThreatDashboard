from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from rest_framework.test import APITestCase

from threats.models import Indicator, Source


class APIBase(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user("analyst", password="Analyst-pass-123")
        self.staff = User.objects.create_user("boss", password="Staff-pass-12345", is_staff=True)
        self.responder = User.objects.create_user("ir", password="Responder-pass-1")
        group, _ = Group.objects.get_or_create(name="responders")
        forensics, _ = Group.objects.get_or_create(name="forensics")
        self.responder.groups.add(group, forensics)
        self.client.force_authenticate(self.analyst)

    def as_user(self, user):
        self.client.force_authenticate(user)


def make_indicator(value="203.0.113.10", ioc_type="ipv4", **kwargs):
    defaults = {"threat_type": "c2", "severity": 3, "confidence": 80}
    defaults.update(kwargs)
    return Indicator.objects.create(value=value, ioc_type=ioc_type, **defaults)


def make_source(name="Feed", reliability="B"):
    return Source.objects.create(name=name, reliability=reliability)
