import django


from django.test import TestCase

from models import Server


class TestCreationOfServer(TestCase):
 def test_fields(self):
  server = Server()
  server.ip_address = '52.21.152.200	'
  server.country = 'testcountry'
  server.asn = 'testASN'
  server.org = 'testOrg'
  server.save()

  record = Server.objects.get(pk=1)
  self.assertEqual(record, server)