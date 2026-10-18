import unittest
from urllib.error import HTTPError, URLError
from odmm_connection_diagnostics_v22851 import explain_connection_failure
class TestDiagnostics(unittest.TestCase):
    def test_auth(self):
        self.assertIn('jeton', explain_connection_failure(HTTPError('https://secret',401,'bad',{},None)).lower())
    def test_server(self):
        self.assertIn('Serveur', explain_connection_failure(HTTPError('https://secret',503,'bad',{},None)))
    def test_network_no_leak(self):
        self.assertNotIn('secret.internal', explain_connection_failure(URLError('secret.internal')))
    def test_validation_no_leak(self):
        self.assertNotIn('my-token', explain_connection_failure(ValueError('my-token')))
    def test_invalid_token(self):
        self.assertIn('Jeton invalide', explain_connection_failure(ValueError('INVALID_TOKEN')))
    def test_timeout(self):
        self.assertIn('Délai', explain_connection_failure(TimeoutError('secret')))
if __name__ == '__main__':unittest.main()
