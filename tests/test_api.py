import pytest
import requests
from proton import cert_pinning

class TestCertificatePinning():
    
    s = requests.Session()
    
    def test_api_url(self):
        url = 'https://api.protonvpn.ch/tests/ping'
        self.s.mount(url, cert_pinning.TLSPinningAdapter())
        try:
            r = self.s.get(url)
        except cert_pinning.TLSPinningError as e:
            assert e.strerror == "Insecure connection"
        else:
            assert int(r.status_code) == 200


    def test_non_api_url(self):
        url = 'https://protonvpn.com'
        self.s.mount(url, cert_pinning.TLSPinningAdapter())
        try:
            r = self.s.get(url)
        except cert_pinning.TLSPinningError as e:
            assert e.strerror == "Insecure connection"
        else:
            assert int(r.status_code) == 200


    def test_random_page(self):
        url = 'https://randompage.com'
        self.s.mount(url, cert_pinning.TLSPinningAdapter())

        with pytest.raises(requests.exceptions.ConnectionError):
            self.s.get(url)
