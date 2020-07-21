import pytest
import requests
from proton import cert_pinning

fake_hashes = {
    "api.protonvpn.ch": [
        "aIEwk65VSaxv3s1/88vF/rM8PauJoIun3rzVCX5mLS3M=",
        "adrtmcR2kFkM8qJClsuWgUzxgBkePfRCkRpqUesyDmeE=",
        "aYRGlaY0jyJ4Jw2/4M8FIftwbDIQfh8Sdro96CeEel54=",
        "aAfMENBVvOS8MnISprtvyPsjKlPooqh8nMB/pvCrpJpw="
    ],
    "protonvpn.com": [
        "a+0dMG0qG2Ga+dNE8uktwMm7dv6RFEXwBoBjQ43GqsQ0=",
        "a8joiNBdqaYiQpKskgtkJsqRxF7zN0C0aqfi8DacknnI=",
        "aJMI8yrbc6jB1FYGyyWRLFTmDNgIszrNEMGlgy972e7w=",
        "aIu44zU84EOCZ9vx/vz67/MRVrxF1IO4i4NIa8ETwiIY="
    ]
}


class TestCertificatePinning():

    s = requests.Session()

    def test_api_url_real_hash(self):
        url = 'https://api.protonvpn.ch/tests/ping'
        self.s.mount(url, cert_pinning.TLSPinningAdapter())
        r = self.s.get(url)
        assert int(r.status_code) == 200

    def test_non_api_url_real_hash(self):
        url = 'https://protonvpn.com'
        self.s.mount(url, cert_pinning.TLSPinningAdapter())
        r = self.s.get(url)
        assert int(r.status_code) == 200

    def test_api_url_fake_hash(self):
        url = 'https://api.protonvpn.ch/tests/ping'
        self.s.mount(url, cert_pinning.TLSPinningAdapter(fake_hashes))

        with pytest.raises(requests.exceptions.ConnectionError):
            self.s.get(url)

    def test_non_api_url_fake_hash(self):
        url = 'https://protonvpn.com'
        self.s.mount(url, cert_pinning.TLSPinningAdapter(fake_hashes))

        with pytest.raises(requests.exceptions.ConnectionError):
            self.s.get(url)
