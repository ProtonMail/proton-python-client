# import requests
# from proton import cert_pinning
# import urllib3


failing_hash = {
    "api.protonvpn.ch": [""],
    "protonvpn.com": [""],
    "alt_routing": ["EU6TS9MO0L/GsDHvVc9D5fChYLNy5JdGYpJw0ccgetM="],
}
working_hash1 = {
    "api.protonvpn.ch": [""],
    "protonvpn.com": [""],
    "alt_routing": ["W8/42Z0ffufwnHIOSndT+eVzBJSC0E8uTIC8O6mEliQ="],
}
working_hash2 = {
    "api.protonvpn.ch": [""],
    "protonvpn.com": [""],
    "alt_routing": ["9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8="],
}


# class TestCertificatePinning:

#     def test_failling_hash(self):
#         from proton import exceptions
#         import pytest
#         s = requests.Session()
#         urllib3.disable_warnings()
#         url = 'https://rsa4096.badssl.com/'
#         s.mount(url, cert_pinning.TLSPinningAdapter(failing_hash))
#         with pytest.raises(exceptions.TLSPinningError):
#             s.get(url, verify=False)

#     def test_working_hash1(self):
#         s = requests.Session()
#         urllib3.disable_warnings()
#         url = 'https://rsa4096.badssl.com/'
#         s.mount(url, cert_pinning.TLSPinningAdapter(working_hash1))
#         s.get(url, verify=False)

#     def test_working_hash2(self):
#         s = requests.Session()
#         urllib3.disable_warnings()
#         url = 'https://self-signed.badssl.com/'
#         s.mount(url, cert_pinning.TLSPinningAdapter(working_hash2))
#         s.get(url, verify=False)
