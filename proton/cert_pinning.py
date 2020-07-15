import base64
import hashlib
import json
import os

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.connectionpool import HTTPSConnectionPool
from requests.packages.urllib3.poolmanager import PoolManager

crypto = requests.packages.urllib3.contrib.pyopenssl.OpenSSL.crypto

class InspectedHTTPSConnectionPool(HTTPSConnectionPool):
    """Custom HTTPSConnectionPool that verifies the certificate for each connection"""
    
    def _validate_conn(self, conn):
        r = super(InspectedHTTPSConnectionPool, self)._validate_conn(conn)
 
        sock = conn.sock
        sock_connection = sock.connection

        if self.is_session_secure(sock_connection.get_peer_cert_chain()[0], conn):
            return r


    def is_session_secure(self, cert, conn):
        """Checks if connection is secure"""
        
        cert_hash = self.extract_hash(cert)

        if not self.validate_hash(cert_hash):
            # Also generate a report
            conn.close()
            raise Exception("Server hash does not match local hash")
        
        return True


    def validate_hash(self, cert_hash):
        """Validates the hash agains a known list of hashes/pins"""
        folder_path = os.path.dirname(os.path.abspath(__file__))

        with open(os.path.join(folder_path, "pins.json"), "r") as f:
            pin_list = json.load(f)

        for domain_info in pin_list["domain_list"]:
            try:
                if domain_info["url"] == self.host and cert_hash in domain_info["hashes"]:
                    return True
            except Exception as e:
                print(e)

        return False


    def extract_hash(self, cert):
        """Extracts the encrypted hash from the certificate"""
        # issuer = cert.get_issuer().get_components()
        cert_data = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)

        pubkey_obj = cert_obj.get_pubkey()

        pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubkey_obj)
        spki_hash = hashlib.sha256(pubkey).digest()
        cert_hash = base64.b64encode(spki_hash).decode('utf-8')
        
        # print(cert_hash)
        
        return cert_hash


class InspectedPoolManager(PoolManager):
    """Custom PoolManager that attaches a custom HTTPSConnectionPool to a new connection pool"""
    def _new_pool(self, scheme, host, port, request_context):
        if scheme != 'https':
            return super(InspectedPoolManager, self)._new_pool(scheme, host, port, request_context)

        kwargs = self.connection_pool_kw

        pool = InspectedHTTPSConnectionPool(host, port, **kwargs)
        
        return pool


class TLSPinning(HTTPAdapter):
    """HTTPAdapter that attaches the custom PoolManager to a session"""
    def __init__(self):
        super(TLSPinning, self).__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = InspectedPoolManager(num_pools=connections, maxsize=maxsize, block=block, strict=True, **pool_kwargs)

# # Code below is only for testing purposes
# url = 'https://protonvpn.com'
# s = requests.Session()
# s.mount(url, TLSPinning())
# r = s.get(url)
