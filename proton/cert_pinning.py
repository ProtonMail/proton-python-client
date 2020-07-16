import base64
import hashlib
import json
import os

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.connectionpool import HTTPSConnectionPool
from requests.packages.urllib3.poolmanager import PoolManager

from .constants import PUBKEY_HASH_DICT

crypto = requests.packages.urllib3.contrib.pyopenssl.OpenSSL.crypto

class TLSPinningError(requests.exceptions.SSLError):
    def __init__(self, strerror):
        self.strerror = strerror
        super(TLSPinningError, self).__init__(strerror)


class TLSPinningHTTPSConnectionPool(HTTPSConnectionPool):
    """Custom HTTPSConnectionPool that verifies the certificate for each connection"""
    
    def _validate_conn(self, conn):
        r = super(TLSPinningHTTPSConnectionPool, self)._validate_conn(conn)
 
        sock = conn.sock
        sock_connection = sock.connection

        try:
            certificate = sock_connection.get_peer_cert_chain()[0]
        except IndexError as e:
            raise TLSPinningError("X.509 was not found: {}".format(e))
        else:
            if self.is_session_secure(certificate, conn):
                return r


    def is_session_secure(self, cert, conn):
        """Checks if connection is secure"""
        
        cert_hash = self.extract_hash(cert)

        if not self.validate_hash(cert_hash):
            # Also generate a report
            conn.close()
            raise TLSPinningError("Insecure connection")
        
        return True


    def validate_hash(self, cert_hash):
        """Validates the hash agains a known list of hashes/pins"""
        try:
            PUBKEY_HASH_DICT[self.host].index(cert_hash)
        except (ValueError, KeyError):
            return False
        else:
            return True


    def extract_hash(self, cert):
        """Extracts the encrypted hash from the certificate"""
        cert_data = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        cert_obj = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)

        pubkey_obj = cert_obj.get_pubkey()

        pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubkey_obj)
        spki_hash = hashlib.sha256(pubkey).digest()
        cert_hash = base64.b64encode(spki_hash).decode('utf-8')
        
        return cert_hash


class TLSPinningPoolManager(PoolManager):
    """Custom PoolManager that attaches a custom HTTPSConnectionPool to a new connection pool"""
    def _new_pool(self, scheme, host, port, request_context):
        if scheme != 'https':
            return super(TLSPinningPoolManager, self)._new_pool(scheme, host, port, request_context)

        kwargs = self.connection_pool_kw

        pool = TLSPinningHTTPSConnectionPool(host, port, **kwargs)
        
        return pool


class TLSPinningAdapter(HTTPAdapter):
    """HTTPAdapter that attaches the custom PoolManager to a session"""
    def __init__(self):
        super(TLSPinningAdapter, self).__init__()

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = TLSPinningPoolManager(num_pools=connections, maxsize=maxsize, block=block, strict=True, **pool_kwargs)

