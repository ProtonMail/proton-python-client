import base64
import copy
import hashlib
from ssl import DER_cert_to_PEM_cert

import requests
from OpenSSL import crypto
from requests.adapters import HTTPAdapter
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.poolmanager import PoolManager
from urllib3.util.timeout import Timeout

from .constants import PUBKEY_HASH_DICT


class TLSPinningError(requests.exceptions.SSLError):
    def __init__(self, strerror):
        self.strerror = strerror
        super(TLSPinningError, self).__init__(strerror)


class TLSPinningHTTPSConnectionPool(HTTPSConnectionPool):
    """HTTPSConnectionPool that verifies the certificate for each connection"""
    def __init__(
        self,
        host,
        alt_hash_dict,
        port=None,
        strict=False,
        timeout=Timeout.DEFAULT_TIMEOUT,
        maxsize=1,
        block=False,
        headers=None,
        retries=None,
        _proxy=None,
        _proxy_headers=None,
        key_file=None,
        cert_file=None,
        cert_reqs=None,
        key_password=None,
        ca_certs=None,
        ssl_version=None,
        assert_hostname=None,
        assert_fingerprint=None,
        ca_cert_dir=None,
        **conn_kw
    ):
        self.alt_hash_dict = alt_hash_dict
        super(TLSPinningHTTPSConnectionPool, self).__init__(
            host,
            port,
            strict,
            timeout,
            maxsize,
            block,
            headers,
            retries,
            _proxy,
            _proxy_headers,
            key_file,
            cert_file,
            cert_reqs,
            key_password,
            ca_certs,
            ssl_version,
            assert_hostname,
            assert_fingerprint,
            ca_cert_dir,
            **conn_kw
        )

    def _validate_conn(self, conn):
        r = super(TLSPinningHTTPSConnectionPool, self)._validate_conn(conn)

        sock = conn.sock

        pem_certificate = self.get_certificate(sock)

        if self.is_session_secure(pem_certificate, conn, self.alt_hash_dict):
            return r

    def is_session_secure(self, cert, conn, alt_hash_dict):
        """Checks if connection is secure"""

        cert_hash = self.extract_hash(cert)

        if not self.validate_hash(cert_hash, alt_hash_dict):
            # Also generate a report
            conn.close()
            raise TLSPinningError("Insecure connection")

        return True

    def validate_hash(self, cert_hash, alt_hash_dict):
        """Validates the hash agains a known list of hashes/pins"""
        hash_dict = copy.deepcopy(PUBKEY_HASH_DICT)

        if alt_hash_dict:
            hash_dict = copy.deepcopy(alt_hash_dict)

        try:
            hash_dict[self.host].index(cert_hash)
        except (ValueError, KeyError):
            return False
        else:
            return True

    def get_certificate(self, sock):
        """Extracts and converts certificate to PEM"""
        certificate_binary_form = sock.getpeercert(True)
        pem_certificate = DER_cert_to_PEM_cert(certificate_binary_form)

        return pem_certificate

    def extract_hash(self, cert):
        """Extracts the encrypted hash from the certificate"""
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

        pubkey_obj = cert_obj.get_pubkey()

        pubkey = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubkey_obj)
        spki_hash = hashlib.sha256(pubkey).digest()
        cert_hash = base64.b64encode(spki_hash).decode('utf-8')

        return cert_hash


class TLSPinningPoolManager(PoolManager):
    """
    Custom PoolManager that attaches
    a custom HTTPSConnectionPool to a new connection pool
    """
    def __init__(
        self,
        alt_hash_dict,
        num_pools=10,
        headers=None,
        **connection_pool_kw
    ):
        self.alt_hash_dict = alt_hash_dict
        super(TLSPinningPoolManager, self).__init__(
            num_pools=10, headers=None, **connection_pool_kw
        )

    def _new_pool(self, scheme, host, port, request_context):
        if scheme != 'https':
            return super(TLSPinningPoolManager, self)._new_pool(
                scheme, host, port, request_context
                )

        kwargs = self.connection_pool_kw

        pool = TLSPinningHTTPSConnectionPool(
                    host=host, port=port,
                    alt_hash_dict=self.alt_hash_dict, **kwargs
                )

        return pool


class TLSPinningAdapter(HTTPAdapter):
    """HTTPAdapter that attaches the custom PoolManager to a session"""
    def __init__(self, alt_hash_dict=None):
        self.alt_hash_dict = alt_hash_dict
        super(TLSPinningAdapter, self).__init__()

    def init_poolmanager(
        self,
        connections,
        maxsize,
        block=False,
        **pool_kwargs
    ):
        self.poolmanager = TLSPinningPoolManager(
            num_pools=connections, maxsize=maxsize, block=block,
            strict=True, alt_hash_dict=self.alt_hash_dict, **pool_kwargs
        )
