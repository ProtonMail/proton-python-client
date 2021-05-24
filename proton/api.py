import base64
import json

import gnupg
import requests

from .cert_pinning import TLSPinningAdapter
from .constants import (DEFAULT_TIMEOUT, SRP_MODULUS_KEY,
                        SRP_MODULUS_KEY_FINGERPRINT)
from .exceptions import (ConnectionTimeOutError, NewConnectionError,
                         ProtonError, TLSPinningError, UnknownConnectionError)
from .srp import User as PmsrpUser


class Session:
    _base_headers = {
        "x-pm-apiversion": "3",
        "Accept": "application/vnd.protonmail.v1+json"
    }

    @staticmethod
    def load(dump, TLSPinning=True, timeout=DEFAULT_TIMEOUT, proxies=None):
        api_url = dump['api_url']
        appversion = dump['appversion']
        user_agent = dump['User-Agent']
        cookies = dump.get('cookies', {})
        s = Session(
            api_url=api_url,
            appversion=appversion,
            user_agent=user_agent,
            TLSPinning=TLSPinning,
            timeout=timeout,
            proxies=proxies
        )
        requests.utils.add_dict_to_cookiejar(s.s.cookies, cookies)
        s._session_data = dump['session_data']
        if s.UID is not None:
            s.s.headers['x-pm-uid'] = s.UID
            s.s.headers['Authorization'] = 'Bearer ' + s.AccessToken
        return s

    def dump(self):
        return {
            'api_url': self.__api_url,
            'appversion': self.__appversion,
            'User-Agent': self.__user_agent,
            'cookies': self.s.cookies.get_dict(),
            'session_data': self._session_data
        }

    def __init__(
        self, api_url, appversion="Other", user_agent="None",
        TLSPinning=True, ClientSecret=None, timeout=DEFAULT_TIMEOUT,
        proxies=None
    ):
        self.__api_url = api_url
        self.__appversion = appversion
        self.__user_agent = user_agent
        self.__clientsecret = ClientSecret
        self.__timeout = timeout

        # Verify modulus
        self.__gnupg = gnupg.GPG()
        self.__gnupg.import_keys(SRP_MODULUS_KEY)

        self._session_data = {}

        self.s = requests.Session()
        if proxies:
            self.s.proxies.update(proxies)

        if TLSPinning:
            self.s.mount(self.__api_url, TLSPinningAdapter())
        self.s.headers['x-pm-appversion'] = appversion
        self.s.headers['User-Agent'] = user_agent

    def api_request(
        self, endpoint, jsondata=None, additional_headers=None, method=None
    ):
        fct = self.s.post
        if method is None:
            if jsondata is None:
                fct = self.s.get
            else:
                fct = self.s.post
        else:
            fct = {
                'get': self.s.get,
                'post': self.s.post,
                'put': self.s.put,
                'delete': self.s.delete,
                'patch': self.s.patch
            }.get(method.lower())

        if fct is None:
            raise ValueError("Unknown method: {}".format(method))

        try:
            ret = fct(
                self.__api_url + endpoint,
                headers=additional_headers,
                json=jsondata,
                timeout=self.__timeout
            )
        except requests.exceptions.ConnectionError as e:
            raise NewConnectionError(e)
        except requests.exceptions.Timeout as e:
            raise ConnectionTimeOutError(e)
        except TLSPinningError as e:
            raise TLSPinningError(e)
        except (Exception, requests.exceptions.BaseHTTPError) as e:
            raise UnknownConnectionError(e)

        try:
            ret = ret.json()
        except json.decoder.JSONDecodeError:
            raise ProtonError(
                {
                    "Code": ret.status_code,
                    "Error": ret.reason,
                    "Headers": ret.headers
                }
            )

        if ret['Code'] != 1000:
            raise ProtonError(ret)

        return ret

    def verify_modulus(self, armored_modulus):
        # gpg.decrypt verifies the signature too, and returns the parsed data.
        # By using gpg.verify the data is not returned
        verified = self.__gnupg.decrypt(armored_modulus)

        if not (verified.valid and verified.fingerprint.lower() == SRP_MODULUS_KEY_FINGERPRINT):
            raise ValueError('Invalid modulus')

        return base64.b64decode(verified.data.strip())

    def authenticate(self, username, password):
        self.logout()

        payload = {"Username": username}
        if self.__clientsecret:
            payload['ClientSecret'] = self.__clientsecret
        info_response = self.api_request("/auth/info", payload)

        modulus = self.verify_modulus(info_response['Modulus'])
        server_challenge = base64.b64decode(info_response["ServerEphemeral"])
        salt = base64.b64decode(info_response["Salt"])
        version = info_response["Version"]

        usr = PmsrpUser(password, modulus)
        client_challenge = usr.get_challenge()
        client_proof = usr.process_challenge(salt, server_challenge, version)

        if client_proof is None:
            raise ValueError('Invalid challenge')

        # Send response
        payload = {
            "Username": username,
            "ClientEphemeral": base64.b64encode(client_challenge).decode(
                'utf8'
            ),
            "ClientProof": base64.b64encode(client_proof).decode('utf8'),
            "SRPSession": info_response["SRPSession"],
        }
        if self.__clientsecret:
            payload['ClientSecret'] = self.__clientsecret
        auth_response = self.api_request("/auth", payload)

        if "ServerProof" not in auth_response:
            raise ValueError("Invalid password")

        usr.verify_session(base64.b64decode(auth_response["ServerProof"]))
        if not usr.authenticated():
            raise ValueError('Invalid server proof')

        self._session_data = {
            'UID': auth_response["UID"],
            'AccessToken': auth_response["AccessToken"],
            'RefreshToken': auth_response["RefreshToken"],
            'Scope': auth_response["Scope"].split(),
        }

        if self.UID is not None:
            self.s.headers['x-pm-uid'] = self.UID
            self.s.headers['Authorization'] = 'Bearer ' + self.AccessToken

        return self.Scope

    def provide_2fa(self, code):
        ret = self.api_request('/auth/2fa', {
            "TwoFactorCode": code
        })
        self._session_data['Scope'] = ret['Scope']

        return self.Scope

    def logout(self):
        if self._session_data:
            self.api_request('/auth', method='DELETE')
            del self.s.headers['Authorization']
            del self.s.headers['x-pm-uid']
            self._session_data = {}

    def refresh(self):
        refresh_response = self.api_request('/auth/refresh', {
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RefreshToken": self.RefreshToken,
            "RedirectURI": "http://protonmail.ch"
        })
        self._session_data['AccessToken'] = refresh_response["AccessToken"]
        self._session_data['RefreshToken'] = refresh_response["RefreshToken"]
        self.s.headers['Authorization'] = 'Bearer ' + self.AccessToken

    @property
    def UID(self):
        return self._session_data.get('UID', None)

    @property
    def AccessToken(self):
        return self._session_data.get('AccessToken', None)

    @property
    def RefreshToken(self):
        return self._session_data.get('RefreshToken', None)

    @property
    def Scope(self):
        return self._session_data.get('Scope', [])
