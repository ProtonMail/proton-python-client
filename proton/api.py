import base64
import json

import gnupg
import requests
import urllib3

"""
When using alternative routing, we want to verify as little data as possible. Thus we'll
end up relying mostly on tls key pinning. If we don't disable warnings, a warning will be
constantly popping on the terminal informing the user about it.
https://urllib3.readthedocs.io/en/latest/advanced-usage.html#ssl-warnings
"""
urllib3.disable_warnings()

from concurrent.futures import ThreadPoolExecutor

try:
    from dns import message
    from dns.rdatatype import TXT
except ModuleNotFoundError:
    from .dns import message
    from .dns.rdatatype import TXT

from .cert_pinning import TLSPinningAdapter
from .constants import (DEFAULT_TIMEOUT, SRP_MODULUS_KEY,
                        SRP_MODULUS_KEY_FINGERPRINT, DNS_HOSTS, ENCODED_URLS)
from .exceptions import (ConnectionTimeOutError,
                         EmptyAlternativeRoutesListError, NewConnectionError,
                         ProtonAPIError, TLSPinningError,
                         UnknownConnectionError, TLSPinningDisabledError)
from .srp import User as PmsrpUser


class Session:
    _base_headers = {
        "x-pm-apiversion": "3",
        "Accept": "application/vnd.protonmail.v1+json"
    }
    __tls_verification = True
    __tls_pinning_enabled = False

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

        self.s.proxies = proxies

        if TLSPinning:
            self.__tls_pinning_enabled = True
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
                timeout=self.__timeout,
                verify=self.__tls_verification
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
            raise ProtonAPIError(
                {
                    "Code": ret.status_code,
                    "Error": ret.reason,
                    "Headers": ret.headers
                }
            )

        if ret['Code'] not in [1000, 1001]:
            raise ProtonAPIError(ret)

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

    def get_alternative_routes(self, callback=None):
        """Get alternative routes to circumvent firewalls and api restrictions.

        Args:
            callback (func): a callback method to be called
            Might be usefull for multi-threading.

        This method leverages the power of ThreadPoolExecutor to async
        check if the provided dns hosts can be reached, and if so, collect the
        alternatives routes provided by them.
        The encoded url are done sync because most often one of the two should work,
        as it should provide the data as quick as possible.

        If callback is passed then the method does not return any value, otherwise it
        returns a set().
        """
        routes = None

        if not self.__tls_pinning_enabled:
            raise TLSPinningDisabledError(
                "TLS pinning should be enabled when using alternative routing"
            )

        for encoded_url in ENCODED_URLS:
            dns_query, dns_encoded_data = self.__generate_dns_message(encoded_url)
            dns_hosts_response = []

            host_and_dns = [(host, dns_encoded_data) for host in DNS_HOSTS]

            with ThreadPoolExecutor(max_workers=len(DNS_HOSTS)) as executor:
                dns_hosts_response = list(
                    executor.map(self.__query_for_dns_data, host_and_dns, timeout=20)
                )

            if len(dns_hosts_response) == 0:
                continue

            for response in dns_hosts_response:
                routes = self.__extract_dns_answer(response, dns_query)

            if routes:
                break

        if not routes:
            raise EmptyAlternativeRoutesListError("No alternative routes were found")

        if not callback:
            return routes

        callback(routes)

    def __generate_dns_message(self, encoded_url):
        """Generate DNS object.

        Args:
            encoded_url (string): encoded url as per documentation

        Returns:
            tuple():
                dns_query (dns.message.Message): output of dns.message.make_query
                base64_dns_message (base64): encode bytes
        """
        dns_query = message.make_query(encoded_url, TXT)
        dns_wire = dns_query.to_wire()
        base64_dns_message = base64.urlsafe_b64encode(dns_wire).rstrip(b"=")

        return dns_query, base64_dns_message

    def __query_for_dns_data(self, dns_settings):
        """Query for DNS host for data.

        Args:
            dns_settings (tuple):
                host_url (str): http/https url
                dns_encoded_data (str): base64 output
                generate by __generate_dns_message()

        This method uses requests.get to query the url
        for dns data.

        Returns:
            bytes: content of the response
        """
        dns_host, dns_encoded_data = dns_settings[0], dns_settings[1]
        response = requests.get(
            dns_host,
            headers={"accept": "application/dns-message"},
            timeout=(3.05, 16.95),
            params={"dns": dns_encoded_data}
        )

        return response.content

    def __extract_dns_answer(self, query_content, dns_query):
        """Extract alternative URL from dns message.

        Args:
            query_content (bytes): content of the response
            dns_query (dns.message.Message): output of dns.message.make_query

        Returns:
            set(): alternative url for API
        """
        r = message.from_wire(
            query_content,
            keyring=dns_query.keyring,
            request_mac=dns_query.request_mac,
            one_rr_per_rrset=False,
            ignore_trailing=False
        )
        routes = set()
        for route in r.answer:
            routes = set([str(url).strip("\"") for url in route])

        return routes

    @property
    def api_url(self):
        return self.__api_url

    @api_url.setter
    def api_url(self, newvalue):
        self.__api_url = newvalue

    @property
    def tls_verify(self):
        return self.__tls_verification

    @tls_verify.setter
    def tls_verify(self, newvalue):
        self.__tls_verification = newvalue

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
