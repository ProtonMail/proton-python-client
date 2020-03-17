from .srp import User as PmsrpUser

import requests, gnupg, base64

class Session:
    _base_headers = {
        "x-pm-apiversion": "3",
        "x-pm-appversion": "Web_3.99.99",
        "Accept": "application/vnd.protonmail.v1+json"
    }

    _srp_modulus_key = """-----BEGIN PGP PUBLIC KEY BLOCK-----
xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----"""


    def __init__(self, api_url):
        self.__api_url = api_url

        ## Verify modulus
        self.__gnupg = gnupg.GPG()
        self.__gnupg.import_keys(self._srp_modulus_key)

        self._session_data = {}

    def api_request(self, endpoint, jsondata=None, additional_headers=None, method=None):
        headers = self._base_headers.copy()

        if self.UID is not None:
            headers['x-pm-uid'] = self.UID
            headers['Authorization'] = 'Bearer ' + self.AccessToken

        if additional_headers is not None:
            headers.update(additional_headers)
        
        #Remove None values
        headers = dict([(k, v) for k, v in headers.items() if v is not None])

        fct = requests.post
        if method is None:
            if jsondata is None:
                fct = requests.get
            else:
                fct = requests.post
        else:
            fct = {
                'get': requests.get,
                'post': requests.post,
                'put': requests.put,
                'delete': requests.delete,
                'patch': requests.patch
            }.get(method.lower())

        if fct is None:
            raise ValueError("Unknown method: {}".format(method))

        ret = fct(
            self.__api_url + endpoint,
            headers = headers,
            json = jsondata
        ).json()

        if ret['Code'] != 1000:
            raise ValueError("[{0[Code]}] {0[Error]}".format(ret))

        return ret
        

    def authenticate(self, username, password):
        self._session_data = {}

        info_response = self.api_request("/auth/info", {"Username": username})
        d = self.__gnupg.decrypt(info_response['Modulus'])

        if not d.valid:
            raise ValueError('Invalid modulus')

        modulus   = base64.b64decode(d.data.strip())
        challenge = base64.b64decode(info_response["ServerEphemeral"])
        salt      = base64.b64decode(info_response["Salt"])
        session   = info_response["SRPSession"]
        version   = info_response["Version"]

        usr        = PmsrpUser(username, password, modulus)
        uname, A   = usr.start_authentication()
        M          = usr.process_challenge(salt, challenge, version)

        if M is None:
            raise ValueError('Invalid challenge')

        ## Send response
        auth_response = self.api_request("/auth",
            {
                "Username": username,
                "ClientEphemeral" : base64.b64encode(A),
                "ClientProof" : base64.b64encode(M),
                "SRPSession": session,
            }
        )

        if "ServerProof" not in auth_response:
            raise ValueError("Invalid password")

        usr.verify_session( base64.b64decode(auth_response["ServerProof"]))
        if not usr.authenticated():
            raise ValueError('Invalid server proof')
        
        self._session_data = {
            'UID': auth_response["UID"],
            'AccessToken': auth_response["AccessToken"],
            'RefreshToken': auth_response["RefreshToken"],
            'SessionSecret': usr.get_session_key()
        }

        return True

    def logout(self):
        self.api_request('/auth',method='DELETE')
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
    def SessionSecret(self):
        return self._session_data.get('SessionSecret', None)
