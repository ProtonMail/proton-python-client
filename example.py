import hashlib
import gnupg
import requests
import base64
import binascii
import pmsrp

## Constants
username = b"bart"
password = b"bart"
api = "https://protonmail.blue/api"

srp_modulus_key = """-----BEGIN PGP PUBLIC KEY BLOCK-----
xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----""";


## Get modulus & challenge
info_response = requests.post(
    api + "/auth/info",
    headers = {
        "x-pm-apiversion": "3",
        "x-pm-appversion": "Web_3.99.99",
        "Accept": "application/vnd.protonmail.v1+json"
    },
    json = {"Username": username})


res = info_response.json()

## Verify modulus
g = gnupg.GPG()
g.import_keys(srp_modulus_key)
d = g.decrypt(res['Modulus'])

if not d.valid:
    raise ValueError('Invalid modulus')

modulus = base64.b64decode(d.data.strip())
challenge = base64.b64decode(res["ServerEphemeral"])
salt = base64.b64decode(res["Salt"])
session = res["SRPSession"]
version = res["Version"]

## Compute SRP response

usr      = pmsrp.User(username, password, modulus)
uname, A = usr.start_authentication()
M        = usr.process_challenge(salt, challenge, version)

if M is None:
    raise ValueError('Invalid challenge')

## Send response
auth_response = requests.post(
    api + "/auth",
    headers = {
        "x-pm-apiversion": "3",
        "x-pm-appversion": "Web_3.99.99",
        "Accept": "application/vnd.protonmail.v1+json"
    },
    json = {
        "Username": username,
        "ClientEphemeral" : base64.b64encode(A),
        "ClientProof" : base64.b64encode(M),
        "SRPSession": session,
    })

result = auth_response.json()
try:
    usr.verify_session( base64.b64decode(result["ServerProof"]) )
    assert usr.authenticated()

    print("Successfully authenticated:")
    print("UID: " + result["UID"])
    print("AccessToken: " + result["AccessToken"])
    print("RefreshToken: " + result["RefreshToken"])
    print("Session secret: " + base64.b64encode(usr.get_session_key()).decode("utf-8"))
except KeyError:
    raise ValueError('Invalid password')
