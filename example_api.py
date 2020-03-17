import pmsrp
import base64
from pprint import pprint

## Constants
username = b"bart"
password = b"bart"
api = "https://protonmail.blue/api"

sess = pmsrp.Session(api)
sess.authenticate(username, password)

print("UID: " + sess.UID)
print("AccessToken: " + sess.AccessToken)
print("RefreshToken: " + sess.RefreshToken)
print("SessionSecret: " + base64.b64encode(sess.SessionSecret).decode('utf8'))

sess.refresh()

print("UID: " + sess.UID)
print("AccessToken: " + sess.AccessToken)
print("RefreshToken: " + sess.RefreshToken)
print("SessionSecret: " + base64.b64encode(sess.SessionSecret).decode('utf8'))

pprint(sess.api_request('/vpn'))
sess.logout()
