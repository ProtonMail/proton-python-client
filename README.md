Proton API Python Client
=============

## Dependencies
| **Python** | **Debian** | **Fedora** | **Arch** |
|:-----------|:-----------|:-----------|:---------|
| [requests](https://github.com/psf/requests) >= 2.16.0 **\*** | python3-requests | python3-requests | python-requests |
| [bcrypt](https://github.com/pyca/bcrypt/) | python3-bcrypt | python3-bcrypt | python-bcrypt                   |
| [python-gnupg](https://docs.red-dove.com/python-gnupg/) | python3-gnupg | python3-gnupg | python-gnupg        |
| [pyopenssl](https://www.pyopenssl.org/en/stable/) | python3-openssl | python3-pyOpenSSL | python-pyopenssl    |


**\*** versions lower than 2.16 of the Python Requests library are not officially supported due to the missing support for TLS pinning, which is required in order to properly verify and trust the connection to the Proton API. It is possible disable TLS pinning (ie: to run with lower requests versions), but be aware of the risk.

## Table of Contents
- [Install](#install)
- [Usage](#usage)
    - [Import](#import)
    - [Setup](#setup)
    - [Authenticate](#authenticate)
    - [Store session](#store-session)
    - [Load session](#load-session)
    - [Refresh Session](#refresh-session)
    - [API calls](#api-calls)
    - [Error handling](#error-handling)

## Install
The recommended way to install the client is via OS-respective packages (.deb/.rpm/.zst), by either compiling it yourself or downloading the binaries from our repositories. If for some reason that is not possible, then a normal python installation can be accomplished.

# Usage

## Import
`from proton.api import Session, ProtonError`

## Setup
By default, TLS pinning is enabled. If you would like to disable it, you can additionally pass `TLSPinning=False`.
```
proton_session = Session(
    api_url="https://example.api.com",
    appversion="GithubExample_0.0.1",
    user_agent="Ubuntu_20.04",
)
```
`api_url`: The base API url

`appversion`: Usually this is the version of the application that is implementing the client. Leave it empty for non-official Proton clients.

`user_agent`: This helps us to understand on what type of platforms the client is being used. This usually can be fed with the output of a python package called [distro](https://github.com/nir0s/distro). Leave empty in case of doubt.

Now that we've setup our Proton session, we're ready for authentication.

## Authenticate
To authenticate against the Proton API, two types of information would need to be provided first, the Proton username and password.
```
proton_session.authenticate(username, password)
```
`username`: Proton username, ie: protonvpn@protonmail.ch

`password`: Proton password

After successfully authenticating against the API, we can now start using our `proton_session` object to make API calls. More on that in [API calls](#api-calls).

## Store session
To store the session locally on disk (for later re-use), we need to first extract its contents. To accomplish that we will need to use a method called `dump()`. This method returns a dict.

```
proton_session.dump()
```

The output of a dump will usually look something like this:
```
session_dump = proton_session.dump()
print(session_dump)
---
{"api_url": "https://example.api.com", "appversion": "GithubExample_0.0.1", "User-Agent": "Ubuntu_20.04", "cookies": {}, "session_data": {}}
```
If cookies and session_data contain no data, then it means that we've attempted to make an API call and it failed or we haven't made one yet.

If authenticated, `session_data` will contain some data that will be necessary for the [Refresh Session](#refresh-session) chapter, in particular the keys `AccessToken` and `RefreshToken`.

**Note:** It is recommended to store the contents as JSON.

## Load session
To re-use a session that we've previously stored we need to do as following:
1. Get session contents
2. Instantiate our session

If for example we've previously stored the session on a JSON file, then we would need to extract the session contents from file first (step 1):
```
with open(PATH_TO_JSON_SESSION_FILE, "r") as f:
    session_in_json_format = json.loads(f.read())
```

Now we can proceed with session instantiation (step 2):
```
proton_session = Session.load(
    dump=session_in_json_format
)
```

Now we're able to start using our `proton_session` object to make API calls. More on that in [API calls](#api-calls).

## Refresh Session
As previously introduced in the [Store session](#store-session) chapter, `AccessToken` and `RefreshToken` are two tokens that identify us against the API. As their names imply, `AccessToken` is used to give us access to the API while `RefreshToken` is used to refresh the `AccessToken` whenever this one is invalidated by the servers. An `AccessToken` can be invalidated for the following reasons:
- When the session is removed via the webclient
- When a `logout()` is executed
- When the session has expired

If for any reason the API responds with error 401, then it means that the `AccessToken` is invalid and it needs to be refreshed (assuming that the `RefreshToken` is valid). To refresh the tokens **\*** we can use the following method:

```
proton_session.refresh()
```

Our tokens **\*** have now been updated. To make sure that we can re-use this session with the refreshed tokens **\***, we can store them into file (or keyring). Consult the [Store session](#store-session) chapter on how to accomplish that.

**\*** when we use the `refresh()` method, both `AccessToken` and `RefreshToken` are refreshed.

## API calls
Once we're authenticated and our tokens are valid, we can make api calls to various endpoints. By default a `post` request is made, unless another type of request is passed: `method=get|post|put|delete|patch|None`. Also additional custom headers can be sent with `additional_headers="{'header': 'custom_header'}"`. Then to make the request we can use the following:
```
proton_session.api_request(endpoint="custom_api_endpoint")
```

## Error handling
For all of commands presented in the previous chapters, it is recommended to use them within try/except blocks. Some common errors that might come up:
- `401`: Invalid `AccessToken`, client should refresh tokens ([Refresh Session](#refresh-session))
- `403`: Missing scopes, client should re-authenticate (logout and login)
- `429`: Too many requests. Retry after time provided by `ProtonError.headers["Retry-After"]`
- `503`: Unable to reach API (most probably API is down)
- `8002`: Provided password is wrong
- `10002`:  Account is deleted
- `10003`:  Account is disabled
- `10013`:  `RefreshToken` is invalid. Client should re-authenticate (logout and login)

Below are some use cases:

- Authentication
```
error_message = {
    8002: "Provided password is incorrect",
    10002: "Account is deleted",
    10003: "Account is disabled",
}
try:
    proton_session.authenticate("proton_user@protonmail.ch", "Su!erS€cretPa§§word")
except ProtonError as e:
    print(error_message.get(e.code, "Unknown error")
```

- API requests
```
error_message = {
    401: "Invalid access token, client should refresh tokens",
    403: "Missing scopes, client should re-authenticate",
    429: "Too many requests, client needs to retry after specified in headers",
    503: "API is unreacheable",
    10013: "Refresh token is invalid. Client should re-authenticate (logout and login)",
}

try:
    proton_session.api_request(endpoint="custom_api_endpoint")
except ProtonError as e:
    print(error_message.get(e.code, "Unknown error")
```
- Refresh token

```
try:
    proton_session.api_request(endpoint="custom_api_endpoint")
except ProtonError as e:
    e.code == 401:
        proton_session.refresh()
        print("Now we can retry making another API call since tokens have been refreshed")
```