class ProtonError(Exception):
    def __init__(self, ret):
        self.code = ret['Code']
        self.error = ret['Error']
        try:
            self.headers = ret["Headers"]
        except KeyError:
            self.headers = ""

        super().__init__("{}".format(self.error))


class ProtonNetworkError(Exception):
    def __init__(self, message, additional_context=None):
        self.message = message
        self.additional_context = additional_context
        super().__init__(self.message)


class TLSPinningError(ProtonNetworkError):
    """TLS Pinning exception"""


class NewConnectionError(ProtonNetworkError):
    """Network Error"""


class ConnectionTimeOutError(ProtonNetworkError):
    """Connection Time Out Error"""


class UnknownConnectionError(ProtonNetworkError):
    """UnknownConnectionError"""
