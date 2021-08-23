from proton.srp.pmhash import pmhash
from proton.srp.util import (bytes_to_long, custom_hash, get_random_of_length,
                             SRP_LEN_BYTES, long_to_bytes)


class TestServer:
    def setup(self, username, modulus, verifier):
        self.hash_class = pmhash
        self.generator = 2
        self._authenticated = False

        self.user = username.encode()
        self.modulus = bytes_to_long(modulus)
        self.verifier = bytes_to_long(verifier)

        self.b = get_random_of_length(32)
        self.B = (
            self.calculate_k() * self.verifier + pow(
                self.generator, self.b, self.modulus
            )
        ) % self.modulus

        self.secret = None
        self.A = None
        self.u = None
        self.key = None

    def calculate_server_proof(self, client_proof):
        h = self.hash_class()
        h.update(long_to_bytes(self.A, SRP_LEN_BYTES))
        h.update(client_proof)
        h.update(long_to_bytes(self.secret, SRP_LEN_BYTES))
        return h.digest()

    def calculate_client_proof(self):
        h = self.hash_class()
        h.update(long_to_bytes(self.A, SRP_LEN_BYTES))
        h.update(long_to_bytes(self.B, SRP_LEN_BYTES))
        h.update(long_to_bytes(self.secret, SRP_LEN_BYTES))
        return h.digest()

    def calculate_k(self):
        h = self.hash_class()
        h.update(self.generator.to_bytes(SRP_LEN_BYTES, 'little'))
        h.update(long_to_bytes(self.modulus, SRP_LEN_BYTES))
        return bytes_to_long(h.digest())

    def get_challenge(self):
        return long_to_bytes(self.B, SRP_LEN_BYTES)

    def get_session_key(self):
        return long_to_bytes(self.secret, SRP_LEN_BYTES)  # if self._authenticated else None

    def get_authenticated(self):
        return self._authenticated

    def process_challenge(self, client_challenge, client_proof):
        self.A = bytes_to_long(client_challenge)
        self.u = custom_hash(self.hash_class, self.A, self.B)
        self.secret = pow(
            (
                self.A * pow(self.verifier, self.u, self.modulus)
            ),
            self.b, self.modulus
        )

        if client_proof != self.calculate_client_proof():
            return False

        self._authenticated = True
        return self.calculate_server_proof(client_proof)
