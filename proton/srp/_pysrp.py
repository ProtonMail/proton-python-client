# N    A large safe prime (N = 2q+1, where q is prime)
#      All arithmetic is done modulo N.
# g    A generator modulo N
# k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
# s    User's salt
# I    Username
# p    Cleartext Password
# H()  One-way hash function
# ^    (Modular) Exponentiation
# u    Random scrambling parameter
# a,b  Secret ephemeral values
# A,B  Public ephemeral values
# x    Private key (derived from p and s)
# v    Password verifier
from .pmhash import pmhash
from .util import *


def get_ng(n_bin, g_hex):
    return bytes_to_long(n_bin), int(g_hex, 16)


def hash_k(hash_class, g, N, width):
    h = hash_class()
    h.update(g.to_bytes(width, 'little'))
    h.update(N.to_bytes(width, 'little'))
    return bytes_to_long(h.digest())


def calculate_x(hash_class, salt, password, modulus, version):
    password = password.encode() if hasattr(password, 'encode') else password
    exp = hash_password(hash_class, password, long_to_bytes(salt), long_to_bytes(modulus), version)
    return bytes_to_long(exp)


def create_salted_verification_key(username, password, n_bin, g_hex=b"2", salt_len=4):
    hash_class = pmhash
    N, g = get_ng(n_bin, g_hex)
    _s = long_to_bytes(get_random(salt_len))
    _v = long_to_bytes(pow(g, calculate_x(hash_class, _s, username, password), N))

    return _s, _v


def calculate_M(hash_class, A, B, K):
    h = hash_class()
    h.update(long_to_bytes(A))
    h.update(long_to_bytes(B))
    h.update(K)
    return h.digest()


def calculate_H_AMK(hash_class, A, M, K):
    h = hash_class()
    h.update(long_to_bytes(A))
    h.update(M)
    h.update(K)
    return h.digest()


class User(object):
    def __init__(self, username, password, n_bin, g_hex=b"2", bytes_a=None, bytes_A=None):
        if bytes_a and len(bytes_a) != 32:
            raise ValueError("32 bytes required for bytes_a")

        if not isinstance(username, str) or len(username) == 0:
            raise ValueError("Invalid username")

        if not isinstance(password, str) or len(password) == 0:
            raise ValueError("Invalid password")

        self.N, self.g = get_ng(n_bin, g_hex)
        self.hash_class = pmhash
        self.k = hash_k(self.hash_class, self.g, self.N, width=long_length(self.N))

        self.I = username
        self.p = password
        if bytes_a:
            self.a = bytes_to_long(bytes_a)
        else:
            self.a = get_random_of_length(32)
        if bytes_A:
            self.A = bytes_to_long(bytes_A)
        else:
            self.A = pow(self.g, self.a, self.N)
        self.v = None
        self.M = None
        self.K = None
        self.H_AMK = None
        self._authenticated = False

    def authenticated(self):
        return self._authenticated

    def get_username(self):
        return self.I

    def get_ephemeral_secret(self):
        return long_to_bytes(self.a)

    def get_session_key(self):
        return self.K #if self._authenticated else None

    def start_authentication(self):
        return (self.I, long_to_bytes(self.A))

    # Returns M or None if SRP-6a safety check is violated
    def process_challenge(self, bytes_s, bytes_B, version=PM_VERSION):

        self.s = bytes_to_long(bytes_s)
        self.B = bytes_to_long(bytes_B)

        N = self.N
        g = self.g
        k = self.k

        hash_class = self.hash_class

        # SRP-6a safety check
        if (self.B % N) == 0:
            return None

        self.u = custom_hash(hash_class, self.A, self.B, width=len(long_to_bytes(N)))

        # SRP-6a safety check
        if self.u == 0:
            return None

        self.x = calculate_x(hash_class, self.s, self.p, N, version)

        self.v = pow(g, self.x, N)

        self.S = pow((self.B - k * self.v), (self.a + self.u * self.x), N)

        self.K = long_to_bytes(self.S)
        self.M = calculate_M(hash_class, self.A, self.B, self.K)
        self.H_AMK = calculate_H_AMK(hash_class, self.A, self.M, self.K)

        return self.M

    def verify_session(self, host_HAMK):
        if self.H_AMK == host_HAMK:
            self._authenticated = True

    def compute_v(self, bytes_s, version):
        self.s = bytes_to_long(bytes_s)
        self.x = calculate_x(self.hash_class, self.s, self.p, self.N, version)

        return long_to_bytes(pow(self.g, self.x, self.N))