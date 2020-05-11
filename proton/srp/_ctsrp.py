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

from __future__ import division
import sys
import ctypes

from .pmhash import pmhash
from .util import *

dlls = list()

platform = sys.platform
if platform == 'darwin':
    dlls.append(ctypes.cdll.LoadLibrary('libssl.dylib'))
elif 'win' in platform:
    for d in ('libeay32.dll', 'libssl32.dll', 'ssleay32.dll'):
        try:
            dlls.append(ctypes.cdll.LoadLibrary(d))
        except:
            pass
else:
    try:
        dlls.append(ctypes.cdll.LoadLibrary('libssl.so.10'))
    except OSError:
        try:
            dlls.append(ctypes.cdll.LoadLibrary('libssl.so.1.0.0'))
        except OSError:
            dlls.append(ctypes.cdll.LoadLibrary('libssl.so'))


class BIGNUM_Struct(ctypes.Structure):
    _fields_ = [("d", ctypes.c_void_p),
                ("top", ctypes.c_int),
                ("dmax", ctypes.c_int),
                ("neg", ctypes.c_int),
                ("flags", ctypes.c_int)]


class BN_CTX_Struct(ctypes.Structure):
    _fields_ = [("_", ctypes.c_byte)]


BIGNUM = ctypes.POINTER(BIGNUM_Struct)
BN_CTX = ctypes.POINTER(BN_CTX_Struct)


def load_func(name, args, returns=ctypes.c_int):
    d = sys.modules[__name__].__dict__
    f = None

    for dll in dlls:
        try:
            f = getattr(dll, name)
            f.argtypes = args
            f.restype = returns
            d[name] = f
            return
        except:
            pass
    raise ImportError('Unable to load required functions from SSL dlls')


load_func('BN_new', [], BIGNUM)
load_func('BN_free', [BIGNUM], None)
load_func('BN_clear', [BIGNUM], None)

load_func('BN_CTX_new', [], BN_CTX)
load_func('BN_CTX_free', [BN_CTX], None)

load_func('BN_cmp', [BIGNUM, BIGNUM], ctypes.c_int)

load_func('BN_num_bits', [BIGNUM], ctypes.c_int)

load_func('BN_add', [BIGNUM, BIGNUM, BIGNUM])
load_func('BN_sub', [BIGNUM, BIGNUM, BIGNUM])
load_func('BN_mul', [BIGNUM, BIGNUM, BIGNUM, BN_CTX])
load_func('BN_div', [BIGNUM, BIGNUM, BIGNUM, BIGNUM, BN_CTX])
load_func('BN_mod_exp', [BIGNUM, BIGNUM, BIGNUM, BIGNUM, BN_CTX])

load_func('BN_rand', [BIGNUM, ctypes.c_int, ctypes.c_int, ctypes.c_int])

load_func('BN_bn2bin', [BIGNUM, ctypes.c_char_p])
load_func('BN_bin2bn', [ctypes.c_char_p, ctypes.c_int, BIGNUM], BIGNUM)

load_func('BN_hex2bn', [ctypes.POINTER(BIGNUM), ctypes.c_char_p])
load_func('BN_bn2hex', [BIGNUM], ctypes.c_char_p)

load_func('CRYPTO_free', [ctypes.c_char_p])

load_func('RAND_seed', [ctypes.c_char_p, ctypes.c_int])


def bn_num_bytes(a):
    return ((BN_num_bits(a) + 7) // 8)


def bn_mod(rem, m, d, ctx):
    return BN_div(None, rem, m, d, ctx)


def bn_is_zero(n):
    return n[0].top == 0


def bn_to_bytes(n):
    b = ctypes.create_string_buffer(bn_num_bytes(n))
    BN_bn2bin(n, b)
    return b.raw[::-1]


def bytes_to_bn(dest_bn, bytes):
    BN_bin2bn(bytes[::-1], len(bytes), dest_bn)


def bn_hash(hash_class, dest, n1, n2):
    h = hash_class()
    h.update(bn_to_bytes(n1))
    h.update(bn_to_bytes(n2))
    d = h.digest()
    bytes_to_bn(dest, d)


def bn_hash_k(hash_class, dest, g, N, width):
    h = hash_class()
    bin1 = ctypes.create_string_buffer(width)
    bin2 = ctypes.create_string_buffer(width)
    BN_bn2bin(g, bin1)
    BN_bn2bin(N, bin2)
    h.update(bin1)
    h.update(bin2[::-1])
    bytes_to_bn(dest, h.digest())


def calculate_x(hash_class, dest, salt, password, modulus, version):
    exp = hash_password(hash_class, password, bn_to_bytes(salt), bn_to_bytes(modulus), version)
    bytes_to_bn(dest, exp)


def update_hash(h, n):
    h.update(bn_to_bytes(n))


def calculate_client_challenge(hash_class, A, B, K):
    h = hash_class()
    update_hash(h, A)
    update_hash(h, B)
    h.update(K)
    return h.digest()


def calculate_server_challenge(hash_class, A, M, K):
    h = hash_class()
    update_hash(h, A)
    h.update(M)
    h.update(K)
    return h.digest()


def get_ngk(hash_class, n_bin, g_hex, ctx):
    N = BN_new()
    g = BN_new()
    k = BN_new()

    bytes_to_bn(N, n_bin)
    BN_hex2bn(g, g_hex)
    bn_hash_k(hash_class, k, g, N, width=bn_num_bytes(N))

    return N, g, k


class User(object):
    def __init__(self, password, n_bin, g_hex=b"2", bytes_a=None, bytes_A=None):
        if bytes_a and len(bytes_a) != 32:
            raise ValueError("32 bytes required for bytes_a")

        if not isinstance(password, str) or len(password) == 0:
            raise ValueError("Invalid password")

        self.password = password.encode()
        self.a = BN_new()
        self.A = BN_new()
        self.B = BN_new()
        self.s = BN_new()
        self.S = BN_new()
        self.u = BN_new()
        self.x = BN_new()
        self.v = BN_new()
        self.tmp1 = BN_new()
        self.tmp2 = BN_new()
        self.tmp3 = BN_new()
        self.ctx = BN_CTX_new()
        self.M = None
        self.K = None
        self.expected_server_proof = None
        self._authenticated = False

        self.hash_class = pmhash
        self.N, self.g, self.k = get_ngk(self.hash_class, n_bin, g_hex, self.ctx)

        if bytes_a:
            bytes_to_bn(self.a, bytes_a)
        else:
            BN_rand(self.a, 256, 0, 0)

        if bytes_A:
            bytes_to_bn(self.A, bytes_A)
        else:
            BN_mod_exp(self.A, self.g, self.a, self.N, self.ctx)

    def __del__(self):
        if not hasattr(self, 'a'):
            return  # __init__ threw exception. no clean up required
        BN_free(self.a)
        BN_free(self.A)
        BN_free(self.B)
        BN_free(self.s)
        BN_free(self.S)
        BN_free(self.u)
        BN_free(self.x)
        BN_free(self.v)
        BN_free(self.N)
        BN_free(self.g)
        BN_free(self.k)
        BN_free(self.tmp1)
        BN_free(self.tmp2)
        BN_free(self.tmp3)
        BN_CTX_free(self.ctx)

    def authenticated(self):
        return self._authenticated

    def get_ephemeral_secret(self):
        return bn_to_bytes(self.a)

    def get_session_key(self):
        return self.K if self._authenticated else None

    def get_challenge(self):
        return bn_to_bytes(self.A)

    # Returns M or None if SRP-6a safety check is violated
    def process_challenge(self, bytes_s, bytes_server_challenge, version=PM_VERSION):
        bytes_to_bn(self.s, bytes_s)
        bytes_to_bn(self.B, bytes_server_challenge)

        # SRP-6a safety check
        if bn_is_zero(self.B):
            return None

        bn_hash(self.hash_class, self.u, self.A, self.B)

        # SRP-6a safety check
        if bn_is_zero(self.u):
            return None

        calculate_x(self.hash_class, self.x, self.s, self.password, self.N, version)

        BN_mod_exp(self.v, self.g, self.x, self.N, self.ctx)

        # S = (B - k*(g^x)) ^ (a + ux)
        BN_mul(self.tmp1, self.u, self.x, self.ctx)
        BN_add(self.tmp2, self.a, self.tmp1)  # tmp2 = (a + ux)
        BN_mod_exp(self.tmp1, self.g, self.x, self.N, self.ctx)
        BN_mul(self.tmp3, self.k, self.tmp1, self.ctx)  # tmp3 = k*(g^x)
        BN_sub(self.tmp1, self.B, self.tmp3)  # tmp1 = (B - K*(g^x))
        BN_mod_exp(self.S, self.tmp1, self.tmp2, self.N, self.ctx)

        self.K = bn_to_bytes(self.S)
        self.M = calculate_client_challenge(self.hash_class, self.A, self.B, self.K)
        self.expected_server_proof = calculate_server_challenge(self.hash_class, self.A, self.M, self.K)

        return self.M

    def verify_session(self, server_proof):
        if self.expected_server_proof == server_proof:
            self._authenticated = True

    def compute_v(self, bytes_s=None, version=PM_VERSION):
        if bytes_s is None:
            BN_rand(self.s, 10*8, 0, 0)
        else:
            bytes_to_bn(self.s, bytes_s)

        calculate_x(self.hash_class, self.x, self.s, self.password, self.N, version)
        BN_mod_exp(self.v, self.g, self.x, self.N, self.ctx)
        return bn_to_bytes(self.s), bn_to_bytes(self.v)

# ---------------------------------------------------------
# Init
#
RAND_seed(os.urandom(32), 32)
