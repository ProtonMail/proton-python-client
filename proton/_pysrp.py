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

import hashlib
import os
import binascii
import six
import bcrypt
import base64

from .pmhash import pmhash

PM_VERSION = 4

def get_ng( n_bin, g_hex ):
    return bytes_to_long(n_bin), int(g_hex,16)

def long_length(n):
    return (n.bit_length() + 7) // 8

def bytes_to_long(s):
    return int.from_bytes(s, 'little')

def long_to_bytes(n):
    return n.to_bytes(long_length(n), 'little')

def get_random( nbytes ):
    return bytes_to_long( os.urandom( nbytes ) )


def get_random_of_length( nbytes ):
    offset = (nbytes*8) - 1
    return get_random( nbytes ) | (1 << offset)

def H( hash_class, *args, **kwargs ):
    width = kwargs.get('width', None)

    h = hash_class()

    for s in args:
        if s is not None:
            data = long_to_bytes(s) if isinstance(s, six.integer_types) else s
            h.update( data )

    return bytes_to_long( h.digest() )

def hash_k( hash_class, g, N, width):
    h = hash_class()
    h.update( g.to_bytes(width, 'little') )
    h.update( N.to_bytes(width, 'little') )
    return bytes_to_long( h.digest() )


def bcryptB64encode(s): # The joy of bcrypt
    bcrypt_base64  = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    std_base64chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    s = base64.b64encode(s)
    return s.translate(bytes.maketrans(std_base64chars, bcrypt_base64))


def hash_password_3(hash_class, password, salt, modulus):
    salt = (salt + b"proton")[:16]
    salt = bcryptB64encode(salt)[:22]
    hashed = bcrypt.hashpw(password, b"$2y$10$" + salt)
    return hash_class( hashed + modulus ).digest()


def hash_password(hash_class, password, salt, username, modulus, version):
    if version == 4 or version == 3:
        return hash_password_3(hash_class, password, salt, modulus)

    # if version == 2:
    #     return hash_password_1(password, cleanUsername(username), modulus)
    #
    # if version == 1:
    #     return hash_password_1(password, username, modulus)
    #
    # if version == 0:
    #     return hash_password_0(password, username, modulus)

    raise ValueError('Unsupported auth version')

def calculate_x( hash_class, salt, username, password, modulus, version ):
    username = username.encode() if hasattr(username, 'encode') else username
    password = password.encode() if hasattr(password, 'encode') else password
    exp = hash_password(hash_class, password, long_to_bytes(salt), username, long_to_bytes(modulus), version)
    return bytes_to_long(exp)


def create_salted_verification_key( username, password, n_bin, g_hex=b"2", salt_len=4 ):
    hash_class = pmhash
    N,g = get_ng( n_bin, g_hex )
    _s = long_to_bytes( get_random( salt_len ) )
    _v = long_to_bytes( pow(g,  gen_x( hash_class, _s, username, password ), N) )

    return _s, _v

def calculate_M( hash_class, A, B, K ):
    h = hash_class()
    h.update( long_to_bytes(A) )
    h.update( long_to_bytes(B) )
    h.update( K )
    return h.digest()


def calculate_H_AMK( hash_class, A, M, K ):
    h = hash_class()
    h.update( long_to_bytes(A) )
    h.update( M )
    h.update( K )
    return h.digest()


class User (object):
    def __init__(self, username, password, n_bin, g_hex=b"2", bytes_a=None, bytes_A=None):
        if bytes_a and len(bytes_a) != 32:
            raise ValueError("32 bytes required for bytes_a")
        N,g        = get_ng( n_bin, g_hex )
        hash_class = pmhash
        k          = hash_k( hash_class, g, N, width=long_length(N) )

        self.I     = username
        self.p     = password
        if bytes_a:
            self.a = bytes_to_long(bytes_a)
        else:
            self.a = get_random_of_length( 32 )
        if bytes_A:
            self.A = bytes_to_long(bytes_A)
        else:
            self.A = pow(g, self.a, N)
        self.v     = None
        self.M     = None
        self.K     = None
        self.H_AMK = None
        self._authenticated = False

        self.hash_class = hash_class
        self.N          = N
        self.g          = g
        self.k          = k


    def authenticated(self):
        return self._authenticated


    def get_username(self):
        return self.I


    def get_ephemeral_secret(self):
        return long_to_bytes(self.a)


    def get_session_key(self):
        return self.K if self._authenticated else None


    def start_authentication(self):
        return (self.I, long_to_bytes(self.A))


    # Returns M or None if SRP-6a safety check is violated
    def process_challenge(self, bytes_s, bytes_B, version = PM_VERSION):

        self.s = bytes_to_long( bytes_s )
        self.B = bytes_to_long( bytes_B )

        N = self.N
        g = self.g
        k = self.k

        hash_class = self.hash_class

        # SRP-6a safety check
        if (self.B % N) == 0:
            return None

        self.u = H( hash_class, self.A, self.B, width=len(long_to_bytes(N)) )

        # SRP-6a safety check
        if self.u == 0:
            return None

        self.x = calculate_x( hash_class, self.s, self.I, self.p,  N, version )

        self.v = pow(g, self.x, N)

        self.S = pow((self.B - k*self.v), (self.a + self.u*self.x), N)

        self.K     = long_to_bytes(self.S)
        self.M     = calculate_M( hash_class, self.A, self.B, self.K )
        self.H_AMK = calculate_H_AMK(hash_class, self.A, self.M, self.K)

        return self.M


    def verify_session(self, host_HAMK):
        if self.H_AMK == host_HAMK:
            self._authenticated = True
