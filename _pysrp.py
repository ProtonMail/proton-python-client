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


def bytes_to_long(s):
    n = ord(s[0])
    for b in ( ord(x) for x in s[1:] ):
        n = (n << 8) | b
    return n
    
    
def long_to_bytes(n):
    l = list()
    x = 0
    off = 0
    while x != n:
        b = (n >> off) & 0xFF
        l.append( chr(b) )
        x = x | (b << off)
        off += 8
    l.reverse()
    return ''.join(l)

    
def get_random( nbytes ):
    return bytes_to_long( os.urandom( nbytes ) )

    
def old_H( s1, s2 = '', s3=''):
    if isinstance(s1, (long, int)):
        s1 = long_to_bytes(s1)
    if s2 and isinstance(s2, (long, int)):
        s2 = long_to_bytes(s2)
    if s3 and isinstance(s3, (long, int)):
        s3 = long_to_bytes(s3)
    s = s1 + s2 + s3
    return long(hashlib.sha256(s).hexdigest(), 16)
    
    
def H( *args, **kwargs ):
    h = hashlib.sha256()
    
    for s in args:
        if s is not None:
            h.update( long_to_bytes(s) if isinstance(s, (long, int)) else s )

    return long( h.hexdigest(), 16 )



N = 0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73;
g = 2;    
k = H(N,g)  

hN = hashlib.sha256( long_to_bytes(N) ).digest()
hg = hashlib.sha256( long_to_bytes(g) ).digest()

HNxorg  = ''.join( chr( ord(hN[i]) ^ ord(hg[i]) ) for i in range(0,len(hN)) )
    
    
    
def gen_x( salt, username, password ):
    return H( salt, H( username + ':' + password ) )
    
    
    
    
def gen_sv( username, password ):
    _s = long_to_bytes( get_random( 4 ) )
    _v = long_to_bytes( pow(g,  gen_x( _s, username, password ), N) )
    
    return _s, _v
    

    
def calculate_M( I, s, A, B, K ):
    h = hashlib.sha256()
    h.update( HNxorg )
    h.update( hashlib.sha256(I).digest() )
    h.update( long_to_bytes(s) )
    h.update( long_to_bytes(A) )
    h.update( long_to_bytes(B) )
    h.update( K )
    return h.digest()


def calculate_H_AMK( A, M, K ):
    h = hashlib.sha256()
    h.update( long_to_bytes(A) )
    h.update( M )
    h.update( K )
    return h.digest()


  
  
class Verifier (object):
  
    def __init__(self, username, bytes_s, bytes_v, bytes_A):
        self.s = bytes_to_long(bytes_s)
        self.v = bytes_to_long(bytes_v)
        self.I = username
        self.K = None
        self._authenticated = False
        
        self.A = bytes_to_long(bytes_A)
        
        # SRP-6a safety check
        self.safety_failed = self.A % N == 0
        
        if not self.safety_failed:
            
            self.b = get_random( 32 )
            self.B = (k*self.v + pow(g, self.b, N)) % N
            self.u = H(self.A, self.B)
            self.S = pow(self.A*pow(self.v, self.u, N ), self.b, N)
            self.K = hashlib.sha256( long_to_bytes(self.S) ).digest()
            self.M = calculate_M( self.I, self.s, self.A, self.B, self.K )
            self.H_AMK = calculate_H_AMK(self.A, self.M, self.K)
        
        
    def authenticated(self):
        return self._authenticated
    
    
    def get_username(self):
        return self.I
    
        
    def get_session_key(self):
        return self.K if self._authenticated else None
        
    # returns (bytes_s, bytes_B) on success, (None,None) if SRP-6a safety check fails
    def get_challenge(self):
        if self.safety_failed:
            return None,None
        else:
            return (long_to_bytes(self.s), long_to_bytes(self.B))
        
    # returns H_AMK on success, None on failure
    def verify_session(self, user_M):
        if not self.safety_failed and user_M == self.M:
            self._authenticated = True
            return self.H_AMK
        
        
        
        
class User (object):
    def __init__(self, username, password):
        self.I     = username
        self.p     = password
        self.a     = get_random( 32 )
        self.A     = pow(g, self.a, N)
        self.v     = None
        self.M     = None
        self.K     = None
        self.H_AMK = None
        self._authenticated = False
        
    
    def authenticated(self):
        return self._authenticated
    
    
    def get_username(self):
        return self.username
    
    
    def get_session_key(self):
        return self.K if self._authenticated else None
    
    
    def start_authentication(self):
        return (self.I, long_to_bytes(self.A))
        
    
    # Returns M or None if SRP-6a safety check is violated
    def process_challenge(self, bytes_s, bytes_B):

        self.s = bytes_to_long( bytes_s )
        self.B = bytes_to_long( bytes_B )
        
        # SRP-6a safety check
        if (self.B % N) == 0:
            return None
        
        self.u = H( self.A, self.B )
        
        # SRP-6a safety check
        if self.u == 0:
            return None
        
        self.x = gen_x( self.s, self.I, self.p )
        
        self.v = pow(g, self.x, N)
        
        self.S = pow((self.B - k*self.v), (self.a + self.u*self.x), N)
        
        self.K     = hashlib.sha256( long_to_bytes(self.S) ).digest()        
        self.M     = calculate_M( self.I, self.s, self.A, self.B, self.K )
        self.H_AMK = calculate_H_AMK(self.A, self.M, self.K)
        
        return self.M
        
        
    def verify_session(self, host_HAMK):
        if self.H_AMK == host_HAMK:
            self._authenticated = True
