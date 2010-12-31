#!/usr/bin/python

import sys
sys.path.append( 'build/lib.linux-i686-2.6/' )

NTHREADS = 1
NTEST    = 10

import _pysrp
u_mod = _pysrp
v_mod = _pysrp
g_mod = _pysrp

import _ctsrp
u_mod = _ctsrp
v_mod = _ctsrp
#g_mod = _ctsrp

try:
    import _srp
    u_mod = _srp
#    v_mod = _srp
    g_mod = _srp
except:
    print 'C-module not available'
    pass

import srp

User                           = u_mod.User
Verifier                       = v_mod.Verifier
create_salted_verification_key = g_mod.create_salted_verification_key

HASH = srp.SHA256
NG   = srp.NG_CUSTOM


username = 'testuser'
password = 'testpassword'

n_hex = ''
g_hex = ''

if NG == srp.NG_CUSTOM:
    g_hex = "2"
    n_hex = '''\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4\
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60\
95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF\
747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907\
8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861\
60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB\
FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73'''
    


_s, _v = create_salted_verification_key( username, password, hash_alg=HASH, ng_type=NG, n_hex=n_hex, g_hex=g_hex )
    
def test_one():
    usr      = User( username, password, hash_alg=HASH, ng_type=NG, n_hex=n_hex, g_hex=g_hex )
    uname, A = usr.start_authentication()
    
    # username, A => server
    svr      = Verifier( uname, _s, _v, A, hash_alg=HASH, ng_type=NG, n_hex=n_hex, g_hex=g_hex )
    s,B      = svr.get_challenge()
    
    # s,B => client
    M        = usr.process_challenge( s, B )
    
    # M => server
    HAMK     = svr.verify_session( M )
    
    # HAMK => client
    usr.verify_session( HAMK )
    
    if not svr.authenticated() or not usr.authenticated(): 
        raise Exception('Authentication failed!')

#---------------------------------------------------------------

import time
import thread

NTESTED = 0

def test_thread():
    global NTESTED
    while NTESTED < NTEST:
        test_one()
        NTESTED += 1

start = time.time()
while NTHREADS > 1:
    thread.start_new_thread( test_thread, () )
    NTHREADS -= 1
test_thread()
duration = time.time() - start

# Pause briefly to ensure no background threads are still executing
time.sleep(0.1)

print 'Total time: ', duration
print 'Time per call: ', duration/NTEST

