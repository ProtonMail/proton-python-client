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
#v_mod = _ctsrp
#g_mod = _ctsrp

try:
    import _srp
    u_mod = _srp
    v_mod = _srp
    g_mod = _srp
except:
    print 'C-module not available'
    pass

import srp

User     = u_mod.User
Verifier = v_mod.Verifier
gen_sv   = g_mod.gen_sv

HASH = srp.SHA256
NG   = srp.NG_2048


username = 'testuser'
password = 'testpassword'

_s, _v = gen_sv( username, password, hash_alg=HASH, ng_type=NG )
    
def test_one():
    usr      = User( username, password, hash_alg=HASH, ng_type=NG )
    uname, A = usr.start_authentication()
    
    # username, A => server
    svr      = Verifier( uname, _s, _v, A, hash_alg=HASH, ng_type=NG )
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

