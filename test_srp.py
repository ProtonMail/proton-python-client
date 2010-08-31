#!/usr/bin/python

NTHREADS = 2
NTEST    = 10

import _pysrp
User     = _pysrp.User
Verifier = _pysrp.Verifier
gen_sv   = _pysrp.gen_sv

import _ctsrp
#User     = _ctsrp.User
#Verifier = _ctsrp.Verifier
#gen_sv   = _ctsrp.gen_sv
    
import _srp
#User     = _srp.User
#Verifier = _srp.Verifier
#gen_sv   = _srp.gen_sv

import srp
#User     = srp.User
#Verifier = srp.Verifier
#gen_sv   = srp.gen_sv

username = 'testuser'
password = 'testpassword'

_s, _v = gen_sv( username, password )
    
def test_one():
    usr      = User( username, password )
    uname, A = usr.start_authentication()
    
    # username, A => server
    svr      = Verifier( uname, _s, _v, A )
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

