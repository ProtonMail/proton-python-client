#!/usr/bin/env python

import unittest
import os.path
import os
import sys
import time
from six.moves import _thread
import six

this_dir = os.path.dirname( os.path.abspath(__file__) )

build_dir = os.path.join( os.path.dirname(this_dir), 'build' )

if not os.path.exists( build_dir ):
    print('Please run "python setup.py build" prior to running tests')
    sys.exit(1)

plat_dirs = [ d for d in os.listdir('build') if d.startswith('lib') ]

if not len(plat_dirs) == 1:
    print('Unexpected build result... aborting')

plat_dir = os.path.join( build_dir, plat_dirs[0] )

sys.path.insert(0, os.path.join('build', plat_dir)  )



import srp
import srp._pysrp as _pysrp
import srp._ctsrp as _ctsrp


test_g_hex = six.b("2")
test_n_hex = six.b('''\
AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4\
A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60\
95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF\
747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907\
8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861\
60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB\
FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73''')


class SRPTests( unittest.TestCase ):

    def doit(self, u_mod, v_mod, g_mod, hash_alg=srp.SHA1, ng_type=srp.NG_2048, n_hex='', g_hex=''):
        User                           = u_mod.User
        Verifier                       = v_mod.Verifier
        create_salted_verification_key = g_mod.create_salted_verification_key

        username = six.b('testuser')
        password = six.b('testpassword')

        _s, _v = create_salted_verification_key( username, password, hash_alg, ng_type, n_hex, g_hex )

        usr      = User( username, password, hash_alg, ng_type, n_hex, g_hex )
        bytes_a  = usr.get_ephemeral_secret()
        uname, A = usr.start_authentication()

        # Make sure a recreated User does all the same appropriate things
        usr2     = User( username, password, hash_alg, ng_type, n_hex, g_hex, bytes_a )
        self.assertEqual(bytes_a, usr2.get_ephemeral_secret())
        uname2, A2 = usr2.start_authentication()
        self.assertEqual(uname, uname2)
        self.assertEqual(A, A2)

        # username, A => server
        svr      = Verifier( uname, _s, _v, A, hash_alg, ng_type, n_hex, g_hex )
        bytes_b  = svr.get_ephemeral_secret()
        s,B      = svr.get_challenge()

        # s,B => client
        M        = usr.process_challenge( s, B )
        M2       = usr2.process_challenge( s, B )
        self.assertEqual(M, M2)

        # M => server
        HAMK     = svr.verify_session( M )

        # Make sure that a recreated Verifier will authenticate appropriately
        svr2     = Verifier( uname, _s, _v, A, hash_alg, ng_type, n_hex, g_hex, bytes_b )
        self.assertEqual(bytes_b, svr2.get_ephemeral_secret())
        HAMK2    = svr2.verify_session( M )
        self.assertEqual(HAMK, HAMK2)

        # HAMK => client
        usr.verify_session( HAMK )
        usr2.verify_session( HAMK )

        self.assertTrue( svr.authenticated() )
        self.assertTrue( svr2.authenticated() )

        self.assertTrue( usr.authenticated() )
        self.assertTrue( svr2.authenticated() )

    def test_pure_python_defaults(self):
        self.doit( _pysrp, _pysrp, _pysrp )

    def test_ctypes_defaults(self):
        self.doit( _ctsrp, _ctsrp, _ctsrp )

    def test_mix1(self):
        self.doit( _pysrp, _ctsrp, _ctsrp )

    def test_mix2(self):
        self.doit( _pysrp, _pysrp, _ctsrp )

    def test_mix3(self):
        self.doit( _ctsrp, _pysrp, _pysrp )

    def test_mix4(self):
        self.doit( _ctsrp, _ctsrp, _pysrp )


    def test_hash_SHA512(self):
        self.doit( _ctsrp, _ctsrp, _ctsrp, hash_alg=srp.SHA512 )

    def test_NG_8192(self):
        self.doit( _ctsrp, _ctsrp, _ctsrp, ng_type=srp.NG_8192 )

    def test_NG_CUSTOM(self):
        self.doit( _ctsrp, _ctsrp, _ctsrp, ng_type=srp.NG_CUSTOM, n_hex=test_n_hex, g_hex=test_g_hex )

    def test_all1(self):
        self.doit( _ctsrp, _pysrp, _ctsrp, hash_alg=srp.SHA256, ng_type=srp.NG_CUSTOM, n_hex=test_n_hex, g_hex=test_g_hex )

    def test_all2(self):
        self.doit( _ctsrp, _pysrp, _ctsrp, hash_alg=srp.SHA224, ng_type=srp.NG_4096 )

    def test_random_of_length(self):
        """
        Verify that the Python implementation guarantees byte length by
        setting most significant bit to 1
        """
        for x in range(10):
            val = _pysrp.get_random_of_length(32)
            self.assertTrue(val >> 255 == 1)

    def test_ephemeral_length(self):
        """
        Verify that all implementations require 32 bytes for ephemeral values
        """
        random31 = _pysrp.long_to_bytes(_pysrp.get_random_of_length(31))
        random33 = _pysrp.long_to_bytes(_pysrp.get_random_of_length(33))

        def verf_len(mod, val):
            with self.assertRaises(ValueError) as ctx:
                mod.User('uname', 'pwd', bytes_a=val)
            self.assertIn('bytes_a', str(ctx.exception) )

            with self.assertRaises(ValueError) as ctx:
                mod.Verifier('uname', random31, random31, random31, bytes_b=val)
            self.assertIn('bytes_b', str(ctx.exception) )

        for mod in [_ctsrp, _pysrp]:
            for val in [random31, random33]:
                verf_len(mod, val)

    def test_authenticated_on_init(self):
        usr = _pysrp.User('test', 'test')
        self.assertTrue(not usr.authenticated())

        usr = _ctsrp.User('test', 'test')
        self.assertTrue(not usr.authenticated())


#-----------------------------------------------------------------------------------
# Performance Testing
#
hash_map  = { 0 : 'SHA1  ', 1 : 'SHA224', 2 : 'SHA256', 3 : 'SHA384', 4 : 'SHA512' }
prime_map = { 0 : 1024, 1 : 2048, 2 : 4096, 3 : 8192 }

username = six.b('testuser')
password = six.b('testpassword')

NLEFT = 0

def do_auth( mod, hash_alg, ng_type, _s, _v ):

    usr      = mod.User( username, password, hash_alg, ng_type)
    uname, A = usr.start_authentication()

    # username, A => server
    svr      = mod.Verifier( uname, _s, _v, A, hash_alg, ng_type)
    s,B      = svr.get_challenge()

    # s,B => client
    M        = usr.process_challenge( s, B )

    # M => server
    HAMK     = svr.verify_session( M )

    # HAMK => client
    usr.verify_session( HAMK )

    if not svr.authenticated() or not usr.authenticated():
        raise Exception('Authentication failed!')


def performance_test( mod, hash_alg, ng_type, niter=10, nthreads=1 ):
    global NLEFT
    _s, _v = srp.create_salted_verification_key( username, password, hash_alg, ng_type )

    NLEFT = niter

    def test_thread():
        global NLEFT
        while NLEFT > 0:
            do_auth( mod, hash_alg, ng_type, _s, _v )
            NLEFT -= 1

    start = time.time()
    while nthreads > 1:
        _thread.start_new_thread( test_thread, () )
        nthreads -= 1

    test_thread()
    duration = time.time() - start

    return duration


def get_param_str( mod, hash_alg, ng_type ):

    m = { 'srp._pysrp' : 'Python',
          'srp._ctsrp' : 'ctypes' }

    cfg = '%s, %s, %d:' % (m[mod.__name__], hash_map[hash_alg], prime_map[ng_type])

    return cfg


def param_test( mod, hash_alg, ng_type, niter=10 ):
    duration = performance_test( mod, hash_alg, ng_type, niter )
    cfg = get_param_str( mod, hash_alg, ng_type )
    print('   ', cfg.ljust(20), '%.6f' % (duration/niter))
    return duration/niter


def print_default_timings():
    print('*'*60)
    print('Default Parameter Timings:')
    py_time = param_test( _pysrp, srp.SHA1, srp.NG_2048 )
    ct_time = param_test( _ctsrp, srp.SHA1, srp.NG_2048 )
    print('')
    print('Performance increases: ')
    print('   ctypes-module : ', py_time/ct_time)


def print_performance_table():
    ng_types = [ srp.NG_1024, srp.NG_2048, srp.NG_4096, srp.NG_8192 ]
    hash_types = [ srp.SHA1, srp.SHA224, srp.SHA256, srp.SHA384, srp.SHA512 ]

    print('*'*60)
    print('Hash Algorithm vs Prime Number performance table')
    print('')
    six.print_('       |', end=' ')
    for ng in ng_types:
        six.print_(('NG_%d' % prime_map[ng]).rjust(12), end=' ')
    print('')
    print('-'*60)

    for hash_alg in hash_types:

        six.print_('%s |' % hash_map[hash_alg], end=' ')
        for ng in ng_types:
            six.print_('{0:>12f}'.format(performance_test(_ctsrp, hash_alg, ng) / 10), end=' ')
        print('')


def print_thread_performance():
    print('*'*60)
    print('Thread Performance Test:')
    niter = 100
    for nthreads in range(1,11):
        print('   Thread Count {0:>2}: {1:8f}'.format(nthreads, performance_test(_ctsrp, srp.SHA1, srp.NG_2048, niter, nthreads)/niter))


print('*'*60)
print('*')
print('* Testing Implementation')
print('*')
suite = unittest.TestLoader().loadTestsFromTestCase(SRPTests)
unittest.TextTestRunner(verbosity=1).run(suite)

print('*'*60)
print('*')
print('* Performance Testing')
print('*')
print_thread_performance()
print_performance_table()
print_default_timings()
#---------------------------------------------------------------

# Pause briefly to ensure no background threads are still executing
time.sleep(0.1)
