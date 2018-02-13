:mod:`srp` --- Secure Remote Password
=====================================

.. module:: srp
    :synopsis: Secure Remote Password
    
.. moduleauthor:: Tom Cocagne <tom.cocagne@gmail.com>

.. sectionauthor:: Tom Cocagne <tom.cocagne@gmail.com>


The Secure Remote Password protocol (SRP) is a cryptographically
strong authentication protocol for password-based, mutual
authentication over an insecure network connection. Successful SRP
authentication requires both sides of the connection to have knowledge
of the user's password. In addition to password verification, the SRP
protocol also performs a secure key exchange during the authentication
process. This key may be used to protect network traffic via symmetric
key encryption.

SRP offers security and deployment advantages over other
challenge-response protocols, such as Kerberos and SSL, in that it
does not require trusted key servers or certificate infrastructures.
Instead, small verification keys derived from each user's password are
stored and used by each SRP server application. SRP provides a
near-ideal solution for many applications requiring simple and secure
password authentication that does not rely on an external
infrastructure.

Another favorable aspect of the SRP protocol is that compromized
verification keys are of little value to an attacker. Possesion of a
verification key does not allow a user to be impersonated
and it cannot be used to obtain the users password except by way of a
computationally infeasible dictionary attack. A compromized key would,
however, allow an attacker to impersonate the server side of an SRP
authenticated connection. Consequently, care should be taken to
prevent unauthorized access to verification keys for applications in
which the client side relies on the server being genuine.



Usage
-----

SRP usage begins with *create_salted_verification_key()*. This function
creates a salted verification key from the user's password. The resulting salt
and key are stored by the server application and will be used during the
authentication process.

The authentication process occurs as an exchange of messages between the clent
and the server. The :ref:`example` below provides a simple demonstration of the
protocol. A comprehensive description of the SRP protocol is contained in the
:ref:`protocol-description` section.

The *User* & *Verifier* constructors, as well as the
*create_salted_verification_key()* function, accept optional arguments
to specify which hashing algorithm and prime number arguments should
be used during the authentication process. These options may be used
to tune the security/performance tradeoff for an application.
Generally speaking, specifying arguments with a higher number of bits
will result in a greater level of security. However, it will come at
the cost of increased computation time. The default values of SHA1
hashes and 2048 bit prime numbers strike a good balance between
performance and security. These values should be sufficient for most
applications. Regardless of which values are used, the parameters
passed to the *User* and *Verifier* constructors must exactly match
those passed to *create_salted_verification_key()*


.. _constants:

Constants
---------

.. table:: Hashing Algorithm Constants

  ==============  ==============
  Hash Algorithm  Number of Bits
  ==============  ==============
  SHA1            160
  SHA224          224
  SHA256          256
  SHA384          384
  SHA512          512
  ==============  ==============

.. note::

  Larger hashing algorithms will result in larger session keys.

.. table:: Prime Number Constants

  ================= ==============
  Prime Number Size Number of Bits
  ================= ==============
  NG_1024           1024
  NG_2048           2048
  NG_4096           4096
  NG_8192           8192
  NG_CUSTOM         User Supplied
  ================= ==============

.. note::

  If NG_CUSTOM is used, the 'n_hex' and 'g_hex' parameters are required.
  These parameters must be ASCII text containing hexidecimal notation of the
  prime number 'n_hex' and the corresponding generator number 'g_hex'. Appendix
  A of RFC 5054 contains several large prime number, generator pairs that may
  be used with NG_CUSTOM.

Functions
---------

.. function:: create_salted_verification_key ( username, password[, hash_alg=SHA1, ng_type=NG_2048, n_hex=None, g_hex=None] )

    *username* Name of the user

    *password* Plaintext user password

    *hash_alg*, *ng_type*, *n_hex*, *g_hex* Refer to the :ref:`constants` section.

    Generate a salted verification key for the given username and password and return the tuple:
    (salt_bytes, verification_key_bytes)


.. function:: rfc5054_enable( enable=True )

    *enable* True if compatibility with RFC5054 is required, False otherwise.

    For backward compatibility, pysrp by default does not conform to RFC5054. If you need compatibility
    with RFC5054, just call this function before using pysrp.

:class:`Verifier` Objects
-------------------------

A :class:`Verifier` object is used to verify the identity of a remote
user.

.. note::

  The standard SRP 6 protocol allows only one password attempt per 
  connection.

.. class:: Verifier( username, bytes_s, bytes_v, bytes_A[, hash_alg=SHA1, ng_type=NG_2048, n_hex=None, g_hex=None] )

  *username* Name of the remote user being authenticated.
  
  *bytes_s* Salt generated by :func:`create_salted_verification_key`.
  
  *bytes_v* Verification Key generated by :func:`create_salted_verification_key`.
  
  *bytes_A* Challenge from the remote user. Generated by
  :meth:`User.start_authentication`  

  *hash_alg*, *ng_type*, *n_hex*, *g_hex* Refer to the :ref:`constants` section.
  
  .. method:: Verifier.authenticated()
  
    Return True if the authentication succeeded. False
    otherwise.
    
  .. method:: Verifier.get_username()
  
    Return the name of the user this :class:`Verifier` object is for.
    
  .. method:: Verifier.get_session_key()
  
    Return the session key for an authenticated user or None if the
    authentication failed or has not yet completed.
    
  .. method:: Verifier.get_challenge()
  
    Return (bytes_s, bytes_B) on success or (None, None) if
    authentication has failed.
    
  .. method:: Verifier.verify_session( user_M )
  
    Complete the :class:`Verifier` side of the authentication
    process. If the authentication succeded the return result,
    bytes_H_AMK should be returned to the remote user. On failure,
    this method returns None.
    
    
:class:`User` Objects
-------------------------

A :class:`User` object is used to prove a user's identity to a remote :class:`Verifier` and
verifiy that the remote :class:`Verifier` knows the verification key associated with
the user's password.

.. class:: User( username, password[, hash_alg=SHA1, ng_type=NG_2048, n_hex=None, g_hex=None] )

  *username* Name of the user being authenticated.
  
  *password* Password for the user.

  *hash_alg*, *ng_type*, *n_hex*, *g_hex* Refer to the :ref:`constants` section.
    
  .. method:: User.authenticated()
  
    Return True if authentication succeeded. False
    otherwise.
    
  .. method:: User.get_username()
  
    Return the username passed to the constructor.
    
  .. method:: User.get_session_key()
  
    Return the session key if authentication succeeded or None if the
    authentication failed or has not yet completed.
    
  .. method:: User.start_authentication()
  
    Return (username, bytes_A). These should be passed to the
    constructor of the remote :class:`Verifer`
    
  .. method:: User.process_challenge( bytes_s, bytes_B )
  
    Processe the challenge returned
    by :meth:`Verifier.get_challenge` on success this method
    returns bytes_M that should be sent
    to :meth:`Verifier.verify_session` if authentication failed,
    it returns None.
    
  .. method:: User.verify_session( bytes_H_AMK )
  
    Complete the :class:`User` side of the authentication process. By
    verifying the *bytes_H_AMK* value returned by
    :meth:`Verifier.verify_session`.  If the authentication succeded
    :meth:`authenticated` will return True
    
.. _example:

Example
-------

Simple Usage Example::

    import srp
    
    # The salt and verifier returned from srp.create_salted_verification_key() should be
    # stored on the server.
    salt, vkey = srp.create_salted_verification_key( 'testuser', 'testpassword' )

    class AuthenticationFailed (Exception):
        pass
    
    # ~~~ Begin Authentication ~~~
    
    usr      = srp.User( 'testuser', 'testpassword' )
    uname, A = usr.start_authentication()
    
    # The authentication process can fail at each step from this
    # point on. To comply with the SRP protocol, the authentication
    # process should be aborted on the first failure.
    
    # Client => Server: username, A
    svr      = srp.Verifier( uname, salt, vkey, A )
    s,B      = svr.get_challenge()

    if s is None or B is None:
        raise AuthenticationFailed()
    
    # Server => Client: s, B
    M        = usr.process_challenge( s, B )

    if M is None:
        raise AuthenticationFailed()
    
    # Client => Server: M
    HAMK     = svr.verify_session( M )

    if HAMK is None:
        raise AuthenticationFailed()
        
    # Server => Client: HAMK
    usr.verify_session( HAMK )
    
    # At this point the authentication process is complete.
    
    assert usr.authenticated()
    assert svr.authenticated()



Implementation Notes
--------------------

This implementation of SRP consists of both a pure-python module and a C-based
implementation that is approximately 10x faster. By default, the
C-implementation will be used if it is available. An additional benefit of the C
implementation is that it can take advantage of of multiple CPUs. For cases in
which the number of connections per second is an issue, using a small pool of
threads to perform the authentication steps on multi-core systems will yield a
substantial performance increase.


.. _protocol-description:

SRP 6a Protocol Description
---------------------------

The original SRP protocol, known as SRP-3, is defined in
RFC 2945. This implementation, however, uses SRP-6a which is a slight
improvement over SRP-3.  The authoritative definition for the SRP-6a
protocol is available at http://srp.stanford.edu. An additional
resource is RFC 5054 which covers the integration of SRP into
TLS. This RFC is the source of hashing strategy and the predefined N
and g constants used in this implementation.

The following is a complete description of the SRP-6a protocol as implemented by
this library. Note that the ^ symbol indicates exponentiaion and the | symbol
indicates concatenation.

.. rubric:: Primary Variables used in SRP 6a

========= =================================================================
Variables Description
========= =================================================================
N         A large, safe prime (N = 2q+1, where q is a Sophie Germain prime)
          All arithmetic is performed in the field of integers modulo N
g         A generator modulo N
s         Small salt for the verification key 
I         Username
p         Cleartext password
H()       One-way hash function
a,b       Secret, random values
K         Session key
========= =================================================================
   

.. rubric:: Derived Values used in SRP 6a

======================================  ====================================
Derived Values                          Description
======================================  ====================================
k = H(N,g)                              Multiplier Parameter       
A = g^a                                 Public ephemeral value
B = kv + g^b                            Public ephemeral value
x = H(s, H( I | ':' | p ))              Private key (as defined by RFC 5054)
v = g^x                                 Password verifier
u = H(A,B)                              Random scrambling parameter
M = H(H(N) xor H(g), H(I), s, A, B, K)  Session key verifier
======================================  ====================================


.. rubric:: Protocol Description

The server stores the password verifier *v*. Authentication begins with a 
message from the client::

    client -> server: I, A = g^a
    
The server replies with the verifier salt and challenge::

    server -> client: s, B = kv + g^b

At this point, both the client and server calculate the shared session key::

     client & server: u = H(A,B)
     
::   

              server: K = H( (Av^u) ^ b )
              
::

              client: x = H( s, H( I + ':' + p ) )            
              client: K = H( (B - kg^x) ^ (a + ux) )

Now both parties have a shared, strong session key *K*. To complete 
authentication they need to prove to each other that their keys match::

    client -> server: M = H(H(N) xor H(g), H(I), s, A, B, K)
    server -> client: H(A, M, K)
    
SRP 6a requires the two parties to use the following safeguards:

1. The client will abort if it recieves B == 0 (mod N) or u == 0
2. The server will abort if it detects A == 0 (mod N)
3. The client must show its proof of K first. If the server detects that this
   proof is incorrect it must abort without showing its own proof of K

