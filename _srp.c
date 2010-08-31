#include <Python.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

/* 2048-bit prime & generator pair from RFC 5054 */
#define N_HEX "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
#define G_HEX "2"


static const BIGNUM * N = 0;
static const BIGNUM * g = 0;
static const BIGNUM * k = 0;


struct SRPVerifier
{
    const char          * username;
    const unsigned char * bytes_B;
    int                   authenticated;
    
    unsigned char M           [SHA256_DIGEST_LENGTH];
    unsigned char H_AMK       [SHA256_DIGEST_LENGTH];
    unsigned char session_key [SHA256_DIGEST_LENGTH];
};


struct SRPUser
{
    BIGNUM *a;
    BIGNUM *A;
    BIGNUM *S;

    const unsigned char * bytes_A;
    int                   authenticated;
    
    const char *          username;
    const unsigned char * password;
    int                   password_len;
    
    unsigned char M           [SHA256_DIGEST_LENGTH];
    unsigned char H_AMK       [SHA256_DIGEST_LENGTH];
    unsigned char session_key [SHA256_DIGEST_LENGTH];
};


/******************************************************************************
 *
 *  SRP Internal Helper Functions
 *
 *****************************************************************************/

/*
static BIGNUM * H_s( const char * s ) 
{
    unsigned char buff[ SHA256_DIGEST_LENGTH ];
    SHA256( (const unsigned char *)s, strlen(s), buff );
    return BN_bin2bn(buff, SHA256_DIGEST_LENGTH, NULL);
}


static BIGNUM * H_n( const BIGNUM * n )
{
    unsigned char   buff[ SHA256_DIGEST_LENGTH ];
    int             nbytes = BN_num_bytes(n);
    unsigned char * bin    = (unsigned char *) malloc( nbytes );
    BN_bn2bin(n, bin);
    SHA256( bin, nbytes, buff );
    free(bin);
    return BN_bin2bn(buff, SHA256_DIGEST_LENGTH, NULL);
}
*/

static BIGNUM * H_nn( const BIGNUM * n1, const BIGNUM * n2 )
{
    unsigned char   buff[ SHA256_DIGEST_LENGTH ];
    int             len_n1 = BN_num_bytes(n1);
    int             len_n2 = BN_num_bytes(n2);
    int             nbytes = len_n1 + len_n2;
    unsigned char * bin    = (unsigned char *) malloc( nbytes );
    BN_bn2bin(n1, bin);
    BN_bn2bin(n2, bin + len_n1);
    SHA256( bin, nbytes, buff );
    free(bin);
    return BN_bin2bn(buff, SHA256_DIGEST_LENGTH, NULL);
}


static BIGNUM * H_ns( const BIGNUM        * n, 
                      const unsigned char * bytes, 
                      int                   len_bytes )
{
    unsigned char   buff[ SHA256_DIGEST_LENGTH ];
    int             len_n  = BN_num_bytes(n);
    int             nbytes = len_n + len_bytes;
    unsigned char * bin    = (unsigned char *) malloc( nbytes );
    BN_bn2bin(n, bin);
    memcpy( bin + len_n, bytes, len_bytes );
    SHA256( bin, nbytes, buff );
    free(bin);
    return BN_bin2bn(buff, SHA256_DIGEST_LENGTH, NULL);
}


static BIGNUM * calculate_x( const BIGNUM        * salt, 
                             const char          * username, 
                             const unsigned char * password, 
                             int                   password_len )
{
    unsigned char ucp_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX    ctx;
        
    SHA256_Init( &ctx );
    
    SHA256_Update( &ctx, username, strlen(username) );
    SHA256_Update( &ctx, ":", 1 );
    SHA256_Update( &ctx, password, password_len );
    
    SHA256_Final( ucp_hash, &ctx );
        
    return H_ns( salt, ucp_hash, sizeof(ucp_hash) );
}


static void update_hash( SHA256_CTX *ctx, const BIGNUM * n )
{
    unsigned long len = BN_num_bytes(n);
    unsigned char * n_bytes = (unsigned char *) malloc( len );
    BN_bn2bin(n, n_bytes);
    SHA256_Update(ctx, n_bytes, len);
    free( n_bytes );
}


static void hash_num( const BIGNUM * n, unsigned char * dest )
{
    int             nbytes = BN_num_bytes(n);
    unsigned char * bin    = (unsigned char *) malloc( nbytes );
    BN_bn2bin(n, bin);
    SHA256( bin, nbytes, dest );
    free( bin );
}


static void calculate_M( unsigned char       * dest, 
                         const char          * I, 
                         const BIGNUM        * s,
                         const BIGNUM        * A, 
                         const BIGNUM        * B,
                         const unsigned char * K )
{
    unsigned char H_N[ SHA256_DIGEST_LENGTH ];
    unsigned char H_g[ SHA256_DIGEST_LENGTH ];
    unsigned char H_I[ SHA256_DIGEST_LENGTH ];
    unsigned char H_xor[ SHA256_DIGEST_LENGTH ];
    SHA256_CTX    ctx;
    int           i = 0;
        
    hash_num( N, H_N );
    hash_num( g, H_g );
    
    SHA256((const unsigned char *)I, strlen(I), H_I);
    
    for (i=0; i < SHA256_DIGEST_LENGTH; i++ )
        H_xor[i] = H_N[i] ^ H_g[i];
    
    SHA256_Init( &ctx );
    
    SHA256_Update( &ctx, H_xor, sizeof(H_xor) );
    SHA256_Update( &ctx, H_I,   sizeof(H_I)   );
    update_hash( &ctx, s );
    update_hash( &ctx, A );
    update_hash( &ctx, B );
    SHA256_Update( &ctx, K, SHA256_DIGEST_LENGTH );
    
    SHA256_Final( dest, &ctx );
}


static void calculate_H_AMK( unsigned char       * dest, 
                             const BIGNUM        * A, 
                             const unsigned char * M, 
                             const unsigned char * K )
{
    SHA256_CTX ctx;
    
    SHA256_Init( &ctx );
    
    update_hash( &ctx, A );
    SHA256_Update( &ctx, M, SHA256_DIGEST_LENGTH);
    SHA256_Update( &ctx, K, SHA256_DIGEST_LENGTH);
    
    SHA256_Final( dest, &ctx );
}


/******************************************************************************
 *
 *  SRP "external" API
 *
 *****************************************************************************/

static void srp_init( const char * random_seed, int seed_len )
{
    BIGNUM *tN   = BN_new();
    BIGNUM *tg   = BN_new();
    
    BN_hex2bn( &tN, N_HEX );
    BN_hex2bn( &tg, G_HEX );
    
    N = tN;
    g = tg;
    
    k = H_nn(N,g);
    
    RAND_seed( random_seed, seed_len );
}

static void srp_fini( void )
{    
    BN_free((BIGNUM *)N);
    BN_free((BIGNUM *)g);
    BN_free((BIGNUM *)k);
    
    N = 0;
    g = 0;
}


static void srp_gen_sv( const char * username,
                        const unsigned char * password, int len_password,
                        const unsigned char ** bytes_s, int * len_s, 
                        const unsigned char ** bytes_v, int * len_v )
{
    BIGNUM * s  = BN_new();
	BIGNUM * v  = BN_new();
	BIGNUM * x  = 0;
	BN_CTX *ctx = BN_CTX_new();
    	
	BN_rand(s, 32, -1, 0);
	
	x = calculate_x( s, username, password, len_password );

	BN_mod_exp(v, g, x, N, ctx);
        
    *len_s   = BN_num_bytes(s);
    *len_v   = BN_num_bytes(v);
    
    *bytes_s = (const unsigned char *) malloc( *len_s );
    *bytes_v = (const unsigned char *) malloc( *len_v );
    
    BN_bn2bin(s, (unsigned char *) *bytes_s);
    BN_bn2bin(v, (unsigned char *) *bytes_v);
        
    BN_free(s);
    BN_free(v);
    BN_free(x);
    BN_CTX_free(ctx);
}


/* Out: bytes_B, len_B.
 * 
 * On failure, bytes_B will be set to NULL and len_B will be set to 0
 */
static struct SRPVerifier *  srp_verifier_new( const char * username,
                               const unsigned char * bytes_s, int len_s,
                               const unsigned char * bytes_v, int len_v,
                               const unsigned char * bytes_A, int len_A,
                               const unsigned char ** bytes_B, int * len_B)
{
    BIGNUM *s    = BN_bin2bn(bytes_s, len_s, NULL);
    BIGNUM *v    = BN_bin2bn(bytes_v, len_v, NULL);
    BIGNUM *A    = BN_bin2bn(bytes_A, len_A, NULL);
    BIGNUM *u    = 0;
    BIGNUM *B    = BN_new();
    BIGNUM *S    = BN_new();
    BIGNUM *b    = BN_new();
    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();
    BN_CTX *ctx  = BN_CTX_new();
    int     ulen = strlen(username) + 1;
    
    struct SRPVerifier * ver;
    
    ver = (struct SRPVerifier *) malloc( sizeof(struct SRPVerifier) );
    
    ver->username = (char *) malloc( ulen );
    
    memcpy( (char*)ver->username, username, ulen );
    
    ver->authenticated = 0;
    	
    /* SRP-6a safety check */
    BN_mod(tmp1, A, N, ctx);
    if ( !BN_is_zero(tmp1) )
    {		
		BN_rand(b, 256, -1, 0);
		
		/* B = kv + g^b */
		BN_mul(tmp1, k, v, ctx);
		BN_mod_exp(tmp2, g, b, N, ctx);
		BN_add(B, tmp1, tmp2);
		
		u = H_nn(A,B);
		
		/* S = (A *(v^u)) ^ b */
		BN_mod_exp(tmp1, v, u, N, ctx);
		BN_mul(tmp2, A, tmp1, ctx);
		BN_mod_exp(S, tmp2, b, N, ctx);

		hash_num(S, ver->session_key);
		
		calculate_M( ver->M, username, s, A, B, ver->session_key );
		calculate_H_AMK( ver->H_AMK, A, ver->M, ver->session_key );
		
        *len_B   = BN_num_bytes(B);
        *bytes_B = malloc( *len_B );
        
        BN_bn2bin( B, (unsigned char *) *bytes_B );
        
        ver->bytes_B = *bytes_B;
	}
    else
    {
        *len_B   = 0;
        *bytes_B = NULL;
    }
    
    BN_free(s);
    BN_free(v);
    BN_free(A);
    if (u) BN_free(u);
    BN_free(B);
    BN_free(S);
    BN_free(b);
    BN_free(tmp1);
    BN_free(tmp2);
    BN_CTX_free(ctx);
    
    return ver;
}

                                        
static void srp_verifier_delete( struct SRPVerifier * ver )
{
    free( (char *) ver->username );
    free( (unsigned char *) ver->bytes_B );
    free( ver );
}


static int srp_verifier_is_authenticated( struct SRPVerifier * ver )
{
    return ver->authenticated;
}


static const char * srp_verifier_get_username( struct SRPVerifier * ver )
{
    return ver->username;
}


/* Key length is SHA256_DIGEST_LENGTH */
static const unsigned char * 
srp_verifier_get_session_key( struct SRPVerifier * ver )
{
    return ver->session_key;
}


/* user_M must be exactly SHA256_DIGEST_LENGTH bytes in size */
static void srp_verifier_verify_session( struct SRPVerifier   * ver, 
                                         const unsigned char  * user_M, 
                                         const unsigned char ** bytes_HAMK )
{
    if ( memcmp( ver->M, user_M, SHA256_DIGEST_LENGTH ) == 0 )
    {
        ver->authenticated = 1;
        *bytes_HAMK = ver->H_AMK;
    }
    else
        *bytes_HAMK = NULL;
}


/*******************************************************************************/

static struct SRPUser * srp_user_new( const char          * username, 
                                      const unsigned char * bytes_password, 
                                      int                   len_password )
{
    struct SRPUser  *usr;
    int              ulen = strlen(username) + 1;
    
    usr  = (struct SRPUser *) malloc( sizeof(struct SRPUser) );
    
    usr->a = BN_new();
    usr->A = BN_new();
    usr->S = BN_new();
    
    usr->username     = (const char *) malloc(ulen);
    usr->password     = (const unsigned char *) malloc(len_password);
    usr->password_len = len_password;
    
    memcpy((char *)usr->username, username,       ulen);
    memcpy((char *)usr->password, bytes_password, len_password);
    
    usr->bytes_A = 0;
	
    return usr;
}


static void srp_user_delete( struct SRPUser * usr )
{
    BN_free( usr->a );
    BN_free( usr->A );
    BN_free( usr->S );
    
    free((char *)usr->username);
    free((char *)usr->password);
    
    if (usr->bytes_A) 
        free( (char *)usr->bytes_A );
    
    free( usr );
}


static int srp_user_is_authenticated( struct SRPUser * usr)
{
    return usr->authenticated;
}


static const char * srp_user_get_username( struct SRPUser * usr )
{
    return usr->username;
}


/* Key length is SHA256_DIGEST_LENGTH */
static const unsigned char * srp_user_get_session_key( struct SRPUser * usr )
{
    return usr->session_key;
}


/* Output: username, bytes_A, len_A */
static void  srp_user_start_authentication( struct SRPUser       * usr, 
                                            const char          ** username,
                                            const unsigned char ** bytes_A, 
                                            int                  * len_A )
{
    BN_CTX  *ctx  = BN_CTX_new();
    
    BN_rand(usr->a, 256, -1, 0);
		
    BN_mod_exp(usr->A, g, usr->a, N, ctx);
		
    BN_CTX_free(ctx);
    
    *len_A   = BN_num_bytes(usr->A);
    *bytes_A = malloc( *len_A );
        
    BN_bn2bin( usr->A, (unsigned char *) *bytes_A );
    
    usr->bytes_A = *bytes_A;
    *username = usr->username;
}


/* Output: bytes_M. Buffer length is SHA256_DIGEST_LENGTH */
static void  srp_user_process_challenge( struct SRPUser * usr, 
                                         const unsigned char * bytes_s, 
                                         int len_s,
                                         const unsigned char * bytes_B, 
                                         int len_B,
                                         const unsigned char ** bytes_M )
{
    BIGNUM *s    = BN_bin2bn(bytes_s, len_s, NULL);
    BIGNUM *B    = BN_bin2bn(bytes_B, len_B, NULL);
    BIGNUM *u    = 0;
    BIGNUM *x    = 0;
    BIGNUM *v    = BN_new();
    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();
    BIGNUM *tmp3 = BN_new();
    BN_CTX *ctx  = BN_CTX_new();
    
    u = H_nn(usr->A,B);
    
    x = calculate_x( s, usr->username, usr->password, usr->password_len );
        
    /* SRP-6a safety check */
    if ( !BN_is_zero(B) && !BN_is_zero(u) )
    {
        BN_mod_exp(v, g, x, N, ctx);
        
        /* S = (B - k*(g^x)) ^ (a + ux) */
        BN_mul(tmp1, u, x, ctx);
        BN_add(tmp2, usr->a, tmp1);             /* tmp2 = (a + ux)      */
        BN_mod_exp(tmp1, g, x, N, ctx);
        BN_mul(tmp3, k, tmp1, ctx);             /* tmp3 = k*(g^x)       */
        BN_sub(tmp1, B, tmp3);                  /* tmp1 = (B - K*(g^x)) */
        BN_mod_exp(usr->S, tmp1, tmp2, N, ctx);

        hash_num(usr->S, usr->session_key);
        
        calculate_M( usr->M, usr->username, s, usr->A, B, usr->session_key );
        calculate_H_AMK( usr->H_AMK, usr->A, usr->M, usr->session_key );
        
        *bytes_M = usr->M;
    }
    else
    {
        *bytes_M = NULL;
    }
    
    BN_free(s);
    BN_free(B);
    BN_free(u);
    BN_free(x);
    BN_free(v);
    BN_free(tmp1);
    BN_free(tmp2);
    BN_free(tmp3);
    BN_CTX_free(ctx);
}
                                                  
/* bytes_HAMK must be exactly SHA256_DIGEST_LENGTH bytes in size */
static void srp_user_verify_session( struct SRPUser      * usr, 
                                     const unsigned char * bytes_HAMK )
{
    if ( memcmp( usr->H_AMK, bytes_HAMK, SHA256_DIGEST_LENGTH ) == 0 )
        usr->authenticated = 1;
}


/******************************************************************************
 * 
 *                         Python Module
 * 
 *****************************************************************************/

typedef struct 
{
    PyObject_HEAD
    struct SRPVerifier  * ver;
    const unsigned char * bytes_B;
    const unsigned char * bytes_s;
    int                   len_B;
    int                   len_s;
}PyVerifier;


typedef struct 
{
    PyObject_HEAD
    struct SRPUser * usr;
}PyUser;


static void ver_dealloc( PyVerifier * self )
{
    if ( self->ver != NULL )
        srp_verifier_delete( self->ver );
    
    if ( self->bytes_s != NULL )
        free( (char *)self->bytes_s );
        
    self->ob_type->tp_free( (PyObject *) self );
}


static void usr_dealloc( PyUser * self )
{
    if ( self->usr != NULL )
        srp_user_delete( self->usr );
    self->ob_type->tp_free( (PyObject *) self );
}


static PyObject * ver_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyVerifier *self = (PyVerifier *) type->tp_alloc(type, 0);
    
    if (!self)
        return NULL;
    
    self->ver     = NULL;
    self->bytes_B = NULL;
    self->bytes_s = NULL;
    self->len_B   = 0;
    self->len_s   = 0;
    
    return (PyObject *) self;
}


static PyObject * usr_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyUser *self = (PyUser *) type->tp_alloc(type, 0);
    
    if (!self)
        return NULL;
    
    self->usr   = NULL;
    
    return (PyObject *) self;
}


static int ver_init( PyVerifier *self, PyObject *args, PyObject *kwds )
{
    const char          *username;
    const unsigned char *bytes_s, *bytes_v, *bytes_A;
    int                  len_s, len_v, len_A;
        
    if ( self->ver != NULL )
    {
        PyErr_SetString(PyExc_TypeError, "Type cannot be re-initialized");
        return -1;
    }
    
    if ( ! PyArg_ParseTuple(args, "st#t#t#", &username, 
                                             &bytes_s, &len_s,
                                             &bytes_v, &len_v,
                                             &bytes_A, &len_A) )
    {
        return -1;
    }
    
    /* The srp_verifier_new command is computationally intensive... ~15ms on a
     * 3Ghz x86 CPU. Allowing multiple, simultaneous calls here may speed 
     * things up for multi-cpu machines
     */
    Py_BEGIN_ALLOW_THREADS
    self->ver = srp_verifier_new( username, 
                                  bytes_s, len_s, 
                                  bytes_v, len_v, 
                                  bytes_A, len_A,
                                  &self->bytes_B, &self->len_B );
    Py_END_ALLOW_THREADS
        
    if ( self->bytes_B == NULL )
    {
        PyErr_SetString(PyExc_Exception, "SRP-6a safety check violated");
        return -1;
    }
    
    self->bytes_s = malloc( len_s );
    self->len_s   = len_s;
    
    memcpy( (char *)self->bytes_s, bytes_s, len_s );
    
    return 0;
}


static int usr_init( PyUser *self, PyObject *args, PyObject *kwds )
{
    const char          *username;
    const unsigned char *bytes_password;
    int                  len_password;
        
    if ( self->usr != NULL )
    {
        PyErr_SetString(PyExc_TypeError, "Type cannot be re-initialized");
        return -1;
    }
    
    if ( ! PyArg_ParseTuple(args, "st#", &username, 
                                         &bytes_password, 
                                         &len_password) )
    {
        return -1;
    }
    
    
    self->usr = srp_user_new( username, bytes_password, len_password );
        
    return 0;
}

    
static PyObject * ver_is_authenticated( PyVerifier * self )
{
    if ( self->ver == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    if ( srp_verifier_is_authenticated(self->ver) )
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}


static PyObject * usr_is_authenticated( PyUser * self )
{
    if ( self->usr == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    if ( srp_user_is_authenticated(self->usr) )
        Py_RETURN_TRUE;
    else
        Py_RETURN_FALSE;
}


static PyObject * ver_get_username( PyVerifier * self )
{
    if ( self->ver == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    
    return PyString_FromString( srp_verifier_get_username(self->ver) );
}


static PyObject * usr_get_username( PyUser * self )
{
    if ( self->usr == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    
    return PyString_FromString( srp_user_get_username(self->usr) );
}


static PyObject * ver_get_session_key( PyVerifier * self )
{
    if ( self->ver == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    if ( srp_verifier_is_authenticated(self->ver) )
    {
        const char * u = (const char *)srp_verifier_get_session_key(self->ver);
        return PyString_FromStringAndSize(u, SHA256_DIGEST_LENGTH);
    }
    else
        Py_RETURN_NONE;
}


static PyObject * usr_get_session_key( PyUser * self )
{
    if ( self->usr == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    if ( srp_user_is_authenticated(self->usr) )
    {
        const char * u = (const char *) srp_user_get_session_key(self->usr);
        return PyString_FromStringAndSize(u, SHA256_DIGEST_LENGTH);
    }
    else
        Py_RETURN_NONE;
}


static PyObject * ver_get_challenge( PyVerifier * self )
{
    if ( self->ver == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    if ( self->bytes_B == NULL ) {
        PyErr_SetString(PyExc_Exception, "SRP-6a security check failed");
        return NULL;
    }
    
    return Py_BuildValue("s#s#", self->bytes_s, 
                                 self->len_s, 
                                 self->bytes_B, 
                                 self->len_B);
}


static PyObject * ver_verify_session( PyVerifier * self, PyObject * args )
{
    const unsigned char * bytes_M;
    const unsigned char * bytes_HAMK;
    int                   len_M;
    
    if ( self->ver == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    
    if ( ! PyArg_ParseTuple(args, "t#", &bytes_M, &len_M) )
    {
        return NULL;
    }
    
    if ( len_M != SHA256_DIGEST_LENGTH )
        Py_RETURN_NONE;
    
    srp_verifier_verify_session( self->ver, bytes_M, &bytes_HAMK );
    
    if ( bytes_HAMK == NULL )
        Py_RETURN_NONE;
    else
        return PyString_FromStringAndSize((const char *) bytes_HAMK, 
                                          SHA256_DIGEST_LENGTH);
}


static PyObject * usr_start_authentication( PyUser * self )
{
    const char          * username;
    const unsigned char * bytes_A;
    int                   len_A;
    
    if ( self->usr == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
        
    srp_user_start_authentication( self->usr, &username, &bytes_A, &len_A );
    
    return Py_BuildValue("ss#", username, bytes_A, len_A);
}


static PyObject * usr_process_challenge( PyUser * self, PyObject * args )
{
    const unsigned char * bytes_s, *bytes_B;
    int                   len_s, len_B;
    const unsigned char * bytes_M;
    
    if ( self->usr == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    
    if ( ! PyArg_ParseTuple(args, "t#t#", &bytes_s, &len_s, &bytes_B, 
                                          &len_B) )
    {
        return NULL;
    }
    
    /* The srp_user_process_challenge command is computationally intensive... 
     * ~20ms on a 2Ghz x86 CPU. Allowing multiple, simultaneous calls here will
     * speed things up for multi-cpu machines.
     */
    Py_BEGIN_ALLOW_THREADS
    srp_user_process_challenge( self->usr, bytes_s, len_s, bytes_B, len_B, 
                                &bytes_M );
    Py_END_ALLOW_THREADS
    
    if (bytes_M == NULL)
        Py_RETURN_NONE;
    else        
        return PyString_FromStringAndSize((const char *) bytes_M, 
                                          SHA256_DIGEST_LENGTH);
}


static PyObject * usr_verify_session( PyUser * self, PyObject * args )
{
    const unsigned char * bytes_HAMK;
    int                   len_HAMK;
    
    if ( self->usr == NULL ) {
        PyErr_SetString(PyExc_Exception, "Type not initialized");
        return NULL;
    }
    
    if ( ! PyArg_ParseTuple(args, "t#", &bytes_HAMK, &len_HAMK) )
    {
        return NULL;
    }
    
    if ( len_HAMK == SHA256_DIGEST_LENGTH )
        srp_user_verify_session( self->usr, bytes_HAMK );
    
    Py_RETURN_NONE;
}


static PyObject * py_gen_sv( PyObject *self, PyObject *args )
{
    const char          *username;
    const unsigned char *bytes_password, *bytes_s, *bytes_v;
    int                  len_password, len_s, len_v;
    PyObject            *ret;
        
    if ( ! PyArg_ParseTuple(args, "st#", &username, &bytes_password, 
                            &len_password) )
        return NULL;
    

    srp_gen_sv( username, bytes_password, len_password, &bytes_s, &len_s, 
                &bytes_v, &len_v );
    
    ret = Py_BuildValue("s#s#", bytes_s, len_s, bytes_v, len_v);
    
    free((char*)bytes_s);
    free((char*)bytes_v);
    
    return ret;
}


/***********************************************************************************/
static PyMethodDef PyVerifier_methods[] = {
    {"authenticated", (PyCFunction) ver_is_authenticated, METH_NOARGS,
            PyDoc_STR("Returns boolean indicating whether the session is "
                      "authenticated or not")
    },
    {"get_username", (PyCFunction) ver_get_username, METH_NOARGS,
            PyDoc_STR("Returns the username the Verifier instance is bound to.")
    },
    {"get_session_key", (PyCFunction) ver_get_session_key, METH_NOARGS,
            PyDoc_STR("Returns the session key for an authenticated session. "
                      "Returns None if the session is not authenticated.")
    },
    {"get_challenge", (PyCFunction) ver_get_challenge, METH_NOARGS,
            PyDoc_STR("Returns: (s,B) or None. The salt & challenge that "
                      "should be sent to the user or None if the SRP-6a "
                      "safety check fails.")
    },
    {"verify_session", (PyCFunction) ver_verify_session, METH_VARARGS,
            PyDoc_STR("Verifies the user based on their reply to "
                      "the challenge")
    },
    {NULL} /* Sentinel */
};


static PyMethodDef PyUser_methods[] = {
    {"authenticated", (PyCFunction) usr_is_authenticated, METH_NOARGS,
            PyDoc_STR("Returns boolean indicating whether the session is "
                      "authenticated or not")
    },
    {"get_username", (PyCFunction) usr_get_username, METH_NOARGS,
            PyDoc_STR("Returns the username the User instance is bound to.")
    },
    {"get_session_key", (PyCFunction) usr_get_session_key, METH_NOARGS,
            PyDoc_STR("Returns the session key for an authenticated session. "
                      "Returns None if the session is not authenticated.")
    },
    {"start_authentication", (PyCFunction) usr_start_authentication, 
            METH_NOARGS,
            PyDoc_STR("Returns (username,A). The username and initial "
                      "authentication challenge to send to the verifier")
    },
    {"process_challenge", (PyCFunction) usr_process_challenge, METH_VARARGS,
            PyDoc_STR("Returns the reply to send to the server or None if the "
                      "SRP-6a safety check fails")
    },
    {"verify_session", (PyCFunction) usr_verify_session, METH_VARARGS,
            PyDoc_STR("Verifies the server based on its reply to the users "
                      "challenge response")
    },
    {NULL} /* Sentinel */
};


static PyMethodDef srp_module_methods[] = {
    {"gen_sv", (PyCFunction) py_gen_sv, METH_VARARGS,
            PyDoc_STR("Returns (s,v): Generates a salt + verifier for the "
                      "given username and password")
    },
    {NULL} /* Sentinel */
};


static PyTypeObject PyVerifier_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_srp.Verifier",            /*tp_name*/
    sizeof(PyVerifier),         /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    /* methods */
    (destructor)ver_dealloc,    /*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    0,                          /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash*/
    0,                          /*tp_call*/
    0,                          /*tp_str*/
    0,                          /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,         /*tp_flags*/
    "SRP-6a verfier",           /*tp_doc*/
    0,                          /*tp_traverse*/
    0,                          /*tp_clear*/
    0,                          /*tp_richcompare*/
    0,                          /*tp_weaklistoffset*/
    0,                          /*tp_iter*/
    0,                          /*tp_iternext*/
    PyVerifier_methods,         /*tp_methods*/
    0,                          /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)ver_init,         /*tp_init*/
    0,                          /*tp_alloc*/
    ver_new,                    /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};


static PyTypeObject PyUser_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_srp.User",                /*tp_name*/
    sizeof(PyUser),             /*tp_basicsize*/
    0,                          /*tp_itemsize*/
    /* methods */
    (destructor)usr_dealloc,    /*tp_dealloc*/
    0,                          /*tp_print*/
    0,                          /*tp_getattr*/
    0,                          /*tp_setattr*/
    0,                          /*tp_compare*/
    0,                          /*tp_repr*/
    0,                          /*tp_as_number*/
    0,                          /*tp_as_sequence*/
    0,                          /*tp_as_mapping*/
    0,                          /*tp_hash*/
    0,                          /*tp_call*/
    0,                          /*tp_str*/
    0,                          /*tp_getattro*/
    0,                          /*tp_setattro*/
    0,                          /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT,         /*tp_flags*/
    "SRP-6a User",              /*tp_doc*/
    0,                          /*tp_traverse*/
    0,                          /*tp_clear*/
    0,                          /*tp_richcompare*/
    0,                          /*tp_weaklistoffset*/
    0,                          /*tp_iter*/
    0,                          /*tp_iternext*/
    PyUser_methods,             /*tp_methods*/
    0,                          /*tp_members*/
    0,                          /*tp_getset*/
    0,                          /*tp_base*/
    0,                          /*tp_dict*/
    0,                          /*tp_descr_get*/
    0,                          /*tp_descr_set*/
    0,                          /*tp_dictoffset*/
    (initproc)usr_init,         /*tp_init*/
    0,                          /*tp_alloc*/
    usr_new,                    /*tp_new*/
    0,                          /*tp_free*/
    0,                          /*tp_is_gc*/
};


PyMODINIT_FUNC
init_srp(void)
{
    int       init_ok    = 0;
    PyObject *m          = NULL;
    PyObject *os         = NULL;
    PyObject *py_urandom = NULL;
    
    os = PyImport_ImportModule("os");
    
    if (os == NULL)
        return;
    
    py_urandom = PyObject_GetAttrString(os, "urandom");

    if ( py_urandom && PyCallable_Check(py_urandom) )
    {
        PyObject *args = Py_BuildValue("(i)", 32);
        if ( args )
        {
            PyObject *randstr = PyObject_CallObject(py_urandom, args);
            if ( randstr && PyString_Check(randstr))
            {
                char       *buff = NULL;
                Py_ssize_t  slen = 0;
                if (!PyString_AsStringAndSize(randstr, &buff, &slen))
                {
                    srp_init( buff, slen );
                    init_ok = 1;
                }
            }
            Py_XDECREF(randstr);
        }
        Py_XDECREF(args);
    }
    
    Py_XDECREF(os);
    Py_XDECREF(py_urandom);
    
    if (!init_ok)
    {
        PyErr_SetString(PyExc_ImportError, "Initialization failed");
        return;
    }
    
    if ( Py_AtExit( &srp_fini ) )
    {
        PyErr_SetString(PyExc_ImportError, "Failed to register atexit handler");
        return;
    }
    
        
    if (PyType_Ready(&PyVerifier_Type) < 0 || PyType_Ready(&PyUser_Type))
        return;
        
    m = Py_InitModule3("_srp", srp_module_methods,"SRP-6a implementation");
        
    if (m == NULL)
        return;
    
    Py_INCREF(&PyVerifier_Type);
    Py_INCREF(&PyUser_Type);
    
    PyModule_AddObject(m, "Verifier", (PyObject*) &PyVerifier_Type );
    PyModule_AddObject(m, "User", (PyObject*) &PyUser_Type );   
}