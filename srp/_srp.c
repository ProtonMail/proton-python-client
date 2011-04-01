#include <Python.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

/*****************************************************************************/
/*                          Begin SRP Header                                 */
/*****************************************************************************/

struct SRPVerifier;
struct SRPUser;

typedef enum
{
    SRP_NG_1024,
    SRP_NG_2048,
    SRP_NG_4096,
    SRP_NG_8192,
    SRP_NG_CUSTOM
} SRP_NGType;

typedef enum 
{
    SRP_SHA1,
    SRP_SHA224, 
    SRP_SHA256,
    SRP_SHA384, 
    SRP_SHA512
} SRP_HashAlgorithm;


/* This library will automatically seed the OpenSSL random number generator
 * using cryptographically sound random data on Windows & Linux. If this is
 * undesirable behavior or the host OS does not provide a /dev/urandom file, 
 * this function may be called to seed the random number generator with 
 * alternate data. 
 * 
 * Passing a null pointer to this function will cause this library to skip
 * seeding the random number generator.
 * 
 * Notes: 
 *    * This function is optional on Windows & Linux.
 * 
 *    * This function is mandatory on all other platforms. Although it
 *      will appear to work on other platforms, this library uses the current
 *      time of day to seed the random number generator. This is well known to
 *      be insecure. 
 * 
 *    * When using this function, ensure the provided random data is
 *      cryptographically strong.
 */
void srp_random_seed( const unsigned char * random_data, int data_length );


/* Out: bytes_s, len_s, bytes_v, len_v
 * 
 * The caller is responsible for freeing the memory allocated for bytes_s and bytes_v
 * 
 * The n_hex and g_hex parameters should be 0 unless SRP_NG_CUSTOM is used for ng_type.
 * If provided, they must contain ASCII text of the hexidecimal notation.
 */
void srp_create_salted_verification_key( SRP_HashAlgorithm alg, SRP_NGType ng_type, const char * username,
                                         const unsigned char * password, int len_password,
                                         const unsigned char ** bytes_s, int * len_s, 
                                         const unsigned char ** bytes_v, int * len_v,
                                         const char * n_hex, const char * g_hex );


/* Out: bytes_B, len_B.
 * 
 * On failure, bytes_B will be set to NULL and len_B will be set to 0
 * 
 * The n_hex and g_hex parameters should be 0 unless SRP_NG_CUSTOM is used for ng_type
 */
struct SRPVerifier *  srp_verifier_new( SRP_HashAlgorithm alg, SRP_NGType ng_type, const char * username,
                                        const unsigned char * bytes_s, int len_s, 
                                        const unsigned char * bytes_v, int len_v,
                                        const unsigned char * bytes_A, int len_A,
                                        const unsigned char ** bytes_B, int * len_B,
                                        const char * n_hex, const char * g_hex );


void                  srp_verifier_delete( struct SRPVerifier * ver );


int                   srp_verifier_is_authenticated( struct SRPVerifier * ver );


const char *          srp_verifier_get_username( struct SRPVerifier * ver );

/* key_length may be null */
const unsigned char * srp_verifier_get_session_key( struct SRPVerifier * ver, int * key_length );


int                   srp_verifier_get_session_key_length( struct SRPVerifier * ver );


/* user_M must be exactly srp_verifier_get_session_key_length() bytes in size */
void                  srp_verifier_verify_session( struct SRPVerifier * ver,
                                                   const unsigned char * user_M, 
                                                   const unsigned char ** bytes_HAMK );

/*******************************************************************************/

/* The n_hex and g_hex parameters should be 0 unless SRP_NG_CUSTOM is used for ng_type */
struct SRPUser *      srp_user_new( SRP_HashAlgorithm alg, SRP_NGType ng_type, const char * username,
                                    const unsigned char * bytes_password, int len_password,
                                    const char * n_hex, const char * g_hex );
                                    
void                  srp_user_delete( struct SRPUser * usr );

int                   srp_user_is_authenticated( struct SRPUser * usr);


const char *          srp_user_get_username( struct SRPUser * usr );

/* key_length may be null */
const unsigned char * srp_user_get_session_key( struct SRPUser * usr, int * key_length );

int                   srp_user_get_session_key_length( struct SRPUser * usr );

/* Output: username, bytes_A, len_A */
void                  srp_user_start_authentication( struct SRPUser * usr, const char ** username, 
                                                     const unsigned char ** bytes_A, int * len_A );

/* Output: bytes_M, len_M  (len_M may be null and will always be 
 *                          srp_user_get_session_key_length() bytes in size) */
void                  srp_user_process_challenge( struct SRPUser * usr, 
                                                  const unsigned char * bytes_s, int len_s, 
                                                  const unsigned char * bytes_B, int len_B,
                                                  const unsigned char ** bytes_M, int * len_M );
                                                  
/* bytes_HAMK must be exactly srp_user_get_session_key_length() bytes in size */
void                  srp_user_verify_session( struct SRPUser * usr, const unsigned char * bytes_HAMK );


/*****************************************************************************/
/*                        Begin SRP Library                                  */
/*****************************************************************************/


static int g_initialized = 0;

typedef struct
{
    BIGNUM     * N;
    BIGNUM     * g;
} NGConstant;

struct NGHex 
{
    const char * n_hex;
    const char * g_hex;
};

/* All constants here were pulled from Appendix A of RFC 5054 */
static struct NGHex global_Ng_constants[] = {
 { /* 1024 */
   "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496"
   "EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8E"
   "F4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA"
   "9AFD5138FE8376435B9FC61D2FC0EB06E3",
   "2"
 },
 { /* 2048 */
   "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4"
   "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60"
   "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF"
   "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907"
   "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861"
   "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB"
   "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
   "2"
 },
 { /* 4096 */
   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
   "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
   "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
   "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
   "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
   "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
   "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
   "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
   "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
   "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
   "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
   "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
   "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
   "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
   "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
   "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
   "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
   "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
   "FFFFFFFFFFFFFFFF",
   "5"
 },
 { /* 8192 */
   "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
   "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
   "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
   "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
   "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
   "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
   "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
   "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
   "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
   "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
   "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
   "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
   "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
   "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
   "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
   "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
   "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
   "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
   "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
   "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
   "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
   "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
   "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
   "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
   "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
   "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
   "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
   "6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA"
   "3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C"
   "5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
   "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886"
   "2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6"
   "6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5"
   "0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268"
   "359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6"
   "FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
   "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
   "13"
 },
 {0,0} /* null sentinel */
};


static NGConstant * new_ng( SRP_NGType ng_type, const char * n_hex, const char * g_hex )
{
    NGConstant * ng   = (NGConstant *) malloc( sizeof(NGConstant) );
    ng->N             = BN_new();
    ng->g             = BN_new();

    if ( ng_type != SRP_NG_CUSTOM )
    {
        n_hex = global_Ng_constants[ ng_type ].n_hex;
        g_hex = global_Ng_constants[ ng_type ].g_hex;
    }
        
    BN_hex2bn( &ng->N, n_hex );
    BN_hex2bn( &ng->g, g_hex );
    
    return ng;
}

static void delete_ng( NGConstant * ng )
{
    BN_free( ng->N );
    BN_free( ng->g );
    ng->N = 0;
    ng->g = 0;
    free(ng);
}



typedef union 
{
    SHA_CTX    sha;
    SHA256_CTX sha256;
    SHA512_CTX sha512;
} HashCTX;


struct SRPVerifier
{
    SRP_HashAlgorithm  hash_alg;
    NGConstant        *ng;
    
    const char          * username;
    const unsigned char * bytes_B;
    int                   authenticated;
    
    unsigned char M           [SHA512_DIGEST_LENGTH];
    unsigned char H_AMK       [SHA512_DIGEST_LENGTH];
    unsigned char session_key [SHA512_DIGEST_LENGTH];
};


struct SRPUser
{
    SRP_HashAlgorithm  hash_alg;
    NGConstant        *ng;
    
    BIGNUM *a;
    BIGNUM *A;
    BIGNUM *S;

    const unsigned char * bytes_A;
    int                   authenticated;
    
    const char *          username;
    const unsigned char * password;
    int                   password_len;
    
    unsigned char M           [SHA512_DIGEST_LENGTH];
    unsigned char H_AMK       [SHA512_DIGEST_LENGTH];
    unsigned char session_key [SHA512_DIGEST_LENGTH];
};


static int hash_init( SRP_HashAlgorithm alg, HashCTX *c )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA1_Init( &c->sha );
      case SRP_SHA224: return SHA224_Init( &c->sha256 );
      case SRP_SHA256: return SHA256_Init( &c->sha256 );
      case SRP_SHA384: return SHA384_Init( &c->sha512 );
      case SRP_SHA512: return SHA512_Init( &c->sha512 );
      default:
        return -1;
    };
}
static int hash_update( SRP_HashAlgorithm alg, HashCTX *c, const void *data, size_t len )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA1_Update( &c->sha, data, len );
      case SRP_SHA224: return SHA224_Update( &c->sha256, data, len );
      case SRP_SHA256: return SHA256_Update( &c->sha256, data, len );
      case SRP_SHA384: return SHA384_Update( &c->sha512, data, len );
      case SRP_SHA512: return SHA512_Update( &c->sha512, data, len );
      default:
        return -1;
    };
}
static int hash_final( SRP_HashAlgorithm alg, HashCTX *c, unsigned char *md )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA1_Final( md, &c->sha );
      case SRP_SHA224: return SHA224_Final( md, &c->sha256 );
      case SRP_SHA256: return SHA256_Final( md, &c->sha256 );
      case SRP_SHA384: return SHA384_Final( md, &c->sha512 );
      case SRP_SHA512: return SHA512_Final( md, &c->sha512 );
      default:
        return -1;
    };
}
static unsigned char * hash( SRP_HashAlgorithm alg, const unsigned char *d, size_t n, unsigned char *md )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA1( d, n, md );
      case SRP_SHA224: return SHA224( d, n, md );
      case SRP_SHA256: return SHA256( d, n, md );
      case SRP_SHA384: return SHA384( d, n, md );
      case SRP_SHA512: return SHA512( d, n, md );
      default:
        return 0;
    };
}
static int hash_length( SRP_HashAlgorithm alg )
{
    switch (alg)
    {
      case SRP_SHA1  : return SHA_DIGEST_LENGTH;
      case SRP_SHA224: return SHA224_DIGEST_LENGTH;
      case SRP_SHA256: return SHA256_DIGEST_LENGTH;
      case SRP_SHA384: return SHA384_DIGEST_LENGTH;
      case SRP_SHA512: return SHA512_DIGEST_LENGTH;
      default:
        return -1;
    };
}


static BIGNUM * H_nn( SRP_HashAlgorithm alg, const BIGNUM * n1, const BIGNUM * n2 )
{
    unsigned char   buff[ SHA512_DIGEST_LENGTH ];
    int             len_n1 = BN_num_bytes(n1);
    int             len_n2 = BN_num_bytes(n2);
    int             nbytes = len_n1 + len_n2;
    unsigned char * bin    = (unsigned char *) malloc( nbytes );
    BN_bn2bin(n1, bin);
    BN_bn2bin(n2, bin + len_n1);
    hash( alg, bin, nbytes, buff );
    free(bin);
    return BN_bin2bn(buff, hash_length(alg), NULL);
}

static BIGNUM * H_ns( SRP_HashAlgorithm alg, const BIGNUM * n, const unsigned char * bytes, int len_bytes )
{
    unsigned char   buff[ SHA512_DIGEST_LENGTH ];
    int             len_n  = BN_num_bytes(n);
    int             nbytes = len_n + len_bytes;
    unsigned char * bin    = (unsigned char *) malloc( nbytes );
    BN_bn2bin(n, bin);
    memcpy( bin + len_n, bytes, len_bytes );
    hash( alg, bin, nbytes, buff );
    free(bin);
    return BN_bin2bn(buff, hash_length(alg), NULL);
}
    
static BIGNUM * calculate_x( SRP_HashAlgorithm alg, const BIGNUM * salt, const char * username, const unsigned char * password, int password_len )
{
    unsigned char ucp_hash[SHA512_DIGEST_LENGTH];
    HashCTX       ctx;

    hash_init( alg, &ctx );

    hash_update( alg, &ctx, username, strlen(username) );
    hash_update( alg, &ctx, ":", 1 );
    hash_update( alg, &ctx, password, password_len );
    
    hash_final( alg, &ctx, ucp_hash );
        
    return H_ns( alg, salt, ucp_hash, hash_length(alg) );
}

static void update_hash_n( SRP_HashAlgorithm alg, HashCTX *ctx, const BIGNUM * n )
{
    unsigned long len = BN_num_bytes(n);
    unsigned char * n_bytes = (unsigned char *) malloc( len );
    BN_bn2bin(n, n_bytes);
    hash_update(alg, ctx, n_bytes, len);
    free(n_bytes);
}

static void hash_num( SRP_HashAlgorithm alg, const BIGNUM * n, unsigned char * dest )
{
    int             nbytes = BN_num_bytes(n);
    unsigned char * bin    = (unsigned char *) malloc( nbytes );
    BN_bn2bin(n, bin);
    hash( alg, bin, nbytes, dest );
    free(bin);
}

static void calculate_M( SRP_HashAlgorithm alg, NGConstant *ng, unsigned char * dest, const char * I, const BIGNUM * s,
                         const BIGNUM * A, const BIGNUM * B, const unsigned char * K )
{
    unsigned char H_N[ SHA512_DIGEST_LENGTH ];
    unsigned char H_g[ SHA512_DIGEST_LENGTH ];
    unsigned char H_I[ SHA512_DIGEST_LENGTH ];
    unsigned char H_xor[ SHA512_DIGEST_LENGTH ];
    HashCTX       ctx;
    int           i = 0;
    int           hash_len = hash_length(alg);
        
    hash_num( alg, ng->N, H_N );
    hash_num( alg, ng->g, H_g );
    
    hash(alg, (const unsigned char *)I, strlen(I), H_I);
    
    
    for (i=0; i < hash_len; i++ )
        H_xor[i] = H_N[i] ^ H_g[i];
    
    hash_init( alg, &ctx );
    
    hash_update( alg, &ctx, H_xor, hash_len );
    hash_update( alg, &ctx, H_I,   hash_len );
    update_hash_n( alg, &ctx, s );
    update_hash_n( alg, &ctx, A );
    update_hash_n( alg, &ctx, B );
    hash_update( alg, &ctx, K, hash_len );
    
    hash_final( alg, &ctx, dest );
}

static void calculate_H_AMK( SRP_HashAlgorithm alg, unsigned char *dest, const BIGNUM * A, const unsigned char * M, const unsigned char * K )
{
    HashCTX ctx;
    
    hash_init( alg, &ctx );
    
    update_hash_n( alg, &ctx, A );
    hash_update( alg, &ctx, M, hash_length(alg) );
    hash_update( alg, &ctx, K, hash_length(alg) );
    
    hash_final( alg, &ctx, dest );
}

/* Python module calls random_seed during module initialization */
#define init_random()


/***********************************************************************************************************
 *
 *  Exported Functions
 *
 ***********************************************************************************************************/

void srp_random_seed( const unsigned char * random_data, int data_length )
{
    g_initialized = 1;

    if (random_data)
        RAND_seed( random_data, data_length );
}


void srp_create_salted_verification_key( SRP_HashAlgorithm alg, SRP_NGType ng_type, const char * username,
                                         const unsigned char * password, int len_password,
                                         const unsigned char ** bytes_s, int * len_s, 
                                         const unsigned char ** bytes_v, int * len_v,
                                         const char * n_hex, const char * g_hex )
{
    BIGNUM     * s   = BN_new();
    BIGNUM     * v   = BN_new();
    BIGNUM     * x   = 0;
    BN_CTX     * ctx = BN_CTX_new();
    NGConstant * ng  = new_ng( ng_type, n_hex, g_hex );

    init_random(); /* Only happens once */
    
    BN_rand(s, 32, -1, 0);
    
    x = calculate_x( alg, s, username, password, len_password );

    BN_mod_exp(v, ng->g, x, ng->N, ctx);
        
    *len_s   = BN_num_bytes(s);
    *len_v   = BN_num_bytes(v);
    
    *bytes_s = (const unsigned char *) malloc( *len_s );
    *bytes_v = (const unsigned char *) malloc( *len_v );
    
    BN_bn2bin(s, (unsigned char *) *bytes_s);
    BN_bn2bin(v, (unsigned char *) *bytes_v);
        
    delete_ng( ng );
    BN_free(s);
    BN_free(v);
    BN_free(x);
    BN_CTX_free(ctx);
}



/* Out: bytes_B, len_B.
 * 
 * On failure, bytes_B will be set to NULL and len_B will be set to 0
 */
struct SRPVerifier *  srp_verifier_new( SRP_HashAlgorithm alg, SRP_NGType ng_type, const char * username,
                                        const unsigned char * bytes_s, int len_s, 
                                        const unsigned char * bytes_v, int len_v,
                                        const unsigned char * bytes_A, int len_A,
                                        const unsigned char ** bytes_B, int * len_B,
                                        const char * n_hex, const char * g_hex )
{
    BIGNUM     *s    = BN_bin2bn(bytes_s, len_s, NULL);
    BIGNUM     *v    = BN_bin2bn(bytes_v, len_v, NULL);
    BIGNUM     *A    = BN_bin2bn(bytes_A, len_A, NULL);
    BIGNUM     *u    = 0;
    BIGNUM     *B    = BN_new();
    BIGNUM     *S    = BN_new();
    BIGNUM     *b    = BN_new();
    BIGNUM     *k    = 0;
    BIGNUM     *tmp1 = BN_new();
    BIGNUM     *tmp2 = BN_new();
    BN_CTX     *ctx  = BN_CTX_new();
    int         ulen = strlen(username) + 1;
    NGConstant *ng   = new_ng( ng_type, n_hex, g_hex );
    
    struct SRPVerifier * ver = (struct SRPVerifier *) malloc( sizeof(struct SRPVerifier) );

    init_random(); /* Only happens once */
    
    ver->username = (char *) malloc( ulen );
    ver->hash_alg = alg;
    ver->ng       = ng;
    
    memcpy( (char*)ver->username, username, ulen );
    
    ver->authenticated = 0;
        
    /* SRP-6a safety check */
    BN_mod(tmp1, A, ng->N, ctx);
    if ( !BN_is_zero(tmp1) )
    {        
        BN_rand(b, 256, -1, 0);
        
        k = H_nn(alg, ng->N, ng->g);
        
        /* B = kv + g^b */
        BN_mul(tmp1, k, v, ctx);
        BN_mod_exp(tmp2, ng->g, b, ng->N, ctx);
        BN_add(B, tmp1, tmp2);
        
        u = H_nn(alg, A, B);
        
        /* S = (A *(v^u)) ^ b */
        BN_mod_exp(tmp1, v, u, ng->N, ctx);
        BN_mul(tmp2, A, tmp1, ctx);
        BN_mod_exp(S, tmp2, b, ng->N, ctx);

        hash_num(alg, S, ver->session_key);
        
        calculate_M( alg, ng, ver->M, username, s, A, B, ver->session_key );
        calculate_H_AMK( alg, ver->H_AMK, A, ver->M, ver->session_key );
        
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
    if (k) BN_free(k);
    BN_free(B);
    BN_free(S);
    BN_free(b);
    BN_free(tmp1);
    BN_free(tmp2);
    BN_CTX_free(ctx);
    
    return ver;
}

                                        


void srp_verifier_delete( struct SRPVerifier * ver )
{
    delete_ng( ver->ng );
    free( (char *) ver->username );
    free( (unsigned char *) ver->bytes_B );
    free( ver );
}



int srp_verifier_is_authenticated( struct SRPVerifier * ver )
{
    return ver->authenticated;
}


const char * srp_verifier_get_username( struct SRPVerifier * ver )
{
    return ver->username;
}


const unsigned char * srp_verifier_get_session_key( struct SRPVerifier * ver, int * key_length )
{
    if (key_length)
        *key_length = hash_length( ver->hash_alg );
    return ver->session_key;
}


int                   srp_verifier_get_session_key_length( struct SRPVerifier * ver )
{
    return hash_length( ver->hash_alg );
}


/* user_M must be exactly SHA512_DIGEST_LENGTH bytes in size */
void srp_verifier_verify_session( struct SRPVerifier * ver, const unsigned char * user_M, const unsigned char ** bytes_HAMK )
{
    if ( memcmp( ver->M, user_M, hash_length(ver->hash_alg) ) == 0 )
    {
        ver->authenticated = 1;
        *bytes_HAMK = ver->H_AMK;
    }
    else
        *bytes_HAMK = NULL;
}

/*******************************************************************************/

struct SRPUser * srp_user_new( SRP_HashAlgorithm alg, SRP_NGType ng_type, const char * username, 
                               const unsigned char * bytes_password, int len_password,
                               const char * n_hex, const char * g_hex )
{
    struct SRPUser  *usr  = (struct SRPUser *) malloc( sizeof(struct SRPUser) );
    int              ulen = strlen(username) + 1;

    init_random(); /* Only happens once */
    
    usr->hash_alg = alg;
    usr->ng       = new_ng( ng_type, n_hex, g_hex );
    
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



void srp_user_delete( struct SRPUser * usr )
{
    BN_free( usr->a );
    BN_free( usr->A );
    BN_free( usr->S );
    
    delete_ng( usr->ng );
    
    free((char *)usr->username);
    free((char *)usr->password);
    
    if (usr->bytes_A) 
        free( (char *)usr->bytes_A );
    
    free( usr );
}



int srp_user_is_authenticated( struct SRPUser * usr)
{
    return usr->authenticated;
}


const char * srp_user_get_username( struct SRPUser * usr )
{
    return usr->username;
}



const unsigned char * srp_user_get_session_key( struct SRPUser * usr, int * key_length )
{
    if (key_length)
        *key_length = hash_length( usr->hash_alg );
    return usr->session_key;
}


int                   srp_user_get_session_key_length( struct SRPUser * usr )
{
    return hash_length( usr->hash_alg );
}



/* Output: username, bytes_A, len_A */
void  srp_user_start_authentication( struct SRPUser * usr, const char ** username, 
                                     const unsigned char ** bytes_A, int * len_A )
{
    BN_CTX  *ctx  = BN_CTX_new();
    
    BN_rand(usr->a, 256, -1, 0);
        
    BN_mod_exp(usr->A, usr->ng->g, usr->a, usr->ng->N, ctx);
        
    BN_CTX_free(ctx);
    
    *len_A   = BN_num_bytes(usr->A);
    *bytes_A = malloc( *len_A );
        
    BN_bn2bin( usr->A, (unsigned char *) *bytes_A );
    
    usr->bytes_A = *bytes_A;
    *username = usr->username;
}


/* Output: bytes_M. Buffer length is SHA512_DIGEST_LENGTH */
void  srp_user_process_challenge( struct SRPUser * usr, 
                                  const unsigned char * bytes_s, int len_s, 
                                  const unsigned char * bytes_B, int len_B,
                                  const unsigned char ** bytes_M, int * len_M )
{
    BIGNUM *s    = BN_bin2bn(bytes_s, len_s, NULL);
    BIGNUM *B    = BN_bin2bn(bytes_B, len_B, NULL);
    BIGNUM *u    = 0;
    BIGNUM *x    = 0;
    BIGNUM *k    = 0;
    BIGNUM *v    = BN_new();
    BIGNUM *tmp1 = BN_new();
    BIGNUM *tmp2 = BN_new();
    BIGNUM *tmp3 = BN_new();
    BN_CTX *ctx  = BN_CTX_new();
    
    u = H_nn(usr->hash_alg, usr->A, B);
    
    x = calculate_x( usr->hash_alg, s, usr->username, usr->password, usr->password_len );
    
    k = H_nn(usr->hash_alg, usr->ng->N, usr->ng->g);
    
    /* SRP-6a safety check */
    if ( !BN_is_zero(B) && !BN_is_zero(u) )
    {
        BN_mod_exp(v, usr->ng->g, x, usr->ng->N, ctx);
        
        /* S = (B - k*(g^x)) ^ (a + ux) */
        BN_mul(tmp1, u, x, ctx);
        BN_add(tmp2, usr->a, tmp1);             /* tmp2 = (a + ux)      */
        BN_mod_exp(tmp1, usr->ng->g, x, usr->ng->N, ctx);
        BN_mul(tmp3, k, tmp1, ctx);             /* tmp3 = k*(g^x)       */
        BN_sub(tmp1, B, tmp3);                  /* tmp1 = (B - K*(g^x)) */
        BN_mod_exp(usr->S, tmp1, tmp2, usr->ng->N, ctx);

        hash_num(usr->hash_alg, usr->S, usr->session_key);
        
        calculate_M( usr->hash_alg, usr->ng, usr->M, usr->username, s, usr->A, B, usr->session_key );
        calculate_H_AMK( usr->hash_alg, usr->H_AMK, usr->A, usr->M, usr->session_key );
        
        *bytes_M = usr->M;
        if (len_M)
            *len_M = hash_length( usr->hash_alg );
    }
    else
    {
        *bytes_M = NULL;
        if (len_M) 
            *len_M   = 0;
    }
    
    BN_free(s);
    BN_free(B);
    BN_free(u);
    BN_free(x);
    BN_free(k);
    BN_free(v);
    BN_free(tmp1);
    BN_free(tmp2);
    BN_free(tmp3);
    BN_CTX_free(ctx);
}
                                                  

void srp_user_verify_session( struct SRPUser * usr, const unsigned char * bytes_HAMK )
{
    if ( memcmp( usr->H_AMK, bytes_HAMK, hash_length(usr->hash_alg) ) == 0 )
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
    int                  hash_alg       = SRP_SHA1;
    int                  ng_type        = SRP_NG_2048;
    const char          *n_hex          = 0;
    const char          *g_hex          = 0;
    static char * kwnames[] = { "username", "bytes_s", "bytes_v", "bytes_A", 
                                "hash_alg", "ng_type",
                                "n_hex", "g_hex", NULL };
        
    if ( self->ver != NULL )
    {
        PyErr_SetString(PyExc_TypeError, "Type cannot be re-initialized");
        return -1;
    }
    
    if ( ! PyArg_ParseTupleAndKeywords(args, kwds, "st#t#t#|iiss", kwnames,
                            &username, 
                            &bytes_s, &len_s,
                            &bytes_v, &len_v,
                            &bytes_A, &len_A,
                            &hash_alg,
                            &ng_type,
                            &n_hex,
                            &g_hex ) )
    {
        return -1;
    }
    
    if ( hash_alg < SRP_SHA1 || hash_alg > SRP_SHA512 )
    {
        PyErr_SetString(PyExc_ValueError, "Invalid Hash Algorithm");
        return -1;
    }
    
    if ( ng_type < SRP_NG_1024 || ng_type > SRP_NG_CUSTOM )
    {
        PyErr_SetString(PyExc_ValueError, "Invalid Prime Number Constant");
        return -1;
    }
    
    if ( ng_type == SRP_NG_CUSTOM && ( !n_hex || !g_hex ) )
    {
        PyErr_SetString(PyExc_ValueError, "Both n_hex and g_hex are required when ng_type = NG_CUSTOM");
        return -1;
    }
    
    /* The srp_verifier_new command is computationally intensive. Allowing multiple,
     *  simultaneous calls here will speed things up for multi-cpu machines
     */
    Py_BEGIN_ALLOW_THREADS
        self->ver = srp_verifier_new( (SRP_HashAlgorithm) hash_alg, 
                                      (SRP_NGType) ng_type,
                                      username,
                                      bytes_s, len_s, 
                                      bytes_v, len_v, 
                                      bytes_A, len_A,
                                      &self->bytes_B, &self->len_B,
                                      n_hex,
                                      g_hex );
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
    const char          *username       = 0;
    const unsigned char *bytes_password = 0;
    int                  len_password   = 0;
    int                  hash_alg       = SRP_SHA1;
    int                  ng_type        = SRP_NG_2048;
    const char          *n_hex          = 0;
    const char          *g_hex          = 0;
    static char * kwnames[] = { "username", "password", "hash_alg", 
                                "ng_type", "n_hex", "g_hex", NULL };
    
        
    if ( self->usr != NULL )
    {
        PyErr_SetString(PyExc_TypeError, "Type cannot be re-initialized");
        return -1;
    }
    
    if ( ! PyArg_ParseTupleAndKeywords(args, kwds, "st#|iiss", kwnames,
                                       &username, 
                                       &bytes_password, 
                                       &len_password,
                                       &hash_alg,
                                       &ng_type,
                                       &n_hex,
                                       &g_hex) )
    {
        return -1;
    }
    
    if ( hash_alg < SRP_SHA1 || hash_alg > SRP_SHA512 )
    {
        PyErr_SetString(PyExc_ValueError, "Invalid Hash Algorithm");
        return -1;
    }
    
    if ( ng_type < SRP_NG_1024 || ng_type > SRP_NG_CUSTOM )
    {
        PyErr_SetString(PyExc_ValueError, "Invalid Prime Number Constant");
        return -1;
    }
    
    if ( ng_type == SRP_NG_CUSTOM && ( !n_hex || !g_hex ) )
    {
        PyErr_SetString(PyExc_ValueError, "Both n_hex and g_hex are required when ng_type = NG_CUSTOM");
        return -1;
    }
    
    
    self->usr = srp_user_new( (SRP_HashAlgorithm) hash_alg, 
                              (SRP_NGType) ng_type,
                              username, 
                              bytes_password, 
                              len_password,
                              n_hex,
                              g_hex );
        
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
        int          key_len;
        const char * u = (const char *)srp_verifier_get_session_key(self->ver, &key_len);
        return PyString_FromStringAndSize(u, key_len);
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
        int          key_len;
        const char * u = (const char *) srp_user_get_session_key(self->usr, &key_len);
        return PyString_FromStringAndSize(u, key_len);
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
    
    if ( len_M != srp_verifier_get_session_key_length( self->ver ) )
        Py_RETURN_NONE;
    
    srp_verifier_verify_session( self->ver, bytes_M, &bytes_HAMK );
    
    if ( bytes_HAMK == NULL )
        Py_RETURN_NONE;
    else
        return PyString_FromStringAndSize((const char *) bytes_HAMK, 
                                          srp_verifier_get_session_key_length( self->ver ));
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
    int                   len_s, len_B, len_M;
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
    
    /* The srp_user_process_challenge command is computationally intensive.
     * Allowing multiple, simultaneous calls here will speed things up on
     * multi-cpu machines.
     */
    Py_BEGIN_ALLOW_THREADS
    srp_user_process_challenge( self->usr, bytes_s, len_s, bytes_B, len_B, 
                                &bytes_M, &len_M );
    Py_END_ALLOW_THREADS
    
    if (bytes_M == NULL)
        Py_RETURN_NONE;
    else        
        return PyString_FromStringAndSize((const char *) bytes_M, len_M);
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
    
    if ( len_HAMK == srp_user_get_session_key_length( self->usr ) )
        srp_user_verify_session( self->usr, bytes_HAMK );
    
    Py_RETURN_NONE;
}


static PyObject * py_create_salted_verification_key( PyObject *self, PyObject *args, PyObject *kwds )
{
    PyObject            *ret;
    const char          *username;
    const unsigned char *bytes_password, *bytes_s, *bytes_v;
    int                  len_password, len_s, len_v;
    int                  hash_alg       = SRP_SHA1;
    int                  ng_type        = SRP_NG_2048;
    const char          *n_hex          = 0;
    const char          *g_hex          = 0;
    static char * kwnames[] = { "username", "password", "hash_alg", 
                                "ng_type", "n_hex", "g_hex", NULL };
        
    if ( ! PyArg_ParseTupleAndKeywords(args, kwds, "st#|iiss", kwnames,
                                       &username, 
                                       &bytes_password, 
                                       &len_password,
                                       &hash_alg,
                                       &ng_type,
                                       &n_hex,
                                       &g_hex) )
        return NULL;
    
    
    if ( hash_alg < SRP_SHA1 || hash_alg > SRP_SHA512 )
    {
        PyErr_SetString(PyExc_ValueError, "Invalid Hash Algorithm");
        return NULL;
    }
    
    if ( ng_type < SRP_NG_1024 || ng_type > SRP_NG_CUSTOM )
    {
        PyErr_SetString(PyExc_ValueError, "Invalid Prime Number Constant");
        return NULL;
    }
    
    if ( ng_type == SRP_NG_CUSTOM && ( !n_hex || !g_hex ) )
    {
        PyErr_SetString(PyExc_ValueError, "Both n_hex and g_hex are required when ng_type = NG_CUSTOM");
        return NULL;
    }

    srp_create_salted_verification_key( (SRP_HashAlgorithm) hash_alg, 
                                        (SRP_NGType) ng_type,
                                        username, bytes_password, len_password, &bytes_s, &len_s, 
                                        &bytes_v, &len_v,
                                        n_hex,
                                        g_hex );
    
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
    {"create_salted_verification_key", (PyCFunction) py_create_salted_verification_key, METH_VARARGS | METH_KEYWORDS,
            PyDoc_STR("Returns (s,v): Generates a salt & verifier for the "
                      "given username and password")
    },
    {NULL} /* Sentinel */
};


static PyTypeObject PyVerifier_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "srp._srp.Verifier",        /*tp_name*/
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
    "srp._srp.User",            /*tp_name*/
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
                    srp_random_seed( (const unsigned char *)buff, slen );
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
    
            
    if (PyType_Ready(&PyVerifier_Type) < 0 || PyType_Ready(&PyUser_Type) < 0)
        return;
        
    m = Py_InitModule3("srp._srp", srp_module_methods,"SRP-6a implementation");
        
    if (m == NULL)
        return;
    
    Py_INCREF(&PyVerifier_Type);
    Py_INCREF(&PyUser_Type);
    
    PyModule_AddObject(m, "Verifier", (PyObject*) &PyVerifier_Type );
    PyModule_AddObject(m, "User", (PyObject*) &PyUser_Type );
    
    PyModule_AddIntConstant(m, "NG_1024",   SRP_NG_1024);
    PyModule_AddIntConstant(m, "NG_2048",   SRP_NG_2048);
    PyModule_AddIntConstant(m, "NG_4096",   SRP_NG_4096);
    PyModule_AddIntConstant(m, "NG_8192",   SRP_NG_8192);
    PyModule_AddIntConstant(m, "NG_CUSTOM", SRP_NG_CUSTOM);


    PyModule_AddIntConstant(m, "SHA1",   SRP_SHA1);
    PyModule_AddIntConstant(m, "SHA224", SRP_SHA224);
    PyModule_AddIntConstant(m, "SHA256", SRP_SHA256);
    PyModule_AddIntConstant(m, "SHA384", SRP_SHA384);
    PyModule_AddIntConstant(m, "SHA512", SRP_SHA512);

}
