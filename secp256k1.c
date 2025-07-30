/**
 * Filename: secp256k1_php.c
 *
 * PHP Extension: secp256k1_php (v1.0.0)
 *
 * Provides three functions for Ethereum‑style ECDSA over secp256k1:
 *   - string secp256k1_sign(string $msg_hash_hex, string $priv_key_hex)
 *   - bool   secp256k1_verify(string $msg_hash_hex, string $sig_hex, string $pub_key_hex)
 *   - string secp256k1_recover(string $msg_hash_hex, string $sig_hex)
 *
 * Hardening features:
 *   • Thread safety via pthread mutex (ZTS‐compatible)
 *   • Context randomization using OpenSSL’s RAND_bytes()
 *   • Zeroing of all sensitive buffers (private keys, hashes)
 *   • Strict hex‐input validation and bounded buffers
 *
 * Dependencies:
 *   • libsecp256k1 (https://github.com/bitcoin-core/secp256k1)
 *   • OpenSSL (for secure RNG)
 *
 * @author  RandomCoderTinker
 * @version 1.0.0
 * @license MIT
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <php.h>
#include <zend_exceptions.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <string.h>

#define PHP_SECP256K1_VERSION "1.0.0"

static secp256k1_context *secp_ctx = NULL;
static pthread_mutex_t secp_mutex = PTHREAD_MUTEX_INITIALIZER;

static int hexchar_to_int(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex2bin(unsigned char *out, const char *hex, size_t hex_len) {
    if (hex_len % 2 != 0) return 0;
    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hexchar_to_int(hex[2 * i]);
        int lo = hexchar_to_int(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static void bytes2hex(char *out, const unsigned char *bin, size_t len) {
    const char *hexmap = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexmap[(bin[i] >> 4) & 0xF];
        out[2 * i + 1] = hexmap[(bin[i] & 0xF)];
    }
    out[2 * len] = '\0';
}

static void secure_zero(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) *p++ = 0;
}

PHP_MINIT_FUNCTION(secp256k1_php)
{
    secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!secp_ctx) {
        zend_error(E_ERROR, "Failed to create secp256k1 context");
        return FAILURE;
    }

    unsigned char seed[32];
    if (!RAND_bytes(seed, sizeof(seed))) {
        php_error_docref(NULL, E_WARNING, "Context randomization failed: RAND_bytes failed");
    } else if (!secp256k1_context_randomize(secp_ctx, seed)) {
        php_error_docref(NULL, E_WARNING, "Context randomization failed");
    }
    secure_zero(seed, sizeof(seed));
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(secp256k1_php)
{
    if (secp_ctx) {
        secp256k1_context_destroy(secp_ctx);
        secp_ctx = NULL;
    }
    pthread_mutex_destroy(&secp_mutex);
    return SUCCESS;
}

PHP_FUNCTION(secp256k1_sign)
{
    char *msg_hash_hex, *priv_hex;
    size_t msg_len, priv_len;
    unsigned char msg_hash[32], privkey[32], sig64[64];
    secp256k1_ecdsa_recoverable_signature recsig;
    int recid;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &msg_hash_hex, &msg_len, &priv_hex, &priv_len) == FAILURE) {
        RETURN_FALSE;
    }

    if (msg_len != 64 || priv_len != 64 ||
        !hex2bin(msg_hash, msg_hash_hex, msg_len) ||
        !hex2bin(privkey, priv_hex, priv_len)) {
        zend_throw_exception(zend_exception_get_default(), "Invalid hex input length", 0);
        RETURN_FALSE;
    }

    pthread_mutex_lock(&secp_mutex);
    int result = secp256k1_ecdsa_sign_recoverable(secp_ctx, &recsig, msg_hash, privkey, NULL, NULL);
    pthread_mutex_unlock(&secp_mutex);

    if (!result) {
        secure_zero(privkey, sizeof(privkey));
        RETURN_FALSE;
    }

    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp_ctx, sig64, &recid, &recsig);
    char out[131];
    bytes2hex(out, sig64, 64);
    const char *hexmap = "0123456789abcdef";
    out[128] = hexmap[(recid + 27) >> 4];
    out[129] = hexmap[(recid + 27) & 0xF];
    out[130] = '\0';

    secure_zero(privkey, sizeof(privkey));
    secure_zero(msg_hash, sizeof(msg_hash));
    RETVAL_STRINGL(out, 130);
}

PHP_FUNCTION(secp256k1_verify)
{
    char *msg_hash_hex, *sig_hex, *pubkey_hex;
    size_t msg_len, sig_len, pub_len;
    unsigned char msg_hash[32], sig64[64];
    int recid;
    secp256k1_ecdsa_recoverable_signature recsig;
    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubkey;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &msg_hash_hex, &msg_len, &sig_hex, &sig_len, &pubkey_hex, &pub_len) == FAILURE) {
        RETURN_FALSE;
    }

    if (msg_len != 64 || sig_len != 130 ||
        !hex2bin(msg_hash, msg_hash_hex, msg_len) ||
        !hex2bin(sig64, sig_hex, 128)) {
        RETURN_FALSE;
    }

    int v = strtol(&sig_hex[128], NULL, 16);
    if (v < 27 || v > 30) RETURN_FALSE;
    recid = v - 27;

    pthread_mutex_lock(&secp_mutex);
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp_ctx, &recsig, sig64, recid)) {
        pthread_mutex_unlock(&secp_mutex);
        RETURN_FALSE;
    }
    secp256k1_ecdsa_recoverable_signature_convert(secp_ctx, &sig, &recsig);

    unsigned char pubbin[65];
    size_t pubbin_len = pub_len / 2;
    if (!(pub_len == 130 || pub_len == 66) ||
        pubbin_len > sizeof(pubbin) ||
        !hex2bin(pubbin, pubkey_hex, pub_len) ||
        !secp256k1_ec_pubkey_parse(secp_ctx, &pubkey, pubbin, pubbin_len)) {
        pthread_mutex_unlock(&secp_mutex);
        RETURN_FALSE;
    }

    int verified = secp256k1_ecdsa_verify(secp_ctx, &sig, msg_hash, &pubkey);
    pthread_mutex_unlock(&secp_mutex);
    RETURN_BOOL(verified);
}

PHP_FUNCTION(secp256k1_recover)
{
    char *msg_hash_hex, *sig_hex;
    size_t msg_len, sig_len;
    unsigned char msg_hash[32], sig64[64], pubout[65];
    int recid;
    secp256k1_ecdsa_recoverable_signature recsig;
    secp256k1_pubkey pubkey;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &msg_hash_hex, &msg_len, &sig_hex, &sig_len) == FAILURE) {
        RETURN_FALSE;
    }

    if (msg_len != 64 || sig_len != 130 ||
        !hex2bin(msg_hash, msg_hash_hex, msg_len) ||
        !hex2bin(sig64, sig_hex, 128)) {
        RETURN_FALSE;
    }

    int v = strtol(&sig_hex[128], NULL, 16);
    if (v < 27 || v > 30) RETURN_FALSE;
    recid = v - 27;

    pthread_mutex_lock(&secp_mutex);
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp_ctx, &recsig, sig64, recid) ||
        !secp256k1_ecdsa_recover(secp_ctx, &pubkey, &recsig, msg_hash)) {
        pthread_mutex_unlock(&secp_mutex);
        RETURN_FALSE;
    }

    size_t outlen = 65;
    secp256k1_ec_pubkey_serialize(secp_ctx, pubout, &outlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    pthread_mutex_unlock(&secp_mutex);

    char hexout[129];
    bytes2hex(hexout, pubout + 1, 64);
    RETVAL_STRINGL(hexout, 128);
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_sign, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, msg_hash_hex, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, priv_key_hex, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_verify, _IS_BOOL, 0)
    ZEND_ARG_TYPE_INFO(0, msg_hash_hex, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, sig_hex, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, pub_key_hex, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(arginfo_secp256k1_recover, IS_STRING, 1)
    ZEND_ARG_TYPE_INFO(0, msg_hash_hex, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, sig_hex, IS_STRING, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry secp256k1_php_functions[] = {
    PHP_FE(secp256k1_sign, arginfo_secp256k1_sign)
    PHP_FE(secp256k1_verify, arginfo_secp256k1_verify)
    PHP_FE(secp256k1_recover, arginfo_secp256k1_recover)
    PHP_FE_END
};

zend_module_entry secp256k1_php_module_entry = {
    STANDARD_MODULE_HEADER,
    "secp256k1_php",
    secp256k1_php_functions,
    PHP_MINIT(secp256k1_php),
    PHP_MSHUTDOWN(secp256k1_php),
    NULL,
    NULL,
    NULL,
    PHP_SECP256K1_VERSION,
    STANDARD_MODULE_PROPERTIES
};

ZEND_GET_MODULE(secp256k1_php)
