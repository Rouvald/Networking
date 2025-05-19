#include "ECDHECrypto.h"

#include <openssl/x509.h>

ECDHE_Crypto::ECDHE_Crypto()
{
    generate_key();
}

ECDHE_Crypto::~ECDHE_Crypto()
{
    if (key)
    {
        EVP_PKEY_free(key);
    }
}

EVP_PKEY* ECDHE_Crypto::get_key() const
{
    return key;
}

std::vector<uint8_t> ECDHE_Crypto::get_public_key_der() const
{
    int len = i2d_PUBKEY(key, nullptr);
    std::vector<uint8_t> out(len);
    unsigned char* tmp = out.data();
    i2d_PUBKEY(key, &tmp);
    return out;
}

std::vector<uint8_t> ECDHE_Crypto::compute_shared_secret(EVP_PKEY* peer_key) const
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_key);
    size_t secret_len;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);
    std::vector<uint8_t> secret(secret_len);
    EVP_PKEY_derive(ctx, secret.data(), &secret_len);
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

void ECDHE_Crypto::generate_key()
{
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* params = nullptr;
    EVP_PKEY_CTX* kctx;

    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_paramgen(pctx, &params);

    kctx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &key);

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
}