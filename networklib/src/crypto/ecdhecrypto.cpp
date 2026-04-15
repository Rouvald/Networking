#include "crypto/ecdhecrypto.h"
#include <cstdlib>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

ECDHECrypto::ECDHECrypto()
{
    generateKey();
}

ECDHECrypto::ECDHECrypto(ECDHECrypto&& other) noexcept : _key(other._key)
{
    other._key = nullptr;
}

ECDHECrypto& ECDHECrypto::operator=(ECDHECrypto&& other) noexcept
{
    if (this != &other)
    {
        EVP_PKEY_free(_key);
        _key = other._key;
        other._key = nullptr;
    }
    return *this;
}

ECDHECrypto::~ECDHECrypto()
{
    if (_key != nullptr)
    {
        EVP_PKEY_free(_key);
    }
}

EVP_PKEY* ECDHECrypto::getKey() const
{
    return _key;
}

std::vector<uint8_t> ECDHECrypto::getPublicKeyDer() const
{
    const int32_t len{i2d_PUBKEY(_key, nullptr)};
    std::vector<uint8_t> out(len);
    uint8_t* tmp{out.data()};
    i2d_PUBKEY(_key, &tmp);
    return out;
}

std::vector<uint8_t> ECDHECrypto::computeSharedSecret(EVP_PKEY* peerKey) const
{
    if (peerKey == nullptr)
    {
        return {};
    }
    EVP_PKEY_CTX* ctx{EVP_PKEY_CTX_new(_key, nullptr)};
    if (ctx == nullptr)
    {
        handleErrors();
    }
    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peerKey) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
    }
    size_t secret_len{0};
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
    }
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        handleErrors();
    }
    EVP_PKEY_CTX_free(ctx);
    secret.resize(secret_len);
    return secret;
}

void ECDHECrypto::generateKey()
{
    EVP_PKEY_CTX* pctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    if (pctx == nullptr)
    {
        handleErrors();
    }

    EVP_PKEY* params{nullptr};
    if (EVP_PKEY_paramgen_init(pctx) <= 0 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_paramgen(pctx, &params) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        handleErrors();
    }

    EVP_PKEY_CTX* kctx{EVP_PKEY_CTX_new(params, nullptr)};
    if (kctx == nullptr)
    {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(params);
        handleErrors();
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &_key) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(kctx);
        handleErrors();
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
}

void ECDHECrypto::handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
