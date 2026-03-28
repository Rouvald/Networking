#include "ECDHECrypto.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <vector>

ECDHECrypto::ECDHECrypto()
{
    generate_key();
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

EVP_PKEY* ECDHECrypto::get_key() const
{
    return _key;
}

std::vector<uint8_t> ECDHECrypto::get_public_key_der() const
{
    const int32_t len{i2d_PUBKEY(_key, nullptr)};
    std::vector<uint8_t> out(len);
    uint8_t* tmp{out.data()};
    i2d_PUBKEY(_key, &tmp);
    return out;
}

std::vector<uint8_t> ECDHECrypto::compute_shared_secret(EVP_PKEY* peer_key) const
{
    EVP_PKEY_CTX* ctx{EVP_PKEY_CTX_new(_key, nullptr)};
    if (ctx == nullptr)
    {
        handle_errors();
    }
    if (EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        handle_errors();
    }
    size_t secret_len{0};
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        handle_errors();
    }
    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx, secret.data(), &secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        handle_errors();
    }
    EVP_PKEY_CTX_free(ctx);
    secret.resize(secret_len);
    return secret;
}

void ECDHECrypto::generate_key()
{
    EVP_PKEY_CTX* pctx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr)};
    if (pctx == nullptr)
    {
        handle_errors();
    }

    EVP_PKEY* params{nullptr};
    if (EVP_PKEY_paramgen_init(pctx) <= 0 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_paramgen(pctx, &params) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        handle_errors();
    }

    EVP_PKEY_CTX* kctx{EVP_PKEY_CTX_new(params, nullptr)};
    if (kctx == nullptr)
    {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(params);
        handle_errors();
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_keygen(kctx, &_key) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(params);
        EVP_PKEY_CTX_free(kctx);
        handle_errors();
    }

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
}

void ECDHECrypto::handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
