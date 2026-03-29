#include "crypto/rsacrypto.h"
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

constexpr uint16_t KEY_SIZE{4096};

RSACrypto::RSACrypto()
{
    generateKey();
}

RSACrypto::RSACrypto(RSACrypto&& other) noexcept : _key(other._key)
{
    other._key = nullptr;
}

RSACrypto& RSACrypto::operator=(RSACrypto&& other) noexcept
{
    if (this != &other)
    {
        EVP_PKEY_free(_key);
        _key = other._key;
        other._key = nullptr;
    }
    return *this;
}

RSACrypto::~RSACrypto()
{
    if (_key != nullptr)
    {
        EVP_PKEY_free(_key);
    }
}

EVP_PKEY* RSACrypto::getKey() const
{
    return _key;
}

std::vector<uint8_t> RSACrypto::sign(const std::vector<uint8_t>& data)
{
    EVP_MD_CTX* ctx{EVP_MD_CTX_new()};
    if (ctx == nullptr)
    {
        handleErrors();
    }
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, _key) <= 0)
    {
        handleErrors();
    }
    EVP_PKEY_CTX* pkctx{EVP_MD_CTX_pkey_ctx(ctx)};
    if (pkctx == nullptr || EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0)
    {
        handleErrors();
    }
    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0)
    {
        handleErrors();
    }
    size_t sig_len{0};
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0)
    {
        handleErrors();
    }
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0)
    {
        handleErrors();
    }
    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    return signature;
}

bool RSACrypto::verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature)
{
    EVP_MD_CTX* ctx{EVP_MD_CTX_new()};
    if (ctx == nullptr)
    {
        handleErrors();
    }
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, _key) <= 0)
    {
        handleErrors();
    }

    EVP_PKEY_CTX* pkctx{EVP_MD_CTX_pkey_ctx(ctx)};
    if (pkctx == nullptr || EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0)
    {
        handleErrors();
    }

    if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0)
    {
        handleErrors();
    }

    const int32_t ret{EVP_DigestVerifyFinal(ctx, signature.data(), signature.size())};
    EVP_MD_CTX_free(ctx);
    return ret == 1;
}

void RSACrypto::generateKey()
{
    EVP_PKEY_CTX* ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
    if (ctx == nullptr)
    {
        handleErrors();
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        handleErrors();
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_SIZE) <= 0)
    {
        handleErrors();
    }
    if (EVP_PKEY_keygen(ctx, &_key) <= 0)
    {
        handleErrors();
    }
    EVP_PKEY_CTX_free(ctx);
}

void RSACrypto::handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
