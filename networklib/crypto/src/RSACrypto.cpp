#include "RSACrypto.h"

#include <cstddef>
#include <cstdint>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <vector>

constexpr uint16_t KEY_SIZE{4096};

RSACrypto::RSACrypto()
{
    generate_key();
}

RSACrypto::~RSACrypto()
{
    if (_key != nullptr)
    {
        EVP_PKEY_free(_key);
    }
}

EVP_PKEY* RSACrypto::get_key() const
{
    return _key;
}

std::vector<uint8_t> RSACrypto::sign(const std::vector<uint8_t>& data)
{
    EVP_MD_CTX* ctx{EVP_MD_CTX_new()};
    if (ctx == nullptr)
    {
        handle_errors();
    }
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, _key) <= 0)
    {
        handle_errors();
    }
    EVP_PKEY_CTX* pkctx{EVP_MD_CTX_pkey_ctx(ctx)};
    if (pkctx == nullptr || EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0)
    {
        handle_errors();
    }
    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0)
    {
        handle_errors();
    }
    size_t sig_len{0};
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0)
    {
        handle_errors();
    }
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0)
    {
        handle_errors();
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
        handle_errors();
    }
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, _key) <= 0)
    {
        handle_errors();
    }

    EVP_PKEY_CTX* pkctx{EVP_MD_CTX_pkey_ctx(ctx)};
    if (pkctx == nullptr || EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0)
    {
        handle_errors();
    }

    if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0)
    {
        handle_errors();
    }

    const int32_t ret{EVP_DigestVerifyFinal(ctx, signature.data(), signature.size())};
    EVP_MD_CTX_free(ctx);
    return ret == 1;
}

void RSACrypto::generate_key()
{
    EVP_PKEY_CTX* ctx{EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr)};
    if (ctx == nullptr)
    {
        handle_errors();
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        handle_errors();
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_SIZE) <= 0)
    {
        handle_errors();
    }
    if (EVP_PKEY_keygen(ctx, &_key) <= 0)
    {
        handle_errors();
    }
    EVP_PKEY_CTX_free(ctx);
}

void RSACrypto::handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
