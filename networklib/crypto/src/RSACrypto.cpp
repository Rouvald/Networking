#include "RSACrypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>

RSA_Crypto::RSA_Crypto()
{
    generate_key();
}

RSA_Crypto::~RSA_Crypto()
{
    if (key)
        EVP_PKEY_free(key);
}

EVP_PKEY* RSA_Crypto::get_key() const
{
    return key;
}

std::vector<uint8_t> RSA_Crypto::sign(const std::vector<uint8_t>& data)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        handle_errors();

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) <= 0)
        handle_errors();

    EVP_PKEY_CTX* pkctx = EVP_MD_CTX_pkey_ctx(ctx);
    if (!pkctx || EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0)
        handle_errors();

    if (EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0)
        handle_errors();

    size_t sig_len = 0;
    if (EVP_DigestSignFinal(ctx, nullptr, &sig_len) <= 0)
        handle_errors();

    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0)
        handle_errors();

    signature.resize(sig_len);
    EVP_MD_CTX_free(ctx);
    return signature;
}

bool RSA_Crypto::verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
        handle_errors();

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) <= 0)
        handle_errors();

    EVP_PKEY_CTX* pkctx = EVP_MD_CTX_pkey_ctx(ctx);
    if (!pkctx || EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0)
        handle_errors();

    if (EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) <= 0)
        handle_errors();

    const int32_t ret = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
    EVP_MD_CTX_free(ctx);
    return ret == 1;
}

void RSA_Crypto::generate_key()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx)
        handle_errors();

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        handle_errors();

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
        handle_errors();

    if (EVP_PKEY_keygen(ctx, &key) <= 0)
        handle_errors();

    EVP_PKEY_CTX_free(ctx);
}

void RSA_Crypto::handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}