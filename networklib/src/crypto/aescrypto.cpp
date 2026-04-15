#include "crypto/aescrypto.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>

AESCrypto::AESCrypto(const std::vector<uint8_t>& key) : _key(key)
{
    if (_key.size() != types::vars::AES_KEY_SIZE)
    {
        std::cerr << "AES key must be 256 bits (32 bytes)" << std::endl;
        abort();
    }
}

std::vector<uint8_t> AESCrypto::generateIv()
{
    std::vector<uint8_t> ivKey(types::vars::AES_IV_KEY_SIZE);
    if (RAND_bytes(ivKey.data(), static_cast<int32_t>(ivKey.size())) != 1)
    {
        handleErrors();
    }
    return ivKey;
}

std::vector<uint8_t> AESCrypto::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ivKey, std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx{EVP_CIPHER_CTX_new()};
    if (ctx == nullptr)
    {
        handleErrors();
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    int32_t len{0};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int32_t>(ivKey.size()), nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, _key.data(), ivKey.data()) <= 0 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int32_t>(plaintext.size())) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }

    int32_t ciphertext_len{len};
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }
    ciphertext_len += len;

    tag.resize(types::vars::GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, types::vars::GCM_TAG_SIZE, tag.data()) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(static_cast<std::vector<uint8_t>::size_type>(ciphertext_len));
    return ciphertext;
}

std::vector<uint8_t> AESCrypto::decrypt(
    const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& ivKey, const std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx{EVP_CIPHER_CTX_new()};
    if (ctx == nullptr)
    {
        handleErrors();
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    int32_t len{0};

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int32_t>(ivKey.size()), nullptr) <= 0 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, _key.data(), ivKey.data()) <= 0 ||
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int32_t>(ciphertext.size())) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }

    int32_t plaintext_len{len};

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, types::vars::GCM_TAG_SIZE, const_cast<uint8_t*>(tag.data())) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors();
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0)
    {
        std::cerr << "Decryption failed: tag mismatch" << '\n';
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(static_cast<std::vector<uint8_t>::size_type>(plaintext_len));
    return plaintext;
}

void AESCrypto::handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
