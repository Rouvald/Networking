#include <AESCrypto.h>
#include <cstdint>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>

AESCrypto::AESCrypto(const std::vector<uint8_t>& key) : _key(key)
{
    if (_key.size() != AES_KEY_SIZE)
    {
        std::cerr << "AES key must be 256 bits (32 bytes)" << '\n';
        abort();
    }
}

std::vector<uint8_t> AESCrypto::generate_iv()
{
    std::vector<uint8_t> ivKey(AES_IV_KEY_SIZE);
    if (RAND_bytes(ivKey.data(), static_cast<int32_t>(ivKey.size())) != 1)
    {
        handle_errors();
    }
    return ivKey;
}

std::vector<uint8_t> AESCrypto::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ivKey, std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx{EVP_CIPHER_CTX_new()};
    if (ctx == nullptr)
    {
        handle_errors();
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    int32_t len{0};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int32_t>(ivKey.size()), nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, _key.data(), ivKey.data()) <= 0 ||
        EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int32_t>(plaintext.size())) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    int32_t ciphertext_len{len};
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }
    ciphertext_len += len;

    tag.resize(GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<uint8_t> AESCrypto::decrypt(
    const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& ivKey, const std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx{EVP_CIPHER_CTX_new()};
    if (ctx == nullptr)
    {
        handle_errors();
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    int32_t len{0};

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int32_t>(ivKey.size()), nullptr) <= 0 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, _key.data(), ivKey.data()) <= 0 ||
        EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int32_t>(ciphertext.size())) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    int32_t plaintext_len{len};

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, const_cast<uint8_t*>(tag.data())) <= 0)
    {
        EVP_CIPHER_CTX_free(ctx);
        handle_errors();
    }

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0)
    {
        std::cerr << "Decryption failed: tag mismatch" << '\n';
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}

void AESCrypto::handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}
