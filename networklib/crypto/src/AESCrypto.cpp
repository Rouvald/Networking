#include <AESCrypto.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>

AES_Crypto::AES_Crypto(const std::vector<uint8_t>& key_) : key(key_)
{
    if (key.size() != 32)
    {
        std::cerr << "AES key must be 256 bits (32 bytes)" << std::endl;
        abort();
    }
}

std::vector<uint8_t> AES_Crypto::generate_iv()
{
    std::vector<uint8_t> iv(12);
    RAND_bytes(iv.data(), iv.size());
    return iv;
}

std::vector<uint8_t> AES_Crypto::encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv, std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> ciphertext(plaintext.size());
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    tag.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<uint8_t> AES_Crypto::decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);

    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data());

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0)
    {
        std::cerr << "Decryption failed: tag mismatch" << std::endl;
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}