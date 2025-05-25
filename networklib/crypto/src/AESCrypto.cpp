#include <AESCrypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>

AES_Crypto::AES_Crypto(const std::vector<uint8_t>& key) : _key(key)
{
    if (_key.size() != AES_KEY_SIZE)
    {
        std::cerr << "AES key must be 256 bits (32 bytes)" << std::endl;
        abort();
    }
}

std::vector<uint8_t> AES_Crypto::generate_iv()
{
    std::vector<uint8_t> ivKey(AES_IV_KEY_SIZE);
    RAND_bytes(ivKey.data(), static_cast<int32_t>(ivKey.size()));
    return ivKey;
}

std::vector<uint8_t> AES_Crypto::encrypt(
    const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ivKey, std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> ciphertext(plaintext.size());
    int32_t len{0};

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int32_t>(ivKey.size()), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, _key.data(), ivKey.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    tag.resize(AES_KEY_SIZE / 2);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_KEY_SIZE / 2, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<uint8_t> AES_Crypto::decrypt(
    const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& ivKey, const std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> plaintext(ciphertext.size());
    int32_t len{0};

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivKey.size(), nullptr);

    EVP_DecryptInit_ex(ctx, nullptr, nullptr, _key.data(), ivKey.data());

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_KEY_SIZE / 2, (void*)(tag.data()));

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
