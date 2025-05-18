#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iostream>
#include <vector>
#include <cstring>

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

std::vector<uint8_t> rsa_sign(EVP_PKEY* rsa_key, const std::vector<uint8_t>& msg)
{
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr)
    {
        handleErrors();
    }
    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, rsa_key) <= 0)
    {
        handleErrors();
    }
    EVP_PKEY_CTX* pkctx = EVP_MD_CTX_pkey_ctx(mdctx);
    if (pkctx == nullptr)
    {
        handleErrors();
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PADDING) <= 0)
    {
        handleErrors();
    }
    if (EVP_DigestSignUpdate(mdctx, msg.data(), msg.size()) <= 0)
    {
        handleErrors();
    }
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx, nullptr, &sig_len) <= 0)
    {
        handleErrors();
    }
    std::vector<uint8_t> signature(sig_len);
    if (EVP_DigestSignFinal(mdctx, signature.data(), &sig_len) <= 0)
    {
        handleErrors();
    }
    signature.resize(sig_len);
    EVP_MD_CTX_free(mdctx);
    return signature;
}

bool rsa_verify(EVP_PKEY* rsa_key, const std::vector<uint8_t>& msg, const std::vector<uint8_t>& signature)
{
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, rsa_key) == 0)
    {
        handleErrors();
    }
    if (EVP_DigestVerifyUpdate(mdctx, msg.data(), msg.size()) == 0)
    {
        handleErrors();
    }
    int32_t result = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
    EVP_MD_CTX_free(mdctx);
    return result == 1;
}

EVP_PKEY* generate_ecdh_key()
{
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* params = nullptr;
    EVP_PKEY_CTX* kctx = nullptr;
    EVP_PKEY* key = nullptr;

    EVP_PKEY_paramgen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY_paramgen(pctx, &params);
    kctx = EVP_PKEY_CTX_new(params, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_keygen(kctx, &key);

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(kctx);
    return key;
}

EVP_PKEY* generate_rsa_key()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (ctx == nullptr)
    {
        handleErrors();
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        handleErrors();
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
    {
        handleErrors();
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        handleErrors();
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

std::vector<uint8_t> derive_shared_secret(EVP_PKEY* priv_key, EVP_PKEY* peer_key)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv_key, nullptr);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_key);
    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);
    std::vector<uint8_t> secret(secret_len);
    EVP_PKEY_derive(ctx, secret.data(), &secret_len);
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

std::vector<uint8_t> aes256_gcm_encrypt(
    const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> ciphertext(plaintext.size());
    int32_t len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int32_t ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    tag.resize(16);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::vector<uint8_t> aes256_gcm_decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> plaintext(ciphertext.size());
    int32_t len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    int32_t plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag.data());

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0)
    {
        std::cerr << "Decryption failed: tag mismatch\n";
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plaintext_len);
    return plaintext;
}

int32_t main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_PKEY* rsa_key = generate_rsa_key();
    EVP_PKEY* client_ec_key = generate_ecdh_key();
    EVP_PKEY* server_ec_key = generate_ecdh_key();

    // print test rsa
    BIO* bprint = BIO_new_fp(stdout, BIO_NOCLOSE);
    EVP_PKEY_print_public(bprint, rsa_key, 1, nullptr);
    EVP_PKEY_print_private(bprint, rsa_key, 1, nullptr);

    BIO_free(bprint);

    std::vector<uint8_t> client_pub_bytes;
    int32_t len = i2d_PUBKEY(client_ec_key, nullptr);
    client_pub_bytes.resize(len);
    uint8_t* tmp = client_pub_bytes.data();
    i2d_PUBKEY(client_ec_key, &tmp);
    std::vector<uint8_t> signature = rsa_sign(rsa_key, client_pub_bytes);

    if (!rsa_verify(rsa_key, client_pub_bytes, signature))
    {
        std::cerr << "Signature verification failed!" << '\n';
        return 1;
    }
    std::vector<uint8_t> client_secret = derive_shared_secret(client_ec_key, server_ec_key);
    std::vector<uint8_t> server_secret = derive_shared_secret(server_ec_key, client_ec_key);

    if (client_secret != server_secret)
    {
        std::cerr << "Shared secrets do not match!" << '\n';
        return 1;
    }
    std::string message = "qwertyuiop];lkjhgfdsazxxcvbnmm,,..";
    std::vector<uint8_t> iv(12);
    RAND_bytes(iv.data(), iv.size());
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ciphertext = aes256_gcm_encrypt(std::vector<uint8_t>(message.begin(), message.end()), client_secret, iv, tag);

    std::vector<uint8_t> decrypted = aes256_gcm_decrypt(ciphertext, server_secret, iv, tag);
    std::cout << "Decrypted message: " << std::string(decrypted.begin(), decrypted.end()) << '\n';

    EVP_PKEY_free(rsa_key);
    EVP_PKEY_free(client_ec_key);
    EVP_PKEY_free(server_ec_key);
    return 0;
}
