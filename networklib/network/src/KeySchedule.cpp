#include <KeySchedule.h>
#include <iobytes.h>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

std::vector<uint8_t> HKDF::extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm)
{
    std::vector<uint8_t> real_salt = salt.empty() ? std::vector<uint8_t>(UtilsCrypto::SHA256_KEY_SIZE, 0) : salt;

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr)
    {
        throw std::runtime_error("Failed to fetch HKDF");
    }
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == nullptr)
    {
        throw std::runtime_error("Failed to create HKDF context");
    }
    OSSL_PARAM params[] = {OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, real_salt.data(), real_salt.size()),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm.data()), ikm.size()),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, (char*)"EXTRACT_ONLY", strlen("EXTRACT_ONLY")),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", strlen("SHA256")), OSSL_PARAM_construct_end()};

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0)
    {
        EVP_KDF_CTX_free(kctx);
        throw std::runtime_error("Failed to set HKDF extract parameters");
    }
    std::vector<uint8_t> prk(UtilsCrypto::SHA256_KEY_SIZE);
    if (EVP_KDF_derive(kctx, prk.data(), prk.size(), nullptr) <= 0)
    {
        EVP_KDF_CTX_free(kctx);
        throw std::runtime_error("HKDF extract derivation failed");
    }
    EVP_KDF_CTX_free(kctx);
    return prk;
}

std::vector<uint8_t> HKDF::expand(const std::vector<uint8_t>& prk, const std::vector<uint8_t>& info, size_t L)
{
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr)
    {
        throw std::runtime_error("Failed to fetch HKDF");
    }
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == nullptr)
    {
        throw std::runtime_error("Failed to create HKDF context");
    }
    size_t out_len = L;
    OSSL_PARAM params[] = {OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(prk.data()), prk.size()),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()), info.size()),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, (char*)"EXPAND_ONLY", strlen("EXPAND_ONLY")),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", strlen("SHA256")),
        OSSL_PARAM_construct_size_t(OSSL_KDF_PARAM_SIZE, &out_len), OSSL_PARAM_construct_end()};

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0)
    {
        EVP_KDF_CTX_free(kctx);
        throw std::runtime_error("Failed to set HKDF expand parameters");
    }
    std::vector<uint8_t> okm(L);
    if (EVP_KDF_derive(kctx, okm.data(), okm.size(), nullptr) <= 0)
    {
        EVP_KDF_CTX_free(kctx);
        throw std::runtime_error("HKDF expand derivation failed");
    }
    EVP_KDF_CTX_free(kctx);
    return okm;
}

std::vector<uint8_t> HKDF::expandLabel(
    const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& context, size_t length)
{
    std::string full_label = "tls13 " + label;
    ByteWriter writer;
    writer.write_uint16(static_cast<uint16_t>(length));
    writer.write_uint8(static_cast<uint8_t>(full_label.size()));
    writer.write_bytes(std::vector<uint8_t>(full_label.begin(), full_label.end()));
    writer.write_uint8(static_cast<uint8_t>(context.size()));
    writer.write_bytes(context);
    std::vector<uint8_t> info = writer.get_buffer();
    return expand(secret, info, length);
}