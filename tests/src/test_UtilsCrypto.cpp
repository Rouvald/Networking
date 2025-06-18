#include "UtilsCrypto.h"
#include <gtest/gtest.h>
#include <vector>

// @note: Test sha256 on empty input yields known SHA256 of empty string
TEST(UtilsCryptoTest, Sha256EmptyInput)
{
    std::vector<uint8_t> empty;
    auto hash = UtilsCrypto::sha256(empty);
    EXPECT_EQ(hash.size(), UtilsCrypto::SHA256_KEY_SIZE);
    const std::vector<uint8_t> expected = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    EXPECT_EQ(hash, expected);
}

// @note: Test sha256 on known data "abc"
TEST(UtilsCryptoTest, Sha256KnownInput)
{
    std::vector<uint8_t> data = {'a', 'b', 'c'};
    auto hash = UtilsCrypto::sha256(data);
    const std::vector<uint8_t> expected = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    EXPECT_EQ(hash, expected);
}

// @note: Test hmac_sha256 size, determinism, and change on key/data
TEST(UtilsCryptoTest, HmacSha256BasicProperties)
{
    std::vector<uint8_t> key = {0x01, 0x02, 0x03};
    std::vector<uint8_t> data = {0x0a, 0x0b, 0x0c};
    auto mac1 = UtilsCrypto::hmac_sha256(key, data);
    auto mac2 = UtilsCrypto::hmac_sha256(key, data);
    EXPECT_EQ(mac1.size(), UtilsCrypto::SHA256_KEY_SIZE);
    EXPECT_EQ(mac1, mac2);

    // Changing key alters result
    std::vector<uint8_t> key2 = {0x04, 0x05, 0x06};
    auto macKey2 = UtilsCrypto::hmac_sha256(key2, data);
    EXPECT_NE(mac1, macKey2);

    // Changing data alters result
    std::vector<uint8_t> data2 = {0x0d};
    auto macData2 = UtilsCrypto::hmac_sha256(key, data2);
    EXPECT_NE(mac1, macData2);
}

// @note: Test d2i_PUBKEY_from_vector returns nullptr for empty or invalid input
TEST(UtilsCryptoTest, D2iPubkeyFromVectorInvalidInput)
{
    const std::vector<uint8_t> empty;
    EVP_PKEY* evp_pkey1 = UtilsCrypto::d2i_PUBKEY_from_vector(empty);
    EXPECT_EQ(evp_pkey1, nullptr);

    std::vector<uint8_t> invalid = {0x00, 0x01, 0x02};
    EVP_PKEY* evp_pkey2 = UtilsCrypto::d2i_PUBKEY_from_vector(invalid);
    EXPECT_EQ(evp_pkey2, nullptr);
}