#include "AESCrypto.h"
#include <gtest/gtest.h>
#include <algorithm>
#include <vector>

// @note: Helper to generate a valid AES key of 32 bytes
static std::vector<uint8_t> generateValidKey()
{
    return std::vector<uint8_t>(AES_KEY_SIZE, 0x01);
}

// @note: Test constructor accepts valid key size
TEST(AESCryptoTest, ConstructorValidKey)
{
    auto key = generateValidKey();
    EXPECT_NO_THROW({ AESCrypto crypto(key); });
}

// @note: Test constructor aborts on invalid key size (death test)
TEST(AESCryptoTest, ConstructorInvalidKeySize)
{
    std::vector<uint8_t> badKey(16, 0x00);
    EXPECT_DEATH({ AESCrypto crypto(badKey); }, "AES key must be 256 bits");
}

// @note: Test that generate_iv returns correct size and produces different IVs
TEST(AESCryptoTest, GenerateIVSizeAndUniqueness)
{
    const auto iv1 = AESCrypto::generate_iv();
    const auto iv2 = AESCrypto::generate_iv();
    EXPECT_EQ(iv1.size(), AES_IV_KEY_SIZE);
    EXPECT_EQ(iv2.size(), AES_IV_KEY_SIZE);
    EXPECT_NE(iv1, iv2);
}

// @note: Test full encrypt-decrypt roundtrip with various plaintexts
TEST(AESCryptoTest, EncryptDecryptRoundTrip)
{
    AESCrypto crypto(generateValidKey());
    std::vector<std::vector<uint8_t>> testPlaintexts = {
        {},
        {0x00},
        {0x00, 0xFF, 0xAA, 0x55},
        std::vector<uint8_t>(1024, 0x7F)
    };

    for (const auto& plaintext : testPlaintexts)
    {
        auto iv_key = AESCrypto::generate_iv();
        std::vector<uint8_t> tag;
        auto ciphertext = crypto.encrypt(plaintext, iv_key, tag);
        EXPECT_EQ(tag.size(), AES_KEY_SIZE / 2);
        EXPECT_EQ(ciphertext.size(), plaintext.size());
        if (!plaintext.empty())
        {
            EXPECT_NE(ciphertext, plaintext);
        }
        auto decrypted = crypto.decrypt(ciphertext, iv_key, tag);
        EXPECT_EQ(decrypted, plaintext);
    }
}

// @note: Test decrypt fails with wrong tag
TEST(AESCryptoTest, DecryptFailsWithWrongTag)
{
    AESCrypto crypto(generateValidKey());
    std::vector<uint8_t> plaintext = {0x10, 0x20, 0x30};
    auto iv_key = AESCrypto::generate_iv();
    std::vector<uint8_t> tag;
    auto ciphertext = crypto.encrypt(plaintext, iv_key, tag);
    tag[0] ^= 0xFF;
    auto result = crypto.decrypt(ciphertext, iv_key, tag);
    EXPECT_TRUE(result.empty());
}

// @note: Test decrypt fails with wrong IV
TEST(AESCryptoTest, DecryptFailsWithWrongIV)
{
    AESCrypto crypto(generateValidKey());
    std::vector<uint8_t> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
    auto iv_key = AESCrypto::generate_iv();
    std::vector<uint8_t> tag;
    auto ciphertext = crypto.encrypt(plaintext, iv_key, tag);
    auto badIv = iv_key;
    badIv[0] ^= 0x01;
    auto result = crypto.decrypt(ciphertext, badIv, tag);
    EXPECT_TRUE(result.empty());
}

// @note: Test decrypt fails with modified ciphertext
TEST(AESCryptoTest, DecryptFailsWithModifiedCiphertext)
{
    AESCrypto crypto(generateValidKey());
    std::vector<uint8_t> plaintext = {0x11, 0x22, 0x33, 0x44};
    auto iv_key = AESCrypto::generate_iv();
    std::vector<uint8_t> tag;
    auto ciphertext = crypto.encrypt(plaintext, iv_key, tag);
    ciphertext[0] ^= 0xFF;
    auto result = crypto.decrypt(ciphertext, iv_key, tag);
    EXPECT_TRUE(result.empty());
}

// @note: Test that copied and moved instances still work correctly
TEST(AESCryptoTest, CopyAndMoveBehavior)
{
    AESCrypto original(generateValidKey());
    AESCrypto copy = original;
    AESCrypto moved = std::move(original);
    std::vector<uint8_t> plaintext = {0x99, 0x88, 0x77};

    for (AESCrypto& crypto : {std::ref(copy), std::ref(moved)})
    {
        auto iv_key = AESCrypto::generate_iv();
        std::vector<uint8_t> tag;
        auto ciphertext = crypto.encrypt(plaintext, iv_key, tag);
        auto decrypted = crypto.decrypt(ciphertext, iv_key, tag);
        EXPECT_EQ(decrypted, plaintext);
    }
}