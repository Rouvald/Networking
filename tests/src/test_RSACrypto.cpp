#include "RSACrypto.h"
#include <gtest/gtest.h>
#include <vector>

// @note: Test constructor initializes a valid key
TEST(RSACryptoTest, ConstructorGeneratesKey)
{
    RSACrypto crypto;
    EXPECT_NE(crypto.get_key(), nullptr);
}

// @note: Test signing produces a non-empty signature and verification succeeds
TEST(RSACryptoTest, SignAndVerifyVariousData)
{
    RSACrypto crypto;
    std::vector<std::vector<uint8_t>> testDatas = {
        {},
        {0x00},
        {0xDE, 0xAD, 0xBE, 0xEF},
        std::vector<uint8_t>(256, 0xAA)
    };
    for (const auto& data : testDatas)
    {
        auto sig = crypto.sign(data);
        EXPECT_GT(sig.size(), 0);
        EXPECT_TRUE(crypto.verify(data, sig));
    }
}

// @note: Test signature is deterministic for the same data
TEST(RSACryptoTest, SignatureDeterministic)
{
    RSACrypto crypto;
    std::vector<uint8_t> data = {0x10, 0x20, 0x30};
    auto sig1 = crypto.sign(data);
    auto sig2 = crypto.sign(data);
    EXPECT_EQ(sig1, sig2);
}

// @note: Test verification fails when data is modified
TEST(RSACryptoTest, VerifyFailsWithModifiedData)
{
    RSACrypto crypto;
    std::vector<uint8_t> data = {0xAB, 0xCD, 0xEF};
    auto sig = crypto.sign(data);
    auto badData = data;
    badData[0] ^= 0xFF;
    EXPECT_FALSE(crypto.verify(badData, sig));
}

// @note: Test verification fails when signature is modified
TEST(RSACryptoTest, VerifyFailsWithModifiedSignature)
{
    RSACrypto crypto;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto sig = crypto.sign(data);
    auto badSig = sig;
    badSig[0] ^= 0xFF;
    EXPECT_FALSE(crypto.verify(data, badSig));
}

// @note: Test verification fails with a different key
TEST(RSACryptoTest, VerifyFailsWithDifferentKey)
{
    RSACrypto signer;
    RSACrypto verifier;
    std::vector<uint8_t> data = {0x11, 0x22, 0x33};
    auto sig = signer.sign(data);
    EXPECT_FALSE(verifier.verify(data, sig));
}
