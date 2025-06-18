#include "ECDHECrypto.h"
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <vector>

// @note: Test constructor initializes a valid key
TEST(ECDHECryptoTest, ConstructorGeneratesKey)
{
    ECDHECrypto crypto;
    EXPECT_NE(crypto.get_key(), nullptr);
}

// @note: Test get_public_key_der returns valid DER encoding and is consistent
TEST(ECDHECryptoTest, PublicKeyDerFormatAndConsistency)
{
    ECDHECrypto crypto;
    auto der1 = crypto.get_public_key_der();
    auto der2 = crypto.get_public_key_der();
    EXPECT_GT(der1.size(), 0);
    EXPECT_EQ(der1, der2);
    EXPECT_EQ(der1[0], 0x30);
}

// @note: Test compute_shared_secret symmetric and non-empty
TEST(ECDHECryptoTest, ComputeSharedSecretSymmetric)
{
    ECDHECrypto alice;
    ECDHECrypto bob;
    EVP_PKEY* aliceKey = alice.get_key();
    EVP_PKEY* bobKey = bob.get_key();

    auto secretAB = alice.compute_shared_secret(bobKey);
    auto secretBA = bob.compute_shared_secret(aliceKey);

    EXPECT_GT(secretAB.size(), 0);
    EXPECT_EQ(secretAB, secretBA);
}

// @note: Test repeated compute_shared_secret yields the same result
TEST(ECDHECryptoTest, RepeatedSharedSecretConsistency)
{
    ECDHECrypto alice;
    ECDHECrypto bob;
    EVP_PKEY* bobKey = bob.get_key();

    auto secret1 = alice.compute_shared_secret(bobKey);
    auto secret2 = alice.compute_shared_secret(bobKey);

    EXPECT_EQ(secret1, secret2);
}

// @note: Test compute_shared_secret with null peer key returns empty vector
TEST(ECDHECryptoTest, ComputeSharedSecretNullPeerKeyReturnsEmpty)
{
    ECDHECrypto crypto;
    auto secret = crypto.compute_shared_secret(nullptr);
    EXPECT_TRUE(secret.empty());
}