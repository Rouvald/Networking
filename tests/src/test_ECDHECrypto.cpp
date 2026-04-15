#include "crypto/ecdhecrypto.h"
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <vector>

// @note: Test constructor initializes a valid key
TEST(ECDHECryptoTest, ConstructorGeneratesKey)
{
    ECDHECrypto crypto;
    EXPECT_NE(crypto.getKey(), nullptr);
}

// @note: Test get_public_key_der returns valid DER encoding and is consistent
TEST(ECDHECryptoTest, PublicKeyDerFormatAndConsistency)
{
    ECDHECrypto crypto;
    auto der1 = crypto.getPublicKeyDer();
    auto der2 = crypto.getPublicKeyDer();
    EXPECT_GT(der1.size(), 0);
    EXPECT_EQ(der1, der2);
    EXPECT_EQ(der1[0], 0x30);
}

// @note: Test compute_shared_secret symmetric and non-empty
TEST(ECDHECryptoTest, ComputeSharedSecretSymmetric)
{
    ECDHECrypto alice;
    ECDHECrypto bob;
    EVP_PKEY* aliceKey = alice.getKey();
    EVP_PKEY* bobKey = bob.getKey();

    auto secretAB = alice.computeSharedSecret(bobKey);
    auto secretBA = bob.computeSharedSecret(aliceKey);

    EXPECT_GT(secretAB.size(), 0);
    EXPECT_EQ(secretAB, secretBA);
}

// @note: Test repeated compute_shared_secret yields the same result
TEST(ECDHECryptoTest, RepeatedSharedSecretConsistency)
{
    ECDHECrypto alice;
    ECDHECrypto bob;
    EVP_PKEY* bobKey = bob.getKey();

    auto secret1 = alice.computeSharedSecret(bobKey);
    auto secret2 = alice.computeSharedSecret(bobKey);

    EXPECT_EQ(secret1, secret2);
}

// @note: Test compute_shared_secret with null peer key returns empty vector
TEST(ECDHECryptoTest, ComputeSharedSecretNullPeerKeyReturnsEmpty)
{
    ECDHECrypto crypto;
    auto secret = crypto.computeSharedSecret(nullptr);
    EXPECT_TRUE(secret.empty());
}

TEST(ECDHECryptoTest, MoveConstructorTransfersOwnershipAndKeepsKeyUsable)
{
    ECDHECrypto peer;
    ECDHECrypto original;
    EVP_PKEY* originalKey = original.getKey();
    const auto expectedSecret = original.computeSharedSecret(peer.getKey());

    ECDHECrypto moved(std::move(original));

    EXPECT_EQ(original.getKey(), nullptr);
    EXPECT_EQ(moved.getKey(), originalKey);
    EXPECT_EQ(moved.computeSharedSecret(peer.getKey()), expectedSecret);
}

TEST(ECDHECryptoTest, MoveAssignmentTransfersOwnership)
{
    ECDHECrypto peer;
    ECDHECrypto source;
    ECDHECrypto target;
    EVP_PKEY* sourceKey = source.getKey();
    const auto expectedSecret = source.computeSharedSecret(peer.getKey());

    target = std::move(source);

    EXPECT_EQ(source.getKey(), nullptr);
    EXPECT_EQ(target.getKey(), sourceKey);
    EXPECT_EQ(target.computeSharedSecret(peer.getKey()), expectedSecret);
}
