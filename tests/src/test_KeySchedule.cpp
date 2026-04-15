#include "network/keyschedule.h"
#include "utils/types.h"
#include <gtest/gtest.h>
#include <vector>

namespace
{
std::vector<uint8_t> makeBytes(std::initializer_list<uint8_t> bytes)
{
    return std::vector<uint8_t>(bytes);
}
}

TEST(KeyScheduleTest, HKDFExtractHandlesEmptySaltAndInput)
{
    const std::vector<uint8_t> secret1 = HKDF::extract({}, {});
    const std::vector<uint8_t> secret2 = HKDF::extract({}, {});

    EXPECT_EQ(secret1.size(), types::vars::SHA256_KEY_SIZE);
    EXPECT_EQ(secret1, secret2);
}

TEST(KeyScheduleTest, HKDFExpandAndExpandLabelAreDeterministic)
{
    const std::vector<uint8_t> prk = HKDF::extract(makeBytes({0x01, 0x02}), makeBytes({0x03, 0x04}));
    const std::vector<uint8_t> expanded1 = HKDF::expand(prk, makeBytes({0xAA, 0xBB}), 42);
    const std::vector<uint8_t> expanded2 = HKDF::expand(prk, makeBytes({0xAA, 0xBB}), 42);
    const std::vector<uint8_t> labeled = HKDF::expandLabel(prk, "label", makeBytes({0x01}), 16);
    const std::vector<uint8_t> labeledOther = HKDF::expandLabel(prk, "other", makeBytes({0x01}), 16);

    EXPECT_EQ(expanded1.size(), 42u);
    EXPECT_EQ(expanded1, expanded2);
    EXPECT_EQ(labeled.size(), 16u);
    EXPECT_NE(labeled, labeledOther);
}

TEST(KeyScheduleTest, DerivedSecretHelpersReturnExpectedSizes)
{
    const std::vector<uint8_t> psk = makeBytes({0x10, 0x20, 0x30});
    const std::vector<uint8_t> earlySecret = deriveEarlySecret(psk);
    const std::vector<uint8_t> handshakeSecret = deriveHandshakeSecret(earlySecret, makeBytes({0x01, 0x02, 0x03, 0x04}));
    const std::vector<uint8_t> trafficSecretClient = deriveTrafficSecret(handshakeSecret, "c hs traffic", makeBytes({0x09, 0x08}));
    const std::vector<uint8_t> trafficSecretServer = deriveTrafficSecret(handshakeSecret, "s hs traffic", makeBytes({0x09, 0x08}));
    const TrafficKeyMaterial keyMaterial = deriveTrafficKeyMaterial(trafficSecretClient);
    const std::vector<uint8_t> masterSecret = deriveMasterSecret(handshakeSecret);

    EXPECT_EQ(earlySecret.size(), types::vars::SHA256_KEY_SIZE);
    EXPECT_EQ(handshakeSecret.size(), types::vars::SHA256_KEY_SIZE);
    EXPECT_EQ(trafficSecretClient.size(), types::vars::SHA256_KEY_SIZE);
    EXPECT_EQ(trafficSecretServer.size(), types::vars::SHA256_KEY_SIZE);
    EXPECT_NE(trafficSecretClient, trafficSecretServer);
    EXPECT_EQ(keyMaterial.key.size(), types::vars::AES_KEY_SIZE);
    EXPECT_EQ(keyMaterial.iv.size(), types::vars::AES_IV_KEY_SIZE);
    EXPECT_EQ(masterSecret.size(), types::vars::SHA256_KEY_SIZE);
}
