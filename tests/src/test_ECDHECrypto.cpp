#include <gtest/gtest.h>
#include <ECDHECrypto.h>
#include <vector>
#include <cstdint>

TEST(testECDHECrypto, base)
{
    const ECDHECrypto client_ecdh;
    const std::vector<uint8_t> client_pub = client_ecdh.get_public_key_der();
    EXPECT_GE(client_pub.size(), 0);
}
