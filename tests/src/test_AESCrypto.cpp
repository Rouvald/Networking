#include <gtest/gtest.h>
#include <AESCrypto.h>
#include <vector>
#include <cstdint>

TEST(testAESCrypto, base)
{
    const std::vector<uint8_t> ivKey{AESCrypto::generate_iv()};
    EXPECT_EQ(ivKey.size(), AES_IV_KEY_SIZE);
}
