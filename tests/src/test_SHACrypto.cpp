#include <gtest/gtest.h>
#include <UtilsCrypto.h>
#include <string>
#include <vector>

TEST(testSHACrypto, base)
{
    const std::string testMsgStr{"test message"};
    const std::vector<uint8_t> testMsg{testMsgStr.begin(), testMsgStr.end()};
    EXPECT_EQ(UtilsCrypto::sha256(testMsg).size(), UtilsCrypto::SHA256_KEY_SIZE);
}
