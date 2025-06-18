#include "Utils.h"
#include <gtest/gtest.h>
#include <chrono>
#include <sstream>
#include <thread>

// @note: Test elapsed_ms increases after a known sleep duration
TEST(UtilsTimerTest, ElapsedMsMonotonic)
{
    Utils::Timer timer;
    timer.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    timer.stop();
    double elapsed = timer.elapsed_ms();
    EXPECT_GE(elapsed, 45.0);
}

// @note: Test elapsed_ms is approximately zero if start and stop are called immediately
TEST(UtilsTimerTest, ElapsedMsNearZero)
{
    Utils::Timer timer;
    timer.start();
    timer.stop();
    double elapsed = timer.elapsed_ms();
    EXPECT_GE(elapsed, 0.0);
    EXPECT_LE(elapsed, 5.0);
}

// @note: Test elapsed_ms returns consistent value on multiple calls after stop
TEST(UtilsTimerTest, ElapsedMsConsistent)
{
    Utils::Timer timer;
    timer.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    timer.stop();
    double first = timer.elapsed_ms();
    double second = timer.elapsed_ms();
    EXPECT_DOUBLE_EQ(first, second);
}

// @note: Test print outputs label and numeric value in milliseconds
TEST(UtilsTimerTest, PrintOutputsCorrectFormat)
{
    Utils::Timer timer;
    timer.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    timer.stop();

    std::ostringstream oss;
    {
        std::streambuf* old_buf = std::cout.rdbuf(oss.rdbuf());
        timer.print("TestTimer");
        std::cout.rdbuf(old_buf);
    }
    std::string output = oss.str();
    EXPECT_NE(output.find("TestTimer:"), std::string::npos);
    EXPECT_NE(output.find("ms"), std::string::npos);
    EXPECT_EQ(output.back(), '\n');
}
