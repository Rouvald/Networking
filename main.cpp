#include <iostream>
#include <cstdint>

#include "manager.h"

int32_t main(int32_t argc, char** argv)
{
    (void)argc;
    (void)argv;

    basio::io_context io;
    Manager mng(io.get_executor(), "google.com");
    mng.connect();

    std::cout << mng.getKey_boost("3") << std::endl;

    mng.disconnect();
    mng.connect();

    std::cout << mng.getKey_boost("3") << std::endl;

    return 0;
}