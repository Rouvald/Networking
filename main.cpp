#include <cstdint>

#include "manager.h"

int32_t main(int32_t argc, char** argv)
{
    (void)argc;
    (void)argv;

    basio::io_context io;
    Manager mng(io.get_executor(), "google.com");
    mng.connect();
    mng.disconnect();
    mng.connect();

    return 0;
}