#include <boost/asio.hpp>
#include "TLSClient.h"
#include <iostream>

int main(int32_t argc, char* argv[])
{
    if (argc != 2)
    {
        throw std::runtime_error("Input args != 2");
    }
    const std::string ipAddr{argv[1]};
    try
    {
        boost::asio::io_context io_context;
        TLSClient client(io_context, ipAddr.c_str(), 52488);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}