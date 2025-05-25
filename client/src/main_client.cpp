#include "TLSClient.h"
#include <cstdint>
#include <boost/asio/io_context.hpp>
#include <exception>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

int32_t main(int32_t argc, char* argv[])
{
    if (argc != 2)
    {
        throw std::runtime_error("Input args != 2");
    }
    const std::string ipAddr{argv[1]};
    try
    {
        std::cout << "Start client" << '\n';
        boost::asio::io_context io_context;
        TLSClient const client(io_context, ipAddr, 52488);
        (void)client;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Client error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
