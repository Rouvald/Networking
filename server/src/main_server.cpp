#include "TLSServer.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>

int32_t mainThread(int32_t argc, char* argv[])
{
    if (argc != 2)
    {
        std::cout << "Input args != 1\n";
        return EXIT_FAILURE;
    }
    const std::string ipAddr{argv[1]};
    try
    {
        std::cout << "Start server" << '\n';
        boost::asio::io_context io_context;
        const boost::asio::ip::address bind_ip{boost::asio::ip::make_address(ipAddr.c_str())};
        TLSServer server(io_context, btcp::endpoint(bind_ip, 52488));

        server.start_accept();
        io_context.run();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Server error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int main(int32_t argc, char* argv[])
{
    return mainThread(argc, argv);
}
