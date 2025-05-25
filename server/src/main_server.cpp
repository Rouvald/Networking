#include "TLSServer.h"
#include <cstdint>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>

int main(int32_t argc, char* argv[])
{
    if (argc != 2)
    {
        throw std::runtime_error("Input args != 2");
    }
    const std::string ipAddr{argv[1]};
    try
    {
        std::cout << "Start server" << '\n';
        boost::asio::io_context io_context;
        boost::asio::ip::address const bind_ip = boost::asio::ip::make_address(ipAddr.c_str());
        TLSServer const server(io_context, btcp::endpoint(bind_ip, 52488));
        io_context.run();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Server error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
