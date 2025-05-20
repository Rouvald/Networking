#include <boost/asio.hpp>
#include "TLSServer.h"
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
        boost::asio::ip::address bind_ip = boost::asio::ip::make_address(ipAddr.c_str());
        TLSServer server(io_context, tcp::endpoint(bind_ip, 52488));
        io_context.run();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}