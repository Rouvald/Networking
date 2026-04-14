#include "tlsclient.h"
#include <boost/asio/io_context.hpp>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

int32_t mainThread(int32_t argc, char* argv[])
{
    std::string ipAddr{"127.0.0.1"};
    if (argc < 2)
    {
        // std::cout << "Usage: client <server_ip>\n";
        // return EXIT_FAILURE;
        std::cout << "argc != 2 -> Using local ip 127.0.0.1" << std::endl;
    }
    else
    {
        ipAddr = argv[1];
    }
    try
    {
        std::cout << "Start client" << '\n';
        boost::asio::io_context ioContext;
        TLSClient client(ioContext, ipAddr, 52488);
        client.runHandshakeAndSend();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Client error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int32_t main(int32_t argc, char* argv[])
{
    return mainThread(argc, argv);
}
