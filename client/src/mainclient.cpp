#include "network/handshakemanager.h"
#include "network/tlsrecordlayer.h"
#include "utils/types.h"
#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <cstdint>
#include <exception>
#include <iostream>
#include <string>

int32_t mainThread(int32_t argc, char* argv[])
{
    std::string ipAddr{"127.0.0.1"};
    if (argc < 2)
    {
        std::cout << "argc != 2 -> Using local ip 127.0.0.1" << '\n';
    }
    else
    {
        ipAddr = argv[1];
    }
    try
    {
        std::cout << "Start client" << '\n';
        boost::asio::io_context ioContext;

        btcp::resolver resolver(ioContext);
        btcp::socket socket(ioContext);
        boost::asio::connect(socket, resolver.resolve(ipAddr, "52488"));

        TLSRecordLayer record(std::vector<uint8_t>(32, 0), std::vector<uint8_t>(12, 0));
        HandshakeManager mgr(socket, record);
        mgr.doClientHandshake();

        std::cout << "Client handshake complete." << '\n';
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
