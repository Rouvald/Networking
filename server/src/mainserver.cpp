#include "network/handshakemanager.h"
#include "network/tlsrecordlayer.h"
#include "utils/types.h"
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <cstdint>
#include <exception>
#include <iostream>

int32_t mainThread()
{
    try
    {
        std::cout << "Start server" << '\n';
        boost::asio::io_context ioContext;
        btcp::acceptor acceptor(ioContext, btcp::endpoint(boost::asio::ip::address_v4::any(), 52488));

        std::cout << "Waiting for client..." << '\n';
        btcp::socket socket(ioContext);
        acceptor.accept(socket);
        std::cout << "Client connected." << '\n';

        TLSRecordLayer record(std::vector<uint8_t>(32, 0), std::vector<uint8_t>(12, 0));
        HandshakeManager mgr(socket, record);
        mgr.doServerHandshake();

        std::cout << "Server handshake complete." << '\n';
    }
    catch (const std::exception& e)
    {
        std::cerr << "Server error: " << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int main()
{
    return mainThread();
}
