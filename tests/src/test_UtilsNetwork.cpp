#include "utils/functions.h"
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <vector>

namespace
{
    // @note: Shared ioContext for socket operations
    boost::asio::io_context ioContext;

    // @note: Create a pair of connected TCP sockets (client <-> server)
    void createConnectedSockets(btcp::socket& server, btcp::socket& client)
    {
        btcp::acceptor acceptor(ioContext, btcp::endpoint(btcp::v4(), 0));
        unsigned short port = acceptor.local_endpoint().port();
        client.connect(btcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
        acceptor.accept(server);
    }
}  // namespace

// @note: Test uint32_t transfer: client -> server
TEST(UtilsNetworkTest, ReadWriteUint32ClientToServer)
{
    btcp::socket server(ioContext);
    btcp::socket client(ioContext);
    createConnectedSockets(server, client);
    uint32_t value = 0x12345678;
    functions::network::writeUint32(client, value);
    uint32_t result = functions::network::readUint32(server);
    EXPECT_EQ(result, value);
}

// @note: Test uint32_t transfer: server -> client
TEST(UtilsNetworkTest, ReadWriteUint32ServerToClient)
{
    btcp::socket server(ioContext);
    btcp::socket client(ioContext);
    createConnectedSockets(server, client);
    uint32_t value = 0x87654321;
    functions::network::writeUint32(server, value);
    uint32_t result = functions::network::readUint32(client);
    EXPECT_EQ(result, value);
}

// @note: Test vector<uint8_t> transfer: non-empty data from client -> server
TEST(UtilsNetworkTest, WriteAndReadVectorNonEmptyClientToServer)
{
    btcp::socket server(ioContext);
    btcp::socket client(ioContext);
    createConnectedSockets(server, client);
    std::vector<uint8_t> data{1, 2, 3, 4, 5};
    functions::network::writeVector(client, data);
    auto result = functions::network::readVector(server);
    EXPECT_EQ(result, data);
}

// @note: Test vector<uint8_t> transfer: empty data from server -> client
TEST(UtilsNetworkTest, WriteAndReadVectorEmptyServerToClient)
{
    btcp::socket server(ioContext);
    btcp::socket client(ioContext);
    createConnectedSockets(server, client);
    std::vector<uint8_t> data;
    functions::network::writeVector(server, data);
    auto result = functions::network::readVector(client);
    EXPECT_TRUE(result.empty());
}
