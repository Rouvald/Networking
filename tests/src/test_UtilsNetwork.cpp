#include "UtilsNetwork.h"
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <vector>

namespace
{
    // @note: Shared io_context for socket operations
    boost::asio::io_context io_context;

    // @note: Create a pair of connected TCP sockets (client <-> server)
    void create_connected_sockets(btcp::socket& server, btcp::socket& client)
    {
        btcp::acceptor acceptor(io_context, btcp::endpoint(btcp::v4(), 0));
        unsigned short port = acceptor.local_endpoint().port();
        client.connect(btcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
        acceptor.accept(server);
    }
}  // namespace

// @note: Test uint32_t transfer: client -> server
TEST(UtilsNetworkTest, ReadWriteUint32ClientToServer)
{
    btcp::socket server(io_context);
    btcp::socket client(io_context);
    create_connected_sockets(server, client);
    uint32_t value = 0x12345678;
    UtilsNetwork::write_uint32(client, value);
    uint32_t result = UtilsNetwork::read_uint32(server);
    EXPECT_EQ(result, value);
}

// @note: Test uint32_t transfer: server -> client
TEST(UtilsNetworkTest, ReadWriteUint32ServerToClient)
{
    btcp::socket server(io_context);
    btcp::socket client(io_context);
    create_connected_sockets(server, client);
    uint32_t value = 0x87654321;
    UtilsNetwork::write_uint32(server, value);
    uint32_t result = UtilsNetwork::read_uint32(client);
    EXPECT_EQ(result, value);
}

// @note: Test vector<uint8_t> transfer: non-empty data from client -> server
TEST(UtilsNetworkTest, WriteAndReadVectorNonEmptyClientToServer)
{
    btcp::socket server(io_context);
    btcp::socket client(io_context);
    create_connected_sockets(server, client);
    std::vector<uint8_t> data{1, 2, 3, 4, 5};
    UtilsNetwork::write_vector(client, data);
    auto result = UtilsNetwork::read_vector(server);
    EXPECT_EQ(result, data);
}

// @note: Test vector<uint8_t> transfer: empty data from server -> client
TEST(UtilsNetworkTest, WriteAndReadVectorEmptyServerToClient)
{
    btcp::socket server(io_context);
    btcp::socket client(io_context);
    create_connected_sockets(server, client);
    std::vector<uint8_t> data;
    UtilsNetwork::write_vector(server, data);
    auto result = UtilsNetwork::read_vector(client);
    EXPECT_TRUE(result.empty());
}
