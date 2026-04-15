#include "network/tlsrecordlayer.h"
#include "network/handshakemessages.h"
#include "utils/types.h"
#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>

namespace
{
std::vector<uint8_t> makeKey(uint8_t fill)
{
    return std::vector<uint8_t>(types::vars::AES_KEY_SIZE, fill);
}

std::vector<uint8_t> makeIv(uint8_t fill)
{
    return std::vector<uint8_t>(types::vars::AES_IV_KEY_SIZE, fill);
}
}

TEST(TLSRecordLayerTest, UsesIndependentReadAndWriteKeysPerDirection)
{
    TLSRecordLayer client(makeKey(0x00), makeIv(0x00));
    TLSRecordLayer server(makeKey(0x00), makeIv(0x00));

    const std::vector<uint8_t> clientWriteKey = makeKey(0x11);
    const std::vector<uint8_t> clientWriteIv = makeIv(0x22);
    const std::vector<uint8_t> serverWriteKey = makeKey(0x33);
    const std::vector<uint8_t> serverWriteIv = makeIv(0x44);

    client.setWriteKeys(clientWriteKey, clientWriteIv);
    client.setReadKeys(serverWriteKey, serverWriteIv);
    server.setWriteKeys(serverWriteKey, serverWriteIv);
    server.setReadKeys(clientWriteKey, clientWriteIv);

    const std::vector<uint8_t> clientPayload = HandshakeMessage{HandshakeType::client_hello, {0x01, 0x02, 0x03}}.serialize();
    auto clientRecord = client.encode(static_cast<uint8_t>(ContentType::handshake), 0x0303, clientPayload);
    EXPECT_EQ(server.decode(clientRecord), clientPayload);

    const std::vector<uint8_t> serverPayload = HandshakeMessage{HandshakeType::server_hello, {0x0A, 0x0B}}.serialize();
    auto serverRecord = server.encode(static_cast<uint8_t>(ContentType::handshake), 0x0303, serverPayload);
    EXPECT_EQ(client.decode(serverRecord), serverPayload);
}

TEST(TLSRecordLayerTest, RejectsCiphertextFromWrongDirectionalKeys)
{
    TLSRecordLayer sender(makeKey(0x55), makeIv(0x66));
    TLSRecordLayer receiver(makeKey(0x77), makeIv(0x88));

    sender.setWriteKeys(makeKey(0x01), makeIv(0x02));
    receiver.setReadKeys(makeKey(0x03), makeIv(0x04));

    auto record = sender.encode(static_cast<uint8_t>(ContentType::handshake), 0x0303, {0xAA, 0xBB, 0xCC});
    EXPECT_THROW(receiver.decode(record), std::runtime_error);
}
