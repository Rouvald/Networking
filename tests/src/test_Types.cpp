#include "utils/types.h"
#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>

TEST(TypesTest, ByteWriterAndReaderRoundTrip)
{
    types::ByteWriter writer;
    writer.writeUint8(0x12);
    writer.writeUint16(0x3456);
    writer.writeUint24(0x789ABC);
    writer.writeBytes({0xDE, 0xAD, 0xBE, 0xEF});

    types::ByteReader reader(writer.getBuffer());
    EXPECT_EQ(reader.readUint8(), 0x12);
    EXPECT_EQ(reader.readUint16(), 0x3456);
    EXPECT_EQ(reader.readUint24(), 0x789ABCu);
    EXPECT_EQ(reader.readBytes(4), (std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
    EXPECT_EQ(reader.bytesRemaining(), 0u);
    EXPECT_FALSE(reader.hasRemaining());
}

TEST(TypesTest, ByteReaderSkipAndUnderflowChecks)
{
    types::ByteReader reader({0x10, 0x20, 0x30, 0x40});
    EXPECT_TRUE(reader.hasRemaining());
    reader.skip(2);
    EXPECT_EQ(reader.readUint16(), 0x3040);
    EXPECT_EQ(reader.bytesRemaining(), 0u);
    EXPECT_THROW(reader.readUint8(), std::out_of_range);

    types::ByteReader shortReader({0x01, 0x02});
    EXPECT_THROW(shortReader.readUint24(), std::out_of_range);
}

TEST(TypesTest, TLSPlaintextSerializeDeserializeRoundTrip)
{
    types::TLSPlaintext plaintext;
    plaintext._type = 22;
    plaintext._legacyVersion = 0x0303;
    plaintext._fragment = {0x01, 0x02, 0x03, 0x04};

    const std::vector<uint8_t> serialized = plaintext.serialize();
    const types::TLSPlaintext restored = types::TLSPlaintext::deserialize(serialized);

    EXPECT_EQ(restored._type, plaintext._type);
    EXPECT_EQ(restored._legacyVersion, plaintext._legacyVersion);
    EXPECT_EQ(restored._fragment, plaintext._fragment);
}

TEST(TypesTest, TLSCiphertextSerializeDeserializeRoundTrip)
{
    types::TLSCiphertext ciphertext;
    ciphertext._type = 23;
    ciphertext._legacyVersion = 0x0303;
    ciphertext._encryptedRecord = {0xAA, 0xBB, 0xCC, 0xDD};

    const std::vector<uint8_t> serialized = ciphertext.serialize();
    const types::TLSCiphertext restored = types::TLSCiphertext::deserialize(serialized);

    EXPECT_EQ(restored._type, ciphertext._type);
    EXPECT_EQ(restored._legacyVersion, ciphertext._legacyVersion);
    EXPECT_EQ(restored._encryptedRecord, ciphertext._encryptedRecord);
}
