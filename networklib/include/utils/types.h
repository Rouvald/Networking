#ifndef TYPES_H
#define TYPES_H

#include <cstdint>
#include <vector>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <boost/asio/ip/tcp.hpp>
#include <ratio>

using btcp = boost::asio::ip::tcp;

namespace types
{
    namespace vars
    {
        constexpr uint8_t SHA256_KEY_SIZE{32};

        constexpr uint8_t AES_KEY_SIZE{32};
        constexpr uint8_t AES_IV_KEY_SIZE{12};
        constexpr uint8_t GCM_TAG_SIZE{16};
    }  // namespace vars

    class ByteWriter
    {
    public:
        void writeUint8(uint8_t value);
        void writeUint16(uint16_t value);
        void writeUint24(uint32_t value);
        void writeBytes(const std::vector<uint8_t>& data);

        const std::vector<uint8_t>& getBuffer() const { return _buffer; }

    private:
        std::vector<uint8_t> _buffer;
    };
    class ByteReader
    {
    public:
        explicit ByteReader(std::vector<uint8_t> buffer) : _buffer(std::move(buffer)) {}
        ~ByteReader() = default;

        ByteReader(const ByteReader&) = delete;
        ByteReader& operator=(const ByteReader&) = delete;
        ByteReader(ByteReader&&) = delete;
        ByteReader& operator=(ByteReader&&) noexcept = delete;

        uint8_t readUint8();
        uint16_t readUint16();
        uint32_t readUint24();
        std::vector<uint8_t> readBytes(size_t length);
        void skip(size_t length);

        size_t bytesRemaining() const { return _buffer.size() - _pos; }
        bool hasRemaining() const { return _pos < _buffer.size(); }

    private:
        std::vector<uint8_t> _buffer;
        size_t _pos{0};

        void ensureAvailable(const size_t& len) const;
    };
    struct TLSPlaintext
    {
        uint8_t _type{};
        uint16_t _legacyVersion{};
        std::vector<uint8_t> _fragment;

        std::vector<uint8_t> serialize() const;
        static TLSPlaintext deserialize(const std::vector<uint8_t>& buf);
    };
    struct TLSCiphertext
    {
        uint8_t _type{};
        uint16_t _legacyVersion{};
        std::vector<uint8_t> _encryptedRecord;

        std::vector<uint8_t> serialize() const;
        static TLSCiphertext deserialize(const std::vector<uint8_t>& buf);
    };

    namespace debug
    {
        class Timer
        {
        public:
            void start() { _start = std::chrono::high_resolution_clock::now(); }
            void stop()
            {
                _durationMs = std::chrono::duration<double, std::milli>(std::chrono::high_resolution_clock::now() - _start).count();
                std::cout << "elapsed: " << std::fixed << std::setprecision(2) << _durationMs << " ms\n";
            }
            double lastElapsedMs() const { return _durationMs; }

        private:
            std::chrono::high_resolution_clock::time_point _start;
            double _durationMs{0.0};
        };
    }  // namespace debug
}  // namespace types

#endif  // TYPES_H
