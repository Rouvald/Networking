#include <HandshakeManager.h>
#include <UtilsCrypto.h>
#include <UtilsNetwork.h>
#include <HandshakeMessages.h>
#include <ECDHECrypto.h>
#include <KeySchedule.h>
#include <stdexcept>
#include <openssl/rand.h>

void HandshakeManager::do_client_handshake()
{
    // 1. Собираем ClientHello
    ClientHello client_hello;
    client_hello.legacy_version = 0x0303;  // всегда 0x0303 в TLS1.3
    client_hello.random.resize(32);
    if (RAND_bytes(client_hello.random.data(), static_cast<int>(client_hello.random.size())) != 1)
    {
        throw std::runtime_error("RAND_bytes failed");
    }
    client_hello.session_id.clear();
    client_hello.cipher_suites = {0x1301};  // TLS_AES_128_GCM_SHA256
    client_hello.compression_methods = {0x00};  // null

    // extensions
    ExtensionWriter ext;
    ext.write_supported_versions({0x0304});  // TLS1.3
    std::vector<uint8_t> client_pub = dhe_.get_public_key_der();
    ext.write_key_share({
        {0x001d, client_pub}
    });  // x25519
    client_hello.extensions = ext.finalize();

    // сериализуем и шлем по сети
    std::vector<uint8_t> ch_bytes = client_hello.to_message().serialize();
    transcript_.insert(transcript_.end(), ch_bytes.begin(), ch_bytes.end());

    // формируем TLSCiphertext и шлем его
    {
        auto rec = record_.encode(static_cast<uint8_t>(ContentType::handshake),
            /*legacy_version=*/0x0303, ch_bytes);
        UtilsNetwork::write_vector(socket_, rec.serialize());
    }

    // 2. Принимаем ServerHello
    std::vector<uint8_t> raw = UtilsNetwork::read_vector(socket_);
    auto tlsRec = TLSCiphertext::deserialize(raw);
    std::vector<uint8_t> sh_bytes = record_.decode(tlsRec);
    HandshakeMessage sh_msg = HandshakeMessage::deserialize(sh_bytes);
    if (sh_msg.msg_type != HandshakeType::server_hello)
    {
        throw std::runtime_error("Expected ServerHello");
    }
    transcript_.insert(transcript_.end(), sh_bytes.begin(), sh_bytes.end());
    ServerHello server_hello = ServerHello::parse_body(sh_msg.body);

    // 3. Вычисляем общий секрет
    KeyShareEntry share_entry = parse_key_share(server_hello.extensions);
    const uint8_t* p = share_entry.key.data();
    EVP_PKEY* peer = d2i_PUBKEY(nullptr, &p, share_entry.key.size());
    if (peer == nullptr)
    {
        throw std::runtime_error("Invalid server public key DER");
    }
    std::vector<uint8_t> shared = dhe_.compute_shared_secret(peer);
    EVP_PKEY_free(peer);

    // 4. Process encrypted handshake messages
    // 4.1 EncryptedExtensions
    {
        std::vector<uint8_t> enc = UtilsNetwork::read_vector(socket_);
        auto trec = TLSCiphertext::deserialize(enc);
        std::vector<uint8_t> body = record_.decode(trec);
        transcript_.insert(transcript_.end(), body.begin(), body.end());
        EncryptedExtensions ee = EncryptedExtensions::parse_body(body);
    }
    // 4.2 Certificate
    Certificate cert;
    {
        std::vector<uint8_t> enc = UtilsNetwork::read_vector(socket_);
        auto trec = TLSCiphertext::deserialize(enc);
        std::vector<uint8_t> body = record_.decode(trec);
        transcript_.insert(transcript_.end(), body.begin(), body.end());
        cert = Certificate::parse_body(body);
    }
    // 4.3 CertificateVerify
    CertificateVerify cv;
    {
        std::vector<uint8_t> enc = UtilsNetwork::read_vector(socket_);
        auto trec = TLSCiphertext::deserialize(enc);
        std::vector<uint8_t> body = record_.decode(trec);
        transcript_.insert(transcript_.end(), body.begin(), body.end());
        cv = CertificateVerify::parse_body(body);
    }
    // TODO: verify signature using cert

    // 4.4 Server Finished
    {
        std::vector<uint8_t> enc = UtilsNetwork::read_vector(socket_);
        auto trec = TLSCiphertext::deserialize(enc);
        std::vector<uint8_t> body = record_.decode(trec);
        transcript_.insert(transcript_.end(), body.begin(), body.end());
        Finished sf = Finished::parse_body(body);
        std::vector<uint8_t> expected = HKDF::expandLabel(handshake_secret_, "finished", transcript_hash(), UtilsCrypto::SHA256_KEY_SIZE);
        if (sf.verify_data != expected)
            throw std::runtime_error("Server Finished verification failed");
    }

    // 5. Send Client Finished
    {
        std::vector<uint8_t> verify_data =
            HKDF::expandLabel(handshake_secret_, "finished", transcript_hash(), UtilsCrypto::SHA256_KEY_SIZE);
        Finished cf{verify_data};
        std::vector<uint8_t> cf_body = cf.to_message().serialize();
        transcript_.insert(transcript_.end(), cf_body.begin(), cf_body.end());

        auto rec = record_.encode(static_cast<uint8_t>(ContentType::handshake), 0x0303, cf_body);
        UtilsNetwork::write_vector(socket_, rec.serialize());
    }

    // 6. Derive Application Keys and switch to application_data
    master_secret_ = deriveMasterSecret(handshake_secret_);
    std::vector<uint8_t> app_key = HKDF::expandLabel(master_secret_, "key", transcript_hash(), UtilsCrypto::SHA256_KEY_SIZE);
    std::vector<uint8_t> app_iv = HKDF::expandLabel(master_secret_, "iv", transcript_hash(), AES_IV_KEY_SIZE);
    record_ = TLSRecordLayer(app_key, app_iv);
    record_.reset_sequence();
}

std::vector<uint8_t> HandshakeManager::transcript_hash() const
{
    return UtilsCrypto::sha256(transcript_);
}