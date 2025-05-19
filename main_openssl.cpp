#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <iostream>
#include <vector>
#include <cstring>

#include <RSACrypto.h>
#include <AESCrypto.h>
#include <ECDHECrypto.h>

std::vector<uint8_t> sha256(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> output(32);
    SHA256(input.data(), input.size(), output.data());
    return output;
}

int32_t main()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    RSA_Crypto rsa;

    ECDHE_Crypto client_ec;
    ECDHE_Crypto server_ec;

    std::vector<uint8_t> client_pub = client_ec.get_public_key_der();
    std::vector<uint8_t> signature = rsa.sign(client_pub);

    if (!rsa.verify(client_pub, signature)) {
        std::cerr << "Signature verification failed!" << std::endl;
        return 1;
    }

    std::vector<uint8_t> client_secret = client_ec.compute_shared_secret(server_ec.get_key());
    std::vector<uint8_t> server_secret = server_ec.compute_shared_secret(client_ec.get_key());

    if (client_secret != server_secret) {
        std::cerr << "Shared secrets do not match!" << std::endl;
        return 1;
    }

    AES_Crypto aes(sha256(client_secret));
    std::string message = "Hello from client!";

    std::vector<uint8_t> iv = aes.generate_iv();
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ciphertext = aes.encrypt(
        std::vector<uint8_t>(message.begin(), message.end()), iv, tag);

    auto aes_key = sha256(client_secret);
    for (uint8_t b : aes_key) std::cout << std::hex << (int)b;
    std::cout << " ← AES key\n";

    for (uint8_t b : client_secret) std::cout << std::hex << (int)b;
    std::cout << " ← client shared secret\n";

    for (uint8_t b : server_secret) std::cout << std::hex << (int)b;
    std::cout << " ← server shared secret\n";

    std::cout << "IV size: " << iv.size() << ", TAG size: " << tag.size() << ", CT len: " << ciphertext.size() << std::endl;

    std::vector<uint8_t> decrypted = aes.decrypt(ciphertext, iv, tag);
    std::cout << "Decrypted message: " << std::string(decrypted.begin(), decrypted.end()) << std::endl;

    return 0;
}
