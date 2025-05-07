#include "SHA256Custom.h"

#include <cstdint>

#include <AESCustom.h>
#include <RSACustom.h>
#include <manager.h>
#include <HandshakeContext.h>
#include <SessionCipher.h>

void testRSA()
{
    RSACustom rsa = RSACustom();
    rsa.generateKeys();

    std::string msg{"Hello world!!!!?"};
    bmp::cpp_int ciph = rsa.encrypt(msg);
    std::cout << "Encrypted: " << ciph << "\n";

    std::string decrypted = rsa.decrypt(ciph);
    std::cout << "Decrypted: " << decrypted << "\n";

    // with sign
    std::string message = "Hello custom TLS! Test";

    bmp::cpp_int signature = rsa.sign(message);
    std::cout << "Signature:\n" << signature << "\n\n";

    bool isValid = rsa.verify(message, signature);
    std::cout << "Signature valid? " << (isValid ? "YES" : "NO") << "\n";

    std::string tampered = message + "!";
    bool fakeValid = rsa.verify(tampered, signature);
    std::cout << "Tampered valid? " << (fakeValid ? "YES" : "NO") << "\n";
}

void testSHA()
{
    const std::string testMsg{"Test message wuth some symbols !!?"};
    auto hash_1 = sha256(testMsg);
    std::cout << "hash_1 - " << hash_1 << '\n';
    auto hash_2 = sha256(testMsg);
    std::cout << "hash_2 - " << hash_2 << '\n';
}

void testAES(const std::string& label, AESKeyLength keyLength, size_t keySize)
{
    std::string plainText = "AES test message for CBC mode!123";
    std::vector<unsigned char> data(plainText.begin(), plainText.end());

    std::vector<unsigned char> key = AESCustom::generateRandomKey(keySize);
    std::vector<unsigned char> iv = AESCustom::generateRandomIV();

    AESCustom aes(keyLength);

    std::cout << "\n=== " << label << " ===\n";
    std::cout << "Plaintext:\n";
    aes.printHexVector(data);

    std::cout << "Random Key:\n";
    aes.printHexVector(key);

    std::cout << "Random IV:\n";
    aes.printHexVector(iv);

    auto encrypted = aes.EncryptCBC(data, key, iv);
    std::cout << "Encrypted:\n";
    aes.printHexVector(encrypted);

    auto decrypted = aes.DecryptCBC(encrypted, key, iv);
    std::cout << "Decrypted:\n";
    aes.printHexVector(decrypted);

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    std::cout << "As string: " << decryptedStr << "\n";
}

void testAESs()
{
    testAES("AES-128 CBC", AESKeyLength::AES_128, 16);
    testAES("AES-256 CBC", AESKeyLength::AES_256, 32);
}

void testHandshake()
{
    HandshakeContext serverCtx(false);
    RSAPublicKey serverPubKey = serverCtx.getPublicKey();

    std::cout << "[Server] generate RSA\n";

    HandshakeContext clientCtx(true);
    clientCtx.generateSessionKey();

    std::cout << "[Client] generate session AES\n";

    auto encryptedKey = clientCtx.encryptSessionKeyWithServerRSA(serverPubKey);

    std::cout << "[Client] encrypt AES\n";

    //std::cout << "[TEST] encryptedKey - " << encryptedKey << '\n';

    serverCtx.decryptSessionKeyFromClient(encryptedKey);

    std::cout << "[Server] decrypt AES \n";

    const auto& clientKey = clientCtx.getSessionKey();
    const auto& serverKey = serverCtx.getSessionKey();

    bool keysMatch = (clientKey == serverKey);

    std::cout << "Seesion keys are " << (keysMatch ? "equal" : "different") << "\n";
}

void testSecureSession() {
    std::cout << "=== Secure Session ===\n";

    HandshakeContext serverHandshake(false);
    RSAPublicKey serverPubKey = serverHandshake.getPublicKey();
    std::cout << "[Server] Generated RSA key pair\n";

    HandshakeContext clientHandshake(true);
    clientHandshake.generateSessionKey();
    std::cout << "[Client] Generated AES session key\n";

    auto encryptedSessionKey = clientHandshake.encryptSessionKeyWithServerRSA(serverPubKey);
    std::cout << "[Client] Encrypted AES key with server's public RSA key\n";

    serverHandshake.decryptSessionKeyFromClient(encryptedSessionKey);
    std::cout << "[Server] Decrypted AES session key from client\n";

    SessionCipher clientCipher;
    clientCipher.setKey(clientHandshake.getSessionKey());

    SessionCipher serverCipher;
    serverCipher.setKey(serverHandshake.getSessionKey());
    serverCipher.setIV(clientCipher.getIV()); // sync IV

    std::string plaintext = "Test msg for TLS hehe 12345677890";
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

    auto encrypted = clientCipher.encrypt(data);
    std::cout << "[Client] Encrypted message sent to server\n";

    auto decrypted = serverCipher.decrypt(encrypted);
    std::string recovered(decrypted.begin(), decrypted.end());

    std::cout << "[Server] Decrypted message: " << recovered << "\n";

    bool keysMatch = (clientHandshake.getSessionKey() == serverHandshake.getSessionKey());
    std::cout << "[Handshake] Session keys match: " << (keysMatch ? "YES" : "NO") << "\n";
}

int32_t main(int32_t argc, char** argv)
{
    (void)argc;
    (void)argv;

    // Network
    /*basio::io_context io;
    Manager mng(io.get_executor(), "google.com");
    mng.connect();
    mng.disconnect();
    mng.connect();*/

    std::cout << std::endl << "===================================================================" << std::endl << std::endl;

    // RSA
    testRSA();

    std::cout << std::endl << "===================================================================" << std::endl << std::endl;

    // sha
    testSHA();

    std::cout << std::endl << "===================================================================" << std::endl << std::endl;

    // AES
    testAESs();

    std::cout << std::endl << "===================================================================" << std::endl << std::endl;

    // Handshake
    //testHandshake();

    // session
    testSecureSession();

    return EXIT_SUCCESS;
}