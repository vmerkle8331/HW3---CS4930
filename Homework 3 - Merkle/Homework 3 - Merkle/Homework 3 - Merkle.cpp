#include <iostream>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/hex.h>
#include <fstream>

int main() {
    // Generate a random initialization vector
    byte iv[AES::BLOCKSIZE];
    auto rng = CryptoPP::AutoSeededX917RNG<CryptoPP::WeakPseudoRandomNumberGenerator>();
    rng.GenerateBlock(iv, AES::BLOCKSIZE);

    // Read the input file
    std::ifstream inputFile("input.txt", std::ios::binary);
    if (!inputFile) {
        std::cerr << "Error: Could not open input file." << std::endl;
        return 1;
    }

    // Encrypt the input data
    std::string plaintext((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
    // Set the key to a known value for testing
    std::string keyString = "0123456789012345678901234567890123";
    CryptoPP::StringSink sink(key, keyString.length());
    CryptoPP::HexEncoder encoder(sink);
    CryptoPP::StringSource(keyString, true, encoder);
    encoder.MessageEnd();

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKey(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

    CryptoPP::StreamTransformationFilter encryptorFilter(encryptor, new CryptoPP::StringSink(plaintext));
    inputFile.read(plaintext, plaintext.size());
    encryptorFilter.Attach(new CryptoPP::FileSink("encrypted.bin"));
    encryptorFilter.MessageEnd();

    // Decrypt the encrypted data
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKey(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

    std::string ciphertext;
    std::ifstream encryptedFile("encrypted.bin", std::ios::binary);
    if (!encryptedFile) {
        std::cerr << "Error: Could not open encrypted file." << std::endl;
        return 1;
    }
    CryptoPP::StringSource(encryptedFile, true, new CryptoPP::StringSink(ciphertext));

    CryptoPP::StreamTransformationFilter decryptorFilter(decryptor, new CryptoPP::StringSink(ciphertext));
    decryptorFilter.Attach(new CryptoPP::FileSink("decrypted.bin"));
    decryptorFilter.MessageEnd();

    return 0;
}