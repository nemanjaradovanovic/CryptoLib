#include "rsa.hpp"
#include <iostream>

using namespace CryptoLib;

int main() {
    try {
        auto keys = RSA::generate_keys(1024);
        const std::string msg = "OK"; // kratko, staje u n bez paddinga

        auto enc = RSA::encrypt_string(msg, keys.public_key);
        auto dec = RSA::decrypt_to_string(enc, keys.private_key);

        std::cout << "Original:  " << msg << "\n";
        std::cout << "Decrypted: " << dec << "\n";
    } catch (const std::exception& ex) {
        std::cerr << "RSA error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}