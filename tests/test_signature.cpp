#include "rsa.hpp"
#include <iostream>
#include <cassert>

using namespace CryptoLib;

int main() {
    try {
        auto keys = RSA::generate_keys(1024);

        const std::string msg = "Ovo je poruka koja se potpisuje.";

        // Potpisivanje
        auto sig = RSA::sign(msg, keys.private_key);

        // Verifikacija
        bool ok = RSA::verify(msg, sig, keys.public_key);
        assert(ok);

        // Negativni test: promenjena poruka
        bool bad = RSA::verify("Izmenjena poruka", sig, keys.public_key);
        assert(!bad);

        std::cout << "[PASS] Digital signature test OK\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[FAIL] Exception: " << ex.what() << "\n";
        return 1;
    }
}