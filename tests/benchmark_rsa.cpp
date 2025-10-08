#include "rsa.hpp"
#include "bigint_utils.hpp"
#include <iostream>
#include <chrono>
#include <string>
#include <fstream>
#include <vector>

using namespace CryptoLib;
using namespace std::chrono;

static void benchmark_rsa(int bits, const std::string& msg, std::ofstream& csv) {
    std::cout << "\n[INFO] Benchmark RSA " << bits << " bits\n";

    try {
        // KeyGen
        auto t1 = high_resolution_clock::now();
        auto keys = RSA::generate_keys(bits);
        auto t2 = high_resolution_clock::now();
        auto keygen_ms = duration_cast<milliseconds>(t2 - t1).count();
        std::cout << "KeyGen:      " << keygen_ms << " ms\n";

        // Encrypt
        t1 = high_resolution_clock::now();
        auto enc = RSA::encrypt_string(msg, keys.public_key);
        t2 = high_resolution_clock::now();
        auto encrypt_ms = duration_cast<milliseconds>(t2 - t1).count();
        std::cout << "Encrypt:     " << encrypt_ms << " ms\n";

        // Decrypt
        t1 = high_resolution_clock::now();
        auto dec = RSA::decrypt_to_string(enc, keys.private_key);
        t2 = high_resolution_clock::now();
        auto decrypt_ms = duration_cast<milliseconds>(t2 - t1).count();
        std::cout << "Decrypt:     " << decrypt_ms << " ms\n";

        bool ok = (dec == msg);
        std::cout << (ok ? "[PASS]" : "[FAIL]") << " Round-trip\n";

        // Upis u CSV
        csv << bits << "," << msg.size() << "," 
            << keygen_ms << "," << encrypt_ms << "," << decrypt_ms << "," 
            << (ok ? "OK" : "FAIL") << "\n";
    }
    catch (const std::exception& ex) {
        std::cerr << "[ERROR] RSA failed: " << ex.what() << "\n";
        csv << bits << "," << msg.size() << ",ERR,ERR,ERR,ERROR\n";
    }
}

int main() {
    std::ofstream csv("rsa_benchmark.csv", std::ios::out);
    if (!csv.is_open()) {
        std::cerr << "Ne mogu da otvorim rsa_benchmark.csv\n";
        return 1;
    }
    csv << "KeyBits,MsgLen,KeyGenMS,EncryptMS,DecryptMS,Status\n";

    const std::vector<std::string> messages = {
        "Hi",
        "Poruka srednje dužine za testiranje.",
        std::string(190, 'X') // max za 2048-bitni ključ
    };

    for (const auto& msg : messages) {
        benchmark_rsa(1024, msg, csv);
        benchmark_rsa(2048, msg, csv);
    }

    csv.close();
    std::cout << "\nBenchmark zapisano u rsa_benchmark.csv\n";
    return 0;
}