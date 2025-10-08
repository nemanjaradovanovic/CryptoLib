#include "rsa.hpp"
#include "bigint_utils.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <cassert>

using namespace CryptoLib;

static void run_round_trip_tests_for_key(int bits) {
    std::cout << "[INFO] Generating RSA keys: " << bits << " bits\n";
    auto keys = RSA::generate_keys(bits);
    const auto k = bigint_to_bytes(keys.public_key.n).size();
    const std::size_t hLen = 32; // SHA-256
    const std::size_t maxMsg = k - 2 * hLen - 2;

    // Priprema poruka: prazna, kratka, srednja, duga do limita
    std::vector<std::string> messages;
    messages.push_back("");                           // prazna
    messages.push_back("OK");                         // kratka
    messages.push_back("Ovo je srednja poruka.");    // srednja
    messages.push_back("Тест са ћирилицом");                  // ćirilica
    messages.push_back("Emoji test 😎🔥🚀");                   // emoji
    messages.push_back("Specijalni znaci: © ™ ∞ µ § ¶");       // simboli
    messages.push_back("混合语言测试 Mixed language test");     // kineski + engleski

    // Duga poruka do maksimalne dužine OAEP-a
    std::string longMsg;
    longMsg.resize(maxMsg, 'A');
    messages.push_back(longMsg);

    for (const auto& msg : messages) {
        auto enc1 = RSA::encrypt_string(msg, keys.public_key);
        auto dec1 = RSA::decrypt_to_string(enc1, keys.private_key);
        assert(dec1 == msg);

        // OAEP randomizacija: dve enkripcije iste poruke treba da daju različite ciphertext-ove
        auto enc2 = RSA::encrypt_string(msg, keys.public_key);
        assert(enc1 != enc2);

        std::cout << "[PASS] bits=" << bits << " len(msg)=" << msg.size() << "\n";
    }

    // Negativni test: poruka veća od limita treba da baci izuzetak
    std::string tooLong;
    tooLong.resize(maxMsg + 1, 'B');
    bool threw = false;
    try {
        auto encFail = RSA::encrypt_string(tooLong, keys.public_key);
    } catch (const std::exception&) {
        threw = true;
    }
    assert(threw && "Expected exception for message too long");
    std::cout << "[PASS] bits=" << bits << " too-long message rejected\n";
}

int main() {
    try {
        // Testiraj različite veličine ključeva
        std::vector<int> keySizes = {1024, 2048};
        for (int bits : keySizes) {
            run_round_trip_tests_for_key(bits);
        }
        std::cout << "[ALL TESTS PASSED]\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "[TEST FAILED] Exception: " << ex.what() << std::endl;
        return 1;
    }
}