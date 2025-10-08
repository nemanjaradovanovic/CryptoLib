#include "rsa.hpp"
#include "hash_utils.hpp"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>

using namespace CryptoLib;

// Pretvaranje bajtova u hex string
std::string to_hex(const std::vector<std::uint8_t>& data) {
    std::ostringstream oss;
    for (auto b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

// Pretvaranje hex stringa u bajtove
std::vector<std::uint8_t> from_hex(const std::string& hex) {
    std::vector<std::uint8_t> out;
    if (hex.size() % 2 != 0) throw std::invalid_argument("Neparan broj hex karaktera");
    for (size_t i = 0; i < hex.size(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        std::uint8_t byte = (std::uint8_t) std::stoul(byteStr, nullptr, 16);
        out.push_back(byte);
    }
    return out;
}

// Učitavanje fajla u bajtove
std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) throw std::runtime_error("Ne mogu da otvorim fajl: " + path);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(ifs)),
                                     std::istreambuf_iterator<char>());
}

// Upis bajtova u fajl
void write_file(const std::string& path, const std::vector<std::uint8_t>& data) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) throw std::runtime_error("Ne mogu da upisem fajl: " + path);
    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Trim navodnika sa početka i kraja stringa
std::string trim_quotes(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

void menu() {
    std::cout << "\n=== CryptoLib CLI ===\n";
    std::cout << "1) Generisi RSA kljuceve\n";
    std::cout << "2) Enkripcija poruke\n";
    std::cout << "3) Dekripcija poruke\n";
    std::cout << "4) Digitalni potpis\n";
    std::cout << "5) Verifikacija potpisa\n";
    std::cout << "6) Enkripcija fajla\n";
    std::cout << "7) Dekripcija fajla\n";
    std::cout << "8) Potpisivanje fajla\n";
    std::cout << "9) Verifikacija potpisa fajla\n";
    std::cout << "0) Izlaz\n";
    std::cout << "Izbor: ";
}

int main() {
    RSAKeyPair keys;
    bool keys_generated = false;

    while (true) {
        menu();
        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::string dummy;
            std::getline(std::cin, dummy);
            std::cout << "[ERROR] Unesi broj opcije!\n";
            continue;
        }
        std::cin.ignore();

                if (choice == 0) break;

        if (choice == 1) {
            std::cout << "Unesi velicinu kljuca (1024 ili 2048): ";
            int bits;
            std::cin >> bits;
            std::cin.ignore();
            keys = RSA::generate_keys(bits);
            keys_generated = true;
            std::cout << "[INFO] Kljucevi generisani.\n";
        }
        else if (choice == 2) {
            if (!keys_generated) { std::cout << "[WARN] Prvo generisi kljuceve!\n"; continue; }
            std::cout << "Unesi poruku: ";
            std::string msg;
            std::getline(std::cin, msg);
            try {
                auto enc = RSA::encrypt_string(msg, keys.public_key);
                std::cout << "[ENCRYPTED HEX] " << to_hex(enc) << "\n";
            } catch (const std::exception& ex) {
                std::cout << "[ERROR] " << ex.what() << "\n";
            }
        }
        else if (choice == 3) {
            if (!keys_generated) { std::cout << "[WARN] Prvo generisi kljuceve!\n"; continue; }
            std::cout << "Unesi sifrovanu poruku u hex formatu: ";
            std::string hex;
            std::getline(std::cin, hex);
            try {
                auto enc = from_hex(hex);
                auto dec = RSA::decrypt_to_string(enc, keys.private_key);
                std::cout << "[DECRYPTED] " << dec << "\n";
            } catch (const std::exception& ex) {
                std::cout << "[ERROR] " << ex.what() << "\n";
            }
        }
        else if (choice == 4) {
            if (!keys_generated) { std::cout << "[WARN] Prvo generisi kljuceve!\n"; continue; }
            std::cout << "Unesi poruku za potpis: ";
            std::string msg;
            std::getline(std::cin, msg);
            try {
                auto sig = RSA::sign(msg, keys.private_key);
                std::cout << "[SIGNATURE HEX] " << to_hex(sig) << "\n";
            } catch (const std::exception& ex) {
                std::cout << "[ERROR] " << ex.what() << "\n";
            }
        }
        else if (choice == 5) {
            if (!keys_generated) { std::cout << "[WARN] Prvo generisi kljuceve!\n"; continue; }
            std::cout << "Unesi poruku za verifikaciju: ";
            std::string msg;
            std::getline(std::cin, msg);
            std::cout << "Unesi potpis u hex formatu: ";
            std::string hex;
            std::getline(std::cin, hex);
            try {
                auto sig = from_hex(hex);
                bool ok = RSA::verify(msg, sig, keys.public_key);
                std::cout << (ok ? "[PASS] Potpis validan\n" : "[FAIL] Potpis NIJE validan\n");
            } catch (const std::exception& ex) {
                std::cout << "[ERROR] " << ex.what() << "\n";
            }
        }
        else if (choice == 6) {
            if (!keys_generated) { std::cout << "[WARN] Prvo generisi kljuceve!\n"; continue; }
            std::cout << "Unesi putanju do fajla: ";
            std::string path;
            std::getline(std::cin, path);
            path = trim_quotes(path);
            try {
                auto data = read_file(path);
                auto enc = RSA::encrypt(data, keys.public_key);
                write_file(path + ".enc", enc);
                std::cout << "[INFO] Fajl enkriptovan u: " << path << ".enc\n";
            } catch (const std::exception& ex) {
                std::cout << "[ERROR] " << ex.what() << "\n";
            }
        }
        else if (choice == 7) {
            if (!keys_generated) { std::cout << "[WARN] Prvo generisi kljuceve!\n"; continue; }
            std::cout << "Unesi putanju do .enc fajla: ";
            std::string path;
            std::getline(std::cin, path);
            path = trim_quotes(path);
            try {
                auto enc = read_file(path);
                auto dec = RSA::decrypt(enc, keys.private_key);
                write_file(path + ".dec", dec);
                std::cout << "[INFO] Fajl dekriptovan u: " << path << ".dec\n";
            } catch (const std::exception& ex) {
                std::cout << "[ERROR] " << ex.what() << "\n";
            }
        }
        else if (choice == 8) {
            if (!keys_generated) { std::cout << "[WARN] Prvo generisi kljuceve!\n"; continue; }
            std::cout << "Unesi putanju do fajla za potpisivanje: ";
            std::string path;
            std::getline(std::cin, path);
            path = trim_quotes(path);
            try {
                auto data = read_file(path);
                auto hash = sha256(data);
                auto sig = RSA::sign(std::string(hash.begin(), hash.end()), keys.private_key);
                write_file(path + ".sig", sig);
                std::cout << "[INFO] Potpis sacuvan u: " << path << ".sig\n";
            } catch (const std::exception& ex) {
                std::cout << "[ERROR] " << ex.what() << "\n";
            }
        }
        else if (choice == 9) {
            if (!keys_generated) { std::cout << "[WARN] Prvo generisi kljuceve!\n"; continue; }
            std::cout << "Unesi putanju do fajla za verifikaciju: ";
            std::string path;
            std::getline(std::cin, path);
            path = trim_quotes(path);
            try {
                auto data = read_file(path);
                auto hash = sha256(data);
                auto sig = read_file(path + ".sig");
                bool ok = RSA::verify(std::string(hash.begin(), hash.end()), sig, keys.public_key);
                std::cout << (ok ? "[PASS] Potpis validan\n" : "[FAIL] Potpis NIJE validan\n");
            } catch (const std::exception& ex) {
                std::cout << "[ERROR] " << ex.what() << "\n";
            }
        }
        else {
            std::cout << "[WARN] Nepoznata opcija.\n";
        }
    }

    std::cout << "Izlaz iz programa.\n";
    return 0;
}