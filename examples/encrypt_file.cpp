#include <iostream>
#include "utils.hpp"

int main() {
    std::string msg = "Nemanja";
    std::cout << "Hex: " << CryptoLib::to_hex(msg) << std::endl;
    return 0;
}