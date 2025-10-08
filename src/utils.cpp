#include "utils.hpp"
#include <sstream>
#include <iomanip>

namespace CryptoLib {
    std::string to_hex(const std::string& input) {
        std::ostringstream oss;
        for (unsigned char c : input) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
        return oss.str();
    }
}