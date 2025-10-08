#pragma once
#include <vector>
#include <cstdint>

namespace CryptoLib {
    // Popuni bafer kriptografski sigurnim random bajtovima
    void csprng_bytes(std::vector<std::uint8_t>& buf);
}