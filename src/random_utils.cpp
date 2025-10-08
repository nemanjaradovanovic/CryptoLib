#include "random_utils.hpp"
#include <stdexcept>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace CryptoLib {
    void csprng_bytes(std::vector<std::uint8_t>& buf) {
        if (buf.empty()) return;
        NTSTATUS status = BCryptGenRandom(
            nullptr,
            buf.data(),
            static_cast<ULONG>(buf.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
        if (status != 0) {
            throw std::runtime_error("BCryptGenRandom failed");
        }
    }
}