#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#endif

int main() {
    alignas(16) std::array<std::uint8_t, 16> marker{
        0x41U, 0x52U, 0x47U, 0x4FU, 0x53U, 0x2DU, 0x4DU, 0x43U,
        0x50U, 0x2DU, 0x54U, 0x45U, 0x53U, 0x54U, 0x21U, 0x00U
    };
#if defined(_WIN32)
    const auto pid = static_cast<unsigned long>(GetCurrentProcessId());
#else
    const auto pid = static_cast<unsigned long>(::getpid());
#endif
    const auto address = reinterpret_cast<std::uintptr_t>(marker.data());
    std::cout << "pid=" << pid << " address=0x" << std::hex << std::uppercase << address
              << " pattern=4152474f532d4d43502d544553542100\n" << std::flush;
    std::string line;
    std::getline(std::cin, line);
    return marker[0] == 0x41U ? 0 : 1;
}
