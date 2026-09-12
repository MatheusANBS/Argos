// The initial bridge deliberately does no work in DllMain. It exists to prove
// the opt-in injection lifecycle (ADR-0021) before any engine-specific
// instrumentation or IPC surface is introduced.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) {
    return TRUE;
}
