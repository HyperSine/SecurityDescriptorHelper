#include <tchar.h>
#include <windows.h>
#include <sddl.h>

#include <stdexcept>
#include <system_error>
#include <ResourceOwned.hpp>
#include <ResourceTraitsWin32.hpp>

namespace sddldisplay {

    void DisplaySecurityDescriptorHeader(PSECURITY_DESCRIPTOR lpSecurityDescriptor);

    void DisplaySecurityDescriptorDacl(PSECURITY_DESCRIPTOR lpSecurityDescriptor);

    void DisplaySecurityDescriptorSacl(PSECURITY_DESCRIPTOR lpSecurityDescriptor);

}

void Help() {
    _putts(TEXT("Usage:"));
    _putts(TEXT("    sddl-display.exe <SDDL string>"));
    _putts(TEXT(""));
}

int _tmain(int argc, PTSTR argv[]) {
    try {
        if (argc == 2) {
            ResourceOwned lpSecurityDescriptor(LocalAllocTraits<PSECURITY_DESCRIPTOR>{});

            if (ConvertStringSecurityDescriptorToSecurityDescriptor(argv[1], SDDL_REVISION, lpSecurityDescriptor.GetAddressOf(), NULL) == FALSE) {
                auto err = GetLastError();
                throw std::system_error(err, std::system_category());
            }
            
            sddldisplay::DisplaySecurityDescriptorHeader(lpSecurityDescriptor);
            sddldisplay::DisplaySecurityDescriptorDacl(lpSecurityDescriptor);
            sddldisplay::DisplaySecurityDescriptorSacl(lpSecurityDescriptor);

            return 0;
        } else {
            Help();
            return -1;
        }
    } catch (std::system_error& e) {
        _tprintf_s(TEXT("[-] system_error -> %hs (%d)\n"), e.what(), e.code().value());
        return e.code().value();
    } catch (std::exception& e) {
        _tprintf_s(TEXT("[-] exception -> %hs\n"), e.what());
        return -1;
    }
}
