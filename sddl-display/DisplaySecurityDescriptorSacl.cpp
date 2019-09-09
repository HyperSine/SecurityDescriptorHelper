#include <tchar.h>
#include <windows.h>

#include <system_error>

#pragma comment(lib, "advapi32")

namespace sddldisplay {

    void DisplayAccessControlEntryHeader(PVOID lpAce, PCTSTR lpszPrefix, DWORD Idx);

    void DisplayAccessControlEntryBody(PVOID lpAce, PCTSTR lpszPrefix, DWORD Idx);

    void DisplaySecurityDescriptorSacl(PSECURITY_DESCRIPTOR lpSecurityDescriptor) {
        BOOL bSaclPresent;
        PACL lpSacl = NULL;
        BOOL bIsDefaulted;

        if (GetSecurityDescriptorSacl(lpSecurityDescriptor, &bSaclPresent, &lpSacl, &bIsDefaulted) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        if (bSaclPresent) {
            _tprintf_s(TEXT("->Sacl    : ->AclRevision: 0x%x\n"), lpSacl->AclRevision);
            _tprintf_s(TEXT("->Sacl    : ->Sbz1       : 0x%x\n"), lpSacl->Sbz1);
            _tprintf_s(TEXT("->Sacl    : ->AclSize    : 0x%x\n"), lpSacl->AclSize);
            _tprintf_s(TEXT("->Sacl    : ->AceCount   : 0x%x\n"), lpSacl->AceCount);
            _tprintf_s(TEXT("->Sacl    : ->Sbz2       : 0x%x\n"), lpSacl->Sbz2);

            for (DWORD i = 0; i < lpSacl->AceCount; ++i) {
                PACE_HEADER lpAceHdr = NULL;
                if (GetAce(lpSacl, i, reinterpret_cast<PVOID*>(&lpAceHdr))) {
                    DisplayAccessControlEntryHeader(lpAceHdr, TEXT("->Sacl"), i);
                    DisplayAccessControlEntryBody(lpAceHdr, TEXT("->Sacl"), i);
                    _putts(TEXT(""));
                } else {
                    auto err = GetLastError();
                    throw std::system_error(err, std::system_category());
                }
            }

            if (lpSacl->AceCount == 0) {
                _tprintf_s(TEXT("\n"));
            }
        } else {
            _tprintf_s(TEXT("->Sacl    :  is NULL\n"));
            _tprintf_s(TEXT("\n"));
        }
    }

}

