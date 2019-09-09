#include <tchar.h>
#include <windows.h>
#include <AclAPI.h>

#include <system_error>
#include <ResourceOwned.hpp>
#include <ResourceTraitsWin32.hpp>
#include <xstring.hpp>

#pragma comment(lib, "advapi32")

namespace sddldisplay {

    void DisplayAccessControlEntryHeader(PVOID lpAce, PCTSTR lpszPrefix, DWORD Idx);

    void DisplayAccessControlEntryBody(PVOID lpAce, PCTSTR lpszPrefix, DWORD Idx);

    void DisplaySecurityDescriptorDacl(PSECURITY_DESCRIPTOR lpSecurityDescriptor) {
        BOOL bDaclPresent;
        PACL lpDacl = NULL;
        BOOL bIsDefaulted;

        if (GetSecurityDescriptorDacl(lpSecurityDescriptor, &bDaclPresent, &lpDacl, &bIsDefaulted) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        if (bDaclPresent) {
            _tprintf_s(TEXT("->Dacl    : ->AclRevision: 0x%x\n"), lpDacl->AclRevision);
            _tprintf_s(TEXT("->Dacl    : ->Sbz1       : 0x%x\n"), lpDacl->Sbz1);
            _tprintf_s(TEXT("->Dacl    : ->AclSize    : 0x%x\n"), lpDacl->AclSize);
            _tprintf_s(TEXT("->Dacl    : ->AceCount   : 0x%x\n"), lpDacl->AceCount);
            _tprintf_s(TEXT("->Dacl    : ->Sbz2       : 0x%x\n"), lpDacl->Sbz2);

            for (DWORD i = 0; i < lpDacl->AceCount; ++i) {
                PACE_HEADER lpAceHdr = NULL;
                if (GetAce(lpDacl, i, reinterpret_cast<PVOID*>(&lpAceHdr))) {
                    DisplayAccessControlEntryHeader(lpAceHdr, TEXT("->Dacl"), i);
                    DisplayAccessControlEntryBody(lpAceHdr, TEXT("->Dacl"), i);
                    _putts(TEXT(""));
                } else {
                    auto err = GetLastError();
                    throw std::system_error(err, std::system_category());
                }
            }

            if (lpDacl->AceCount == 0) {
                _tprintf_s(TEXT("\n"));
            }
        } else {
            _tprintf_s(TEXT("->Dacl    :  is NULL\n"));
            _tprintf_s(TEXT("\n"));
        }
    }

}

