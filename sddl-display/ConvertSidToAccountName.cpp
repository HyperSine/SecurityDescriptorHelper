#include <windows.h>
#include <xstring.hpp>

#pragma comment(lib, "advapi32")

namespace sddldisplay {

    std::xstring ConvertSidToAccountName(PSID lpSid) {
        DWORD cchName = 0;
        std::xstring Name;

        DWORD ccbDomain = 0;
        std::xstring Domain;

        SID_NAME_USE SidNameUse;

        LookupAccountSid(NULL, lpSid, NULL, &cchName, NULL, &ccbDomain, &SidNameUse);
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        Name.resize(cchName - 1);
        Domain.resize(ccbDomain - 1);

        if (LookupAccountSid(NULL, lpSid, Name.data(), &cchName, Domain.data(), &ccbDomain, &SidNameUse) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        return Domain + TEXT('\\') + Name;
    }

}

