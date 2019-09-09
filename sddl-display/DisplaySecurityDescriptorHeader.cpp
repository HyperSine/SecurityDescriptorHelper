#include <tchar.h>
#include <windows.h>
#include <sddl.h>

#include <system_error>
#include <ResourceOwned.hpp>
#include <ResourceTraitsWin32.hpp>
#include <xstring.hpp>

#pragma comment(lib, "advapi32")

namespace sddldisplay {

    std::xstring ConvertSidToAccountName(PSID lpSid);

    void DisplaySecurityDescriptorHeader(PSECURITY_DESCRIPTOR lpSecurityDescriptor) {
        DWORD Revision;
        UCHAR Sbz1;
        SECURITY_DESCRIPTOR_CONTROL Control;

        PSID lpSidOwner;
        ResourceOwned lpszSidOwner(LocalAllocTraits<PTSTR>{});
        std::xstring szOwnerName;

        PSID lpSidGroup;
        ResourceOwned lpszSidGroup(LocalAllocTraits<PTSTR>{});
        std::xstring szGroupName;

        if (GetSecurityDescriptorControl(lpSecurityDescriptor, &Control, &Revision) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        if (GetSecurityDescriptorRMControl(lpSecurityDescriptor, &Sbz1) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        if (BOOL _;  GetSecurityDescriptorOwner(lpSecurityDescriptor, &lpSidOwner, &_) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        if (lpSidOwner) {
            if (ConvertSidToStringSid(lpSidOwner, lpszSidOwner.GetAddressOf()) == FALSE) {
                auto err = GetLastError();
                throw std::system_error(err, std::system_category());
            }

            szOwnerName = ConvertSidToAccountName(lpSidOwner);
        }

        if (BOOL _;  GetSecurityDescriptorGroup(lpSecurityDescriptor, &lpSidGroup, &_) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        if (lpSidGroup) {
            if (ConvertSidToStringSid(lpSidGroup, lpszSidGroup.GetAddressOf()) == FALSE) {
                auto err = GetLastError();
                throw std::system_error(err, std::system_category());
            }

            szGroupName = ConvertSidToAccountName(lpSidGroup);
        }

        _tprintf_s(TEXT("->Revision: 0x%x\n"), Revision);
        _tprintf_s(TEXT("->Sbz1    : 0x%x\n"), Sbz1);
        _tprintf_s(TEXT("->Control : 0x%x\n"), Control);

#define SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(v, f) if (((v) & (f)) != 0) _tprintf_s(TEXT("          : (0x%.4x) %s\n"), f, TEXT(#f))
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_OWNER_DEFAULTED);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_GROUP_DEFAULTED);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_DACL_PRESENT);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_DACL_DEFAULTED);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_SACL_PRESENT);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_SACL_DEFAULTED);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_DACL_AUTO_INHERIT_REQ);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_SACL_AUTO_INHERIT_REQ);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_DACL_AUTO_INHERITED);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_SACL_AUTO_INHERITED);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_DACL_PROTECTED);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_SACL_PROTECTED);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_RM_CONTROL_VALID);
        SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG(Control, SE_SELF_RELATIVE);
#undef SECURITY_DESCRIPTOR_CONTROL_DISPLAY_FLAG

        if (lpSidOwner) {
            _tprintf_s(TEXT("->Owner   : %s (%s)\n"), lpszSidOwner.Get(), szOwnerName.c_str());
        } else {
            _tprintf_s(TEXT("->Owner   :\n"));
        }

        if (lpSidGroup) {
            _tprintf_s(TEXT("->Group   : %s (%s)\n"), lpszSidGroup.Get(), szGroupName.c_str());
        } else {
            _tprintf_s(TEXT("->Group   :\n"));
        }
    }

}

