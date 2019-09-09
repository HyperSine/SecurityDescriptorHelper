#include <tchar.h>
#include <windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <Iads.h>

#include <system_error>
#include <ResourceOwned.hpp>
#include <ResourceTraitsWin32.hpp>
#include <xstring.hpp>

#pragma comment(lib, "advapi32")

namespace sddldisplay {

    std::xstring ConvertSidToAccountName(PSID lpSid);

    std::xstring ConvertGuidToStringGuid(const GUID& Guid);

    template<decltype(ACE_HEADER::AceType) __AceType>
    static void DisplayAccessControlEntryBody(PVOID p, PCTSTR lpszPrefix, DWORD Idx);

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_ALLOWED_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PACCESS_ALLOWED_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_DENIED_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PACCESS_DENIED_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});
        
        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_AUDIT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_AUDIT_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }
        
        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_ALARM_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_ALARM_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_ALLOWED_COMPOUND_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        // Reserved
    }

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_ALLOWED_OBJECT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PACCESS_ALLOWED_OBJECT_ACE>(p);

        auto lpszObjectTypeGuid = ConvertGuidToStringGuid(lpAce->ObjectType);
        auto lpszInheritedObjectTypeGuid = ConvertGuidToStringGuid(lpAce->InheritedObjectType);

        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Flags);

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_OBJECT_TYPE_PRESENT, TEXT("ACE_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_INHERITED_OBJECT_TYPE_PRESENT, TEXT("ACE_INHERITED_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->ObjectType: %s\n"), lpszPrefix, Idx, lpszObjectTypeGuid.c_str());
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->InheritedObjectType: %s\n"), lpszPrefix, Idx, lpszInheritedObjectTypeGuid.c_str());
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_DENIED_OBJECT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PACCESS_DENIED_OBJECT_ACE>(p);

        auto lpszObjectTypeGuid = ConvertGuidToStringGuid(lpAce->ObjectType);
        auto lpszInheritedObjectTypeGuid = ConvertGuidToStringGuid(lpAce->InheritedObjectType);

        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Flags);

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_OBJECT_TYPE_PRESENT, TEXT("ACE_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_INHERITED_OBJECT_TYPE_PRESENT, TEXT("ACE_INHERITED_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->ObjectType: %s\n"), lpszPrefix, Idx, lpszObjectTypeGuid.c_str());
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->InheritedObjectType: %s\n"), lpszPrefix, Idx, lpszInheritedObjectTypeGuid.c_str());
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_AUDIT_OBJECT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_AUDIT_OBJECT_ACE>(p);

        auto lpszObjectTypeGuid = ConvertGuidToStringGuid(lpAce->ObjectType);
        auto lpszInheritedObjectTypeGuid = ConvertGuidToStringGuid(lpAce->InheritedObjectType);

        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Flags);

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_OBJECT_TYPE_PRESENT, TEXT("ACE_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_INHERITED_OBJECT_TYPE_PRESENT, TEXT("ACE_INHERITED_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->ObjectType: %s\n"), lpszPrefix, Idx, lpszObjectTypeGuid.c_str());
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->InheritedObjectType: %s\n"), lpszPrefix, Idx, lpszInheritedObjectTypeGuid.c_str());
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_ALARM_OBJECT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_ALARM_OBJECT_ACE>(p);
        
        auto lpszObjectTypeGuid = ConvertGuidToStringGuid(lpAce->ObjectType);
        auto lpszInheritedObjectTypeGuid = ConvertGuidToStringGuid(lpAce->InheritedObjectType);

        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Flags);

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_OBJECT_TYPE_PRESENT, TEXT("ACE_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_INHERITED_OBJECT_TYPE_PRESENT, TEXT("ACE_INHERITED_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->ObjectType: %s\n"), lpszPrefix, Idx, lpszObjectTypeGuid.c_str());
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->InheritedObjectType: %s\n"), lpszPrefix, Idx, lpszInheritedObjectTypeGuid.c_str());
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_ALLOWED_CALLBACK_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PACCESS_ALLOWED_CALLBACK_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_DENIED_CALLBACK_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PACCESS_DENIED_CALLBACK_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PACCESS_ALLOWED_CALLBACK_OBJECT_ACE>(p);

        auto lpszObjectTypeGuid = ConvertGuidToStringGuid(lpAce->ObjectType);
        auto lpszInheritedObjectTypeGuid = ConvertGuidToStringGuid(lpAce->InheritedObjectType);

        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Flags);

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_OBJECT_TYPE_PRESENT, TEXT("ACE_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_INHERITED_OBJECT_TYPE_PRESENT, TEXT("ACE_INHERITED_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->ObjectType: %s\n"), lpszPrefix, Idx, lpszObjectTypeGuid.c_str());
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->InheritedObjectType: %s\n"), lpszPrefix, Idx, lpszInheritedObjectTypeGuid.c_str());
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PACCESS_DENIED_CALLBACK_OBJECT_ACE>(p);

        auto lpszObjectTypeGuid = ConvertGuidToStringGuid(lpAce->ObjectType);
        auto lpszInheritedObjectTypeGuid = ConvertGuidToStringGuid(lpAce->InheritedObjectType);

        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Flags);

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_OBJECT_TYPE_PRESENT, TEXT("ACE_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_INHERITED_OBJECT_TYPE_PRESENT, TEXT("ACE_INHERITED_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->ObjectType: %s\n"), lpszPrefix, Idx, lpszObjectTypeGuid.c_str());
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->InheritedObjectType: %s\n"), lpszPrefix, Idx, lpszInheritedObjectTypeGuid.c_str());
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_AUDIT_CALLBACK_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_AUDIT_CALLBACK_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_ALARM_CALLBACK_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_ALARM_CALLBACK_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_AUDIT_CALLBACK_OBJECT_ACE>(p);

        auto lpszObjectTypeGuid = ConvertGuidToStringGuid(lpAce->ObjectType);
        auto lpszInheritedObjectTypeGuid = ConvertGuidToStringGuid(lpAce->InheritedObjectType);

        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Flags);

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_OBJECT_TYPE_PRESENT, TEXT("ACE_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_INHERITED_OBJECT_TYPE_PRESENT, TEXT("ACE_INHERITED_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->ObjectType: %s\n"), lpszPrefix, Idx, lpszObjectTypeGuid.c_str());
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->InheritedObjectType: %s\n"), lpszPrefix, Idx, lpszInheritedObjectTypeGuid.c_str());
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_ALARM_CALLBACK_OBJECT_ACE>(p);

        auto lpszObjectTypeGuid = ConvertGuidToStringGuid(lpAce->ObjectType);
        auto lpszInheritedObjectTypeGuid = ConvertGuidToStringGuid(lpAce->InheritedObjectType);

        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Flags);

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_OBJECT_TYPE_PRESENT, TEXT("ACE_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Flags   : (0x%.8x) %s\n"), lpszPrefix, Idx, ACE_INHERITED_OBJECT_TYPE_PRESENT, TEXT("ACE_INHERITED_OBJECT_TYPE_PRESENT"));
        }

        if (lpAce->Flags & ACE_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->ObjectType: %s\n"), lpszPrefix, Idx, lpszObjectTypeGuid.c_str());
        }

        if (lpAce->Flags & ACE_INHERITED_OBJECT_TYPE_PRESENT) {
            _tprintf_s(TEXT("%s    : ->Ace[%u]: ->InheritedObjectType: %s\n"), lpszPrefix, Idx, lpszInheritedObjectTypeGuid.c_str());
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_MANDATORY_LABEL_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAce = reinterpret_cast<PSYSTEM_MANDATORY_LABEL_ACE>(p);
        auto lpszSid = ResourceOwned(LocalAllocTraits<PTSTR>{});

        if (ConvertSidToStringSid(reinterpret_cast<PSID>(&lpAce->SidStart), lpszSid.GetAddressOf()) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }

        auto szName = ConvertSidToAccountName(reinterpret_cast<PSID>(&lpAce->SidStart));

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->Mask    : 0x%.8x\n"), lpszPrefix, Idx, lpAce->Mask);
        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->SID     : %s (%s)\n"), lpszPrefix, Idx, lpszSid.Get(), szName.c_str());
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        // todo
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_SCOPED_POLICY_ID_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        // todo
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        // todo
    }

    template<>
    static void DisplayAccessControlEntryBody<SYSTEM_ACCESS_FILTER_ACE_TYPE>(PVOID p, PCTSTR lpszPrefix, DWORD Idx) {
        // todo
    }

    void DisplayAccessControlEntryBody(PVOID lpAce, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAceHeader = reinterpret_cast<PACE_HEADER>(lpAce);
        switch (lpAceHeader->AceType) {
            case ACCESS_ALLOWED_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_ALLOWED_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case ACCESS_DENIED_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_DENIED_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_AUDIT_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_AUDIT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_ALARM_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_ALARM_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case ACCESS_ALLOWED_COMPOUND_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_ALLOWED_COMPOUND_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_ALLOWED_OBJECT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_DENIED_OBJECT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_AUDIT_OBJECT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_ALARM_OBJECT_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_ALARM_OBJECT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_ALLOWED_CALLBACK_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case ACCESS_DENIED_CALLBACK_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_DENIED_CALLBACK_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                DisplayAccessControlEntryBody<ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_AUDIT_CALLBACK_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_ALARM_CALLBACK_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_MANDATORY_LABEL_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_SCOPED_POLICY_ID_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            case SYSTEM_ACCESS_FILTER_ACE_TYPE:
                DisplayAccessControlEntryBody<SYSTEM_ACCESS_FILTER_ACE_TYPE>(lpAce, lpszPrefix, Idx);
                break;
            default:
                break;
        }
    }

}

