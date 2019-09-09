#include <tchar.h>
#include <windows.h>
#include <stdexcept>

namespace sddldisplay {

    void DisplayAccessControlEntryHeader(PVOID lpAce, PCTSTR lpszPrefix, DWORD Idx) {
        auto lpAceHeader = reinterpret_cast<PACE_HEADER>(lpAce);
        switch (lpAceHeader->AceType) {
#define ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(pref, i, t) case t: _tprintf_s(TEXT("%s    : ->Ace[%u]: ->AceType : 0x%.2x (%s)\n"), pref, Idx, t, TEXT(#t)); break
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_ALLOWED_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_DENIED_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_AUDIT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_ALARM_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_ALLOWED_COMPOUND_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_ALLOWED_OBJECT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_DENIED_OBJECT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_AUDIT_OBJECT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_ALARM_OBJECT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_ALLOWED_CALLBACK_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_DENIED_CALLBACK_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_AUDIT_CALLBACK_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_ALARM_CALLBACK_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_MANDATORY_LABEL_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_SCOPED_POLICY_ID_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE);
            ACCESS_CONTROL_ENTRY_DISPLAY_TYPE(lpszPrefix, Idx, SYSTEM_ACCESS_FILTER_ACE_TYPE);
            default: throw std::invalid_argument("Unknown AceType.");
#undef ACCESS_CONTROL_ENTRY_DISPLAY_TYPE
        }

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->AceFlags: 0x%.2x\n"), lpszPrefix, Idx, lpAceHeader->AceFlags);

#define ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(p, v, f) if (((v) & (f)) != 0) _tprintf_s(TEXT("%*c: (0x%.2x) %s\n"), p, TEXT(' '), f, TEXT(#f))
        int padding = _sctprintf(TEXT("%s    : ->Ace[%u]: ->AceFlags"), lpszPrefix, Idx);
        ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, OBJECT_INHERIT_ACE);
        ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, CONTAINER_INHERIT_ACE);
        ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, NO_PROPAGATE_INHERIT_ACE);
        ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, INHERIT_ONLY_ACE);
        ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, INHERITED_ACE);

        if (lpAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, CRITICAL_ACE_FLAG);
        }

        switch (lpAceHeader->AceType) {
            case SYSTEM_AUDIT_ACE_TYPE:
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            case SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
            case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
            case SYSTEM_ALARM_ACE_TYPE:
            case SYSTEM_ALARM_OBJECT_ACE_TYPE:
            case SYSTEM_ALARM_CALLBACK_ACE_TYPE:
            case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
                ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, SUCCESSFUL_ACCESS_ACE_FLAG);
                ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, FAILED_ACCESS_ACE_FLAG);
            default:
                break;
        }

        if (lpAceHeader->AceType == SYSTEM_ACCESS_FILTER_ACE_TYPE) {
            ACCESS_CONTROL_ENTRY_DISPLAY_FLAG(padding, lpAceHeader->AceFlags, TRUST_PROTECTED_FILTER_ACE_FLAG);
        }
#undef ACCESS_CONTROL_ENTRY_DISPLAY_FLAG

        _tprintf_s(TEXT("%s    : ->Ace[%u]: ->AceSize : 0x%x\n"), lpszPrefix, Idx, lpAceHeader->AceSize);
    }

}

