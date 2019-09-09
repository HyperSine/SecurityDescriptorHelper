#include <windows.h>
#include <xstring.hpp>

namespace sddldisplay {

    std::xstring ConvertGuidToStringGuid(const GUID& Guid) {
        return std::xstring::format(
            TEXT("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"),
            Guid.Data1, 
            Guid.Data2, 
            Guid.Data3,
            Guid.Data4[0], 
            Guid.Data4[1], 
            Guid.Data4[2],
            Guid.Data4[3], 
            Guid.Data4[4], 
            Guid.Data4[5],
            Guid.Data4[6], 
            Guid.Data4[7]
        );
    }

}

