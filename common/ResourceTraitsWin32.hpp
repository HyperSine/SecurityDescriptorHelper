#pragma once
#include <windows.h>
#include <system_error>
#include <type_traits>

struct GenericHandleTraits {
    using HandleType = HANDLE;

    static inline const HandleType InvalidValue = NULL;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Release(_In_ HandleType& Handle) {
        if (CloseHandle(Handle) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }
    }
};

template<typename __PtrType>
struct HeapAllocTraits {
    static_assert(std::is_pointer_v<__PtrType>);

    using HandleType = __PtrType;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Release(_In_ HandleType& Handle) {
        if (HeapFree(GetProcessHeap(), 0, Handle) == FALSE) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }
    }
};

template<typename __PtrType>
struct LocalAllocTraits {
    static_assert(std::is_pointer_v<__PtrType>);

    using HandleType = __PtrType;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Release(_In_ HandleType& Handle) {
        if (LocalFree(Handle) != NULL) {
            auto err = GetLastError();
            throw std::system_error(err, std::system_category());
        }
    }
};

template<typename __PtrType>
struct CoTaskMemAllocTraits {
    static_assert(std::is_pointer_v<__PtrType>);

    using HandleType = __PtrType;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Release(_In_ HandleType& Handle) noexcept {
        CoTaskMemFree(Handle);
    }
};

