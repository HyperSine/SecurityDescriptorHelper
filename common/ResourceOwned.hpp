#pragma once
#include <type_traits>
#include <utility>

template<typename __Traits, typename __Deleter = void>
class ResourceOwned {
public:

    using TraitsType = __Traits;
    using HandleType = typename __Traits::HandleType;
    using DeleterType = __Deleter;

    static_assert(std::is_pod_v<HandleType>);

private:

    HandleType  _Handle;
    DeleterType _Deleter;

public:

    //
    // Construct from custom deleter.
    // Internal handle value will be initialized by `__Traits::InvalidValue`.
    //
    template<typename __DeleterArg>
    ResourceOwned(__DeleterArg&& Deleter) noexcept :
        _Handle(TraitsType::InvalidValue),
        _Deleter(std::forward<__DeleterArg>(Deleter)) {}

    //
    // Construct from handle given and custom deleter.
    //
    template<typename __DeleterArg>
    ResourceOwned(const HandleType& Handle, __DeleterArg&& Deleter) noexcept :
        _Handle(Handle),
        _Deleter(std::forward<__DeleterArg>(Deleter)) {}

    //
    // Construct from custom deleter with hint of traits.
    // Internal handle value will be initialized by `__Traits::InvalidValue`.
    //
    template<typename __DeleterArg>
    ResourceOwned(TraitsType, __DeleterArg&& Deleter) noexcept :
        _Handle(TraitsType::InvalidValue),
        _Deleter(std::forward<__DeleterArg>(Deleter)) {}

    //
    // Construct from handle given and custom deleter with hint of traits.
    //
    template<typename __DeleterArg>
    ResourceOwned(TraitsType, const HandleType& Handle, __DeleterArg&& Deleter) noexcept :
        _Handle(Handle),
        _Deleter(std::forward<__DeleterArg>(Deleter)) {}

    //
    // ResourceOwned doesn't allow copy.
    // Because it holds handle exclusively.
    //
    ResourceOwned(const ResourceOwned<__Traits, __Deleter>& Other) = delete;

    //
    // ResourceOwned allows to move.
    //
    ResourceOwned(ResourceOwned<__Traits, __Deleter>&& Other) noexcept :
        _Handle(std::move(Other._Handle)),
        _Deleter(std::move(Other._Deleter)) { Other._Handle = TraitsType::InvalidValue; }

    //
    // ResourceOwned doesn't allow copy.
    // Because it holds handle exclusively.
    //
    ResourceOwned<__Traits, __Deleter>& operator=(const ResourceOwned<__Traits, __Deleter>& Other) = delete;

    //
    // ResourceOwned allows to move.
    //
    ResourceOwned<__Traits, __Deleter>& operator=(ResourceOwned<__Traits, __Deleter>&& Other) noexcept {
        _Handle = std::move(Other._Handle);
        _Deleter = std::move(Other._Deleter);
        Other._Handle = TraitsType::InvalidValue;
        return *this;
    }

    //
    // Act like handle itself.
    //
    [[nodiscard]]
    operator HandleType() const noexcept { // NOLINT: Allow implicit conversion.
        return _Handle;
    }

    //
    // If handle is a pointer, allow to be casted to another pointer type.
    //
    template<typename __AsPtrType, typename = std::enable_if_t<std::is_pointer_v<HandleType>>>
    [[nodiscard]]
    __AsPtrType As() const noexcept {
        static_assert(std::is_pointer_v<__AsPtrType>);
        return reinterpret_cast<__AsPtrType>(_Handle);
    }

    //
    // If handle is a pointer, enable operator->.
    //
    template<typename = std::enable_if_t<std::is_pointer_v<HandleType>>>
    [[nodiscard]]
    HandleType operator->() const noexcept {
        return _Handle;
    }

    //
    // Check if handle is valid.
    //
    [[nodiscard]]
    bool IsValid() const noexcept {
        return TraitsType::IsValid(_Handle);
    }

    //
    // Get handle explicitly.
    //
    [[nodiscard]]
    const HandleType& Get() const noexcept {
        return _Handle;
    }

    //
    // Get address of handle. this function is designed for functions that receive arguments whose type is `HandleType*`.
    // Use it if and only if `IsValid() == false`.
    //
    template<typename __ReturnType = HandleType*>
    [[nodiscard]]
    __ReturnType GetAddressOf() noexcept {
        return reinterpret_cast<__ReturnType>(&_Handle);
    }

    void TakeOver(const HandleType& Handle) {
        if (IsValid()) {
            _Deleter(_Handle);
        }
        _Handle = Handle;
    }

    void Discard() noexcept {
        _Handle = TraitsType::InvalidValue;
    }

    [[nodiscard]]
    HandleType Transfer() noexcept {
        HandleType t = std::move(_Handle);
        _Handle = TraitsType::InvalidValue;
        return t;
    }

    void Release() {
        if (IsValid()) {
            _Deleter(_Handle);
            _Handle = TraitsType::InvalidValue;
        }
    }

    //
    // Release then get address of handle. 
    // This function is designed for functions that receive arguments whose type is `HandleType*`.
    //
    template<typename __ReturnType = HandleType*>
    [[nodiscard]]
    __ReturnType ReleaseAndGetAddressOf() {
        Release();
        return reinterpret_cast<__ReturnType>(&_Handle);
    }

    ~ResourceOwned() {
        Release();
    }
};

template<typename __Traits>
class ResourceOwned<__Traits, void> {
public:

    using TraitsType = __Traits;
    using HandleType = typename __Traits::HandleType;
    using DeleterType = decltype(__Traits::Release);

    static_assert(std::is_pod_v<HandleType>);

private:

    HandleType _Handle;

public:

    //
    // Internal handle value will be initialized by `__Traits::InvalidValue`.
    //
    ResourceOwned() noexcept :
        _Handle(TraitsType::InvalidValue) {}

    //
    // Construct from handle given.
    //
    ResourceOwned(const HandleType& Handle) noexcept :
        _Handle(Handle) {}

    //
    // Construct with hint of traits.
    // Internal handle value will be initialized by `__Traits::InvalidValue`.
    //
    explicit ResourceOwned(TraitsType) noexcept :
        _Handle(TraitsType::InvalidValue) {}

    //
    // Construct from handle given with hint of traits.
    //
    ResourceOwned(TraitsType, const HandleType& Handle) noexcept :
        _Handle(Handle) {}

    //
    // ResourceOwned doesn't allow copy.
    // Because it holds handle exclusively.
    //
    ResourceOwned(const ResourceOwned<__Traits, void>& Other) = delete;

    //
    // ResourceOwned allows to move.
    //
    ResourceOwned(ResourceOwned<__Traits, void>&& Other) noexcept :
        _Handle(std::move(Other._Handle)) { Other._Handle = TraitsType::InvalidValue; }

    //
    // ResourceOwned doesn't allow copy.
    // Because it holds handle exclusively.
    //
    ResourceOwned<__Traits, void>& operator=(const ResourceOwned<__Traits, void>& Other) = delete;

    //
    // ResourceOwned allows to move.
    //
    ResourceOwned<__Traits, void>& operator=(ResourceOwned<__Traits, void>&& Other) noexcept {
        _Handle = std::move(Other._Handle);
        Other._Handle = TraitsType::InvalidValue;
        return *this;
    }

    //
    // Act like handle itself.
    //
    [[nodiscard]]
    operator HandleType() const noexcept { // NOLINT: Allow implicit conversion.
        return _Handle;
    }

    //
    // If handle is a pointer, allow to be casted to another pointer type.
    //
    template<typename __AsPtrType, typename = std::enable_if_t<std::is_pointer_v<HandleType>>>
    [[nodiscard]]
    __AsPtrType As() const noexcept {
        static_assert(std::is_pointer_v<__AsPtrType>);
        return reinterpret_cast<__AsPtrType>(_Handle);
    }

    //
    // If handle is a pointer, enable operator->.
    //
    template<typename = std::enable_if_t<std::is_pointer_v<HandleType>>>
    [[nodiscard]]
    HandleType operator->() const noexcept {
        return _Handle;
    }

    //
    // Check if handle is valid.
    //
    [[nodiscard]]
    bool IsValid() const noexcept {
        return TraitsType::IsValid(_Handle);
    }

    //
    // Get handle explicitly.
    //
    [[nodiscard]]
    const HandleType& Get() const noexcept {
        return _Handle;
    }

    //
    // Get address of handle. this function is designed for functions that receive arguments whose type is `HandleType*`.
    // Use it if and only if `IsValid() == false`.
    //
    template<typename __ReturnType = HandleType*>
    [[nodiscard]]
    __ReturnType GetAddressOf() noexcept {
        return reinterpret_cast<__ReturnType>(&_Handle);
    }

    void TakeOver(const HandleType& Handle) {
        if (IsValid()) {
            TraitsType::Release(_Handle);
        }
        _Handle = Handle;
    }

    void Discard() noexcept {
        _Handle = TraitsType::InvalidValue;
    }

    [[nodiscard]]
    HandleType Transfer() noexcept {
        HandleType t = _Handle;
        _Handle = TraitsType::InvalidValue;
        return t;
    }

    void Release() {
        if (IsValid()) {
            TraitsType::Release(_Handle);
            _Handle = TraitsType::InvalidValue;
        }
    }

    //
    // Release then get address of handle. 
    // This function is designed for functions that receive arguments whose type is `HandleType*`.
    //
    template<typename __ReturnType = HandleType*>
    [[nodiscard]]
    __ReturnType ReleaseAndGetAddressOf() {
        Release();
        return reinterpret_cast<__ReturnType>(&_Handle);
    }

    ~ResourceOwned() {
        Release();
    }
};

//
// ResourceOwned deduce guide
//

template<typename __Traits>
ResourceOwned(__Traits) ->
    ResourceOwned<__Traits, void>;

template<typename __Traits, typename __ArgType>
ResourceOwned(__Traits, __ArgType&&) ->
    ResourceOwned<
        __Traits,
        std::conditional_t<
            std::is_same_v<std::remove_cv_t<std::remove_reference_t<__ArgType>>, typename __Traits::HandleType>,
            void,
            std::remove_cv_t<std::remove_reference_t<__ArgType>>
        >
    >;

template<typename __Traits, typename __DeleterArg>
ResourceOwned(__Traits, const typename __Traits::HandleType&, __DeleterArg&&) ->
    ResourceOwned<
        __Traits, 
        std::remove_cv_t<std::remove_reference_t<__DeleterArg>>
    >;

template<typename __ClassType>
struct CppObjectTraits {
    using HandleType = __ClassType*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Release(HandleType& Handle) {
        delete Handle;
    }
};

template<typename __Type>
struct CppDynamicArrayTraits {
    using HandleType = __Type*;

    static inline const HandleType InvalidValue = nullptr;

    [[nodiscard]]
    static bool IsValid(const HandleType& Handle) noexcept {
        return Handle != InvalidValue;
    }

    static void Release(HandleType& Handle) {
        delete[] Handle;
    }
};

