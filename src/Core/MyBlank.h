#pragma once
#include <type_traits>
namespace myblank {

struct blank
{
};

// type traits specializations
//
template <class T>
struct is_pod
    : std::integral_constant<bool, false>
{
};

template <>
struct is_pod< blank >
    : std::integral_constant<bool, true>
{
};

template <class T>
struct is_empty
    : std::integral_constant<bool, false>
{
};

template <>
struct is_empty< blank >
    : std::integral_constant<bool, true>
{
};

template <class T>
struct is_stateless
    : std::integral_constant<bool, false>
{
};

template <>
struct is_stateless< blank >
    : std::integral_constant<bool, true>
{
};

// relational operators
//

inline bool operator==(const blank&, const blank&)
{
    return true;
}

inline bool operator<=(const blank&, const blank&)
{
    return true;
}

inline bool operator>=(const blank&, const blank&)
{
    return true;
}

inline bool operator!=(const blank&, const blank&)
{
    return false;
}

inline bool operator<(const blank&, const blank&)
{
    return false;
}

inline bool operator>(const blank&, const blank&)
{
    return false;
}

} // namespace myblank
