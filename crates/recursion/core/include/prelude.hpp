#pragma once

#include "monerochan-recursion-core-sys-cbindgen.hpp"

#ifndef __CUDACC__
#define __MONEROCHAN_HOSTDEV__
#define __MONEROCHAN_INLINE__ inline
#include <array>

namespace monerochan_recursion_core_sys {
template <class T, std::size_t N>
using array_t = std::array<T, N>;
}  // namespace monerochan_recursion_core_sys
#else
#define __MONEROCHAN_HOSTDEV__ __host__ __device__
#define __MONEROCHAN_INLINE__ __forceinline__
#include <cuda/std/array>

namespace monerochan_recursion_core_sys {
template <class T, std::size_t N>
using array_t = cuda::std::array<T, N>;
}  // namespace monerochan_recursion_core_sys
#endif
