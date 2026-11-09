// Host stand-ins for the Cortex-M4 DSP intrinsics the baseband DSP uses (ARM ARM semantics).
#pragma once
#include <cstdint>
#include <cstddef>
#ifndef __STATIC_INLINE
#define __STATIC_INLINE static inline
#endif
#define __SIMD32_TYPE int32_t
#define __SIMD32(addr) (*(__SIMD32_TYPE**)&(addr))
#define _SIMD32_OFFSET(addr) (*(__SIMD32_TYPE*)(addr))
static inline int16_t lo16(uint32_t x) { return (int16_t)(x & 0xFFFF); }
static inline int16_t hi16(uint32_t x) { return (int16_t)(x >> 16); }
static inline uint32_t pack16(int32_t lo, int32_t hi) { return ((uint32_t)(uint16_t)lo) | ((uint32_t)(uint16_t)hi << 16); }
static inline uint32_t ror32(uint32_t x, uint32_t r) { r &= 31; return r ? (x >> r) | (x << (32 - r)) : x; }
static inline int32_t sat16(int32_t v) { return v > 32767 ? 32767 : (v < -32768 ? -32768 : v); }
static inline int32_t __SSAT(int32_t v, uint32_t bits) { const int32_t mx = (1 << (bits - 1)) - 1, mn = -(1 << (bits - 1)); return v > mx ? mx : (v < mn ? mn : v); }
static inline uint32_t __USAT(int32_t v, uint32_t bits) { const int32_t mx = (1 << bits) - 1; return v < 0 ? 0 : (v > mx ? mx : v); }
static inline uint32_t __PKHBT(uint32_t a, uint32_t b, uint32_t sh) { return (a & 0xFFFF) | ((b << sh) & 0xFFFF0000u); }
static inline uint32_t __PKHTB(uint32_t a, uint32_t b, uint32_t sh) { return (a & 0xFFFF0000u) | (((uint32_t)((int32_t)b >> sh)) & 0xFFFF); }
static inline uint32_t __QADD16(uint32_t a, uint32_t b) { return pack16(sat16(lo16(a) + lo16(b)), sat16(hi16(a) + hi16(b))); }
static inline uint32_t __QSUB16(uint32_t a, uint32_t b) { return pack16(sat16(lo16(a) - lo16(b)), sat16(hi16(a) - hi16(b))); }
static inline int32_t __SMUAD(uint32_t a, uint32_t b) { return lo16(a) * lo16(b) + hi16(a) * hi16(b); }
static inline int32_t __SMUADX(uint32_t a, uint32_t b) { return lo16(a) * hi16(b) + hi16(a) * lo16(b); }
static inline int32_t __SMUSD(uint32_t a, uint32_t b) { return lo16(a) * lo16(b) - hi16(a) * hi16(b); }
static inline int32_t __SMUSDX(uint32_t a, uint32_t b) { return lo16(a) * hi16(b) - hi16(a) * lo16(b); }
static inline int32_t __SMLAD(uint32_t a, uint32_t b, int32_t acc) { return acc + __SMUAD(a, b); }
static inline int32_t __SMLADX(uint32_t a, uint32_t b, int32_t acc) { return acc + __SMUADX(a, b); }
static inline int64_t __SMLALD(uint32_t a, uint32_t b, int64_t acc) { return acc + (int64_t)lo16(a) * lo16(b) + (int64_t)hi16(a) * hi16(b); }
static inline int64_t __SMLALDX(uint32_t a, uint32_t b, int64_t acc) { return acc + (int64_t)lo16(a) * hi16(b) + (int64_t)hi16(a) * lo16(b); }
static inline int64_t __SMLSLD(uint32_t a, uint32_t b, int64_t acc) { return acc + (int64_t)lo16(a) * lo16(b) - (int64_t)hi16(a) * hi16(b); }
static inline int32_t __SMLABB(uint32_t a, uint32_t b, int32_t acc) { return acc + lo16(a) * lo16(b); }
static inline int32_t __SMLATB(uint32_t a, uint32_t b, int32_t acc) { return acc + hi16(a) * lo16(b); }
static inline int32_t __SMLABT(uint32_t a, uint32_t b, int32_t acc) { return acc + lo16(a) * hi16(b); }
static inline int32_t __SMLATT(uint32_t a, uint32_t b, int32_t acc) { return acc + hi16(a) * hi16(b); }
static inline int32_t __SMULBB(uint32_t a, uint32_t b) { return lo16(a) * lo16(b); }
static inline int32_t __SMULTB(uint32_t a, uint32_t b) { return hi16(a) * lo16(b); }
static inline int32_t __SMULBT(uint32_t a, uint32_t b) { return lo16(a) * hi16(b); }
static inline int32_t __SMULTT(uint32_t a, uint32_t b) { return hi16(a) * hi16(b); }
static inline int32_t __SMMULR(int32_t a, int32_t b) { return (int32_t)(((int64_t)a * b + 0x80000000LL) >> 32); }
static inline uint32_t __SXTB16(uint32_t x, uint32_t r) { const uint32_t y = ror32(x, r); return pack16((int8_t)(y & 0xFF), (int8_t)((y >> 16) & 0xFF)); }
static inline int32_t __SXTH(uint32_t x, uint32_t r) { return (int16_t)(ror32(x, r) & 0xFFFF); }
static inline int32_t __SXTAH(uint32_t a, uint32_t x, uint32_t r) { return (int32_t)a + (int16_t)(ror32(x, r) & 0xFFFF); }
static inline uint32_t __BFI(uint32_t rd, uint32_t rn, uint32_t lsb, uint32_t width) { const uint32_t m = ((width >= 32) ? 0xFFFFFFFFu : ((1u << width) - 1)) << lsb; return (rd & ~m) | ((rn << lsb) & m); }
static inline uint32_t __REV16(uint32_t x) { return ((x & 0xFF00FF00u) >> 8) | ((x & 0x00FF00FFu) << 8); }
static inline uint32_t __REV(uint32_t x) { return __builtin_bswap32(x); }
static inline uint32_t __SADD16(uint32_t a, uint32_t b) { return pack16(lo16(a) + lo16(b), hi16(a) + hi16(b)); }
static inline uint32_t __SSUB16(uint32_t a, uint32_t b) { return pack16(lo16(a) - lo16(b), hi16(a) - hi16(b)); }
static inline uint32_t __SHADD16(uint32_t a, uint32_t b) { return pack16((lo16(a) + lo16(b)) >> 1, (hi16(a) + hi16(b)) >> 1); }
static inline uint32_t __SHSUB16(uint32_t a, uint32_t b) { return pack16((lo16(a) - lo16(b)) >> 1, (hi16(a) - hi16(b)) >> 1); }
static inline uint32_t __QASX(uint32_t a, uint32_t b) { return pack16(sat16(lo16(a) - hi16(b)), sat16(hi16(a) + lo16(b))); }
static inline uint32_t __QSAX(uint32_t a, uint32_t b) { return pack16(sat16(lo16(a) + hi16(b)), sat16(hi16(a) - lo16(b))); }
static inline uint32_t __SXTAB16(uint32_t a, uint32_t x) { return pack16(lo16(a) + (int8_t)(x & 0xFF), hi16(a) + (int8_t)((x >> 16) & 0xFF)); }
static inline int32_t __SMLSD(uint32_t a, uint32_t b, int32_t acc) { return acc + lo16(a) * lo16(b) - hi16(a) * hi16(b); }
