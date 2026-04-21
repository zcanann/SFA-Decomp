#ifndef GHIDRA_IMPORT_H
#define GHIDRA_IMPORT_H

#include "types.h"

#ifndef __cplusplus
typedef int bool;
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif
#endif

typedef u8 undefined;
typedef u8 undefined1;
typedef u16 undefined2;
typedef u32 undefined4;
typedef u64 undefined8;

typedef s8 sbyte;
typedef u8 byte;
typedef u16 ushort;
typedef u32 uint;
typedef unsigned long ulong;
typedef s64 longlong;
typedef u64 ulonglong;

typedef void (*code)();

#define CONCAT11(x, y) ((u16)(((u16)(u8)(x) << 8) | (u8)(y)))
#define CONCAT12(x, y) ((u32)(((u32)(u8)(x) << 16) | (u16)(y)))
#define CONCAT13(x, y) ((u32)(((u32)(u8)(x) << 24) | (u32)(y)))
#define CONCAT14(x, y) ((u64)(((u64)(u8)(x) << 32) | (u32)(y)))
#define CONCAT21(x, y) ((u32)(((u32)(u16)(x) << 8) | (u8)(y)))
#define CONCAT22(x, y) ((u32)(((u32)(u16)(x) << 16) | (u16)(y)))
#define CONCAT23(x, y) ((u64)(((u64)(u16)(x) << 24) | (u32)(y)))
#define CONCAT24(x, y) ((u64)(((u64)(u16)(x) << 32) | (u32)(y)))
#define CONCAT31(x, y) ((u32)(((u32)(x) << 8) | (u8)(y)))
#define CONCAT32(x, y) ((u64)(((u64)(u32)(x) << 16) | (u16)(y)))
#define CONCAT41(x, y) ((u64)(((u64)(u32)(x) << 8) | (u8)(y)))
#define CONCAT42(x, y) ((u64)(((u64)(u32)(x) << 16) | (u16)(y)))
#define CONCAT43(x, y) ((u64)(((u64)(u32)(x) << 24) | (u32)(y)))
#define CONCAT44(x, y) ((u64)(((u64)(u32)(x) << 32) | (u32)(y)))

static inline u32 CARRY4(u32 x, u32 y) {
    return (u32)(x + y) < x;
}

static inline s32 SCARRY4(s32 x, s32 y) {
    s32 sum = x + y;
    return ((x < 0) == (y < 0)) && ((sum < 0) != (x < 0));
}

static inline s32 SBORROW4(s32 x, s32 y) {
    s32 diff = x - y;
    return ((x < 0) != (y < 0)) && ((diff < 0) != (x < 0));
}

#endif
