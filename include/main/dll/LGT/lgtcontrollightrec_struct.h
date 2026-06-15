#ifndef MAIN_DLL_LGT_LGTCONTROLLIGHTREC_STRUCT_H_
#define MAIN_DLL_LGT_LGTCONTROLLIGHTREC_STRUCT_H_

#include "global.h"

/* Per-firefly control record managed by lgtcontrollight (fn_801F4C28 init,
 * fn_801F4D54 update). File-local layout recovered from constant-offset
 * derefs off the u8* record base. */
typedef struct LgtFireFlyRec {
    u8 unk00[4];     /* 0x00 */
    f32 src0X;       /* 0x04 */
    f32 src1X;       /* 0x08 */
    f32 src2X;       /* 0x0C */
    f32 src3X;       /* 0x10 */
    f32 src0Y;       /* 0x14 */
    f32 src1Y;       /* 0x18 */
    f32 src2Y;       /* 0x1C */
    f32 src3Y;       /* 0x20 */
    f32 src0Z;       /* 0x24 */
    f32 src1Z;       /* 0x28 */
    f32 src2Z;       /* 0x2C */
    f32 src3Z;       /* 0x30 */
    f32 offX;        /* 0x34 */
    f32 offY;        /* 0x38 */
    f32 offZ;        /* 0x3C */
    f32 baseZ;       /* 0x40 */
    f32 baseX;       /* 0x44 */
    f32 baseY;       /* 0x48 */
    f32 radiusMin;   /* 0x4C */
    f32 radius;      /* 0x50 */
    f32 posX;        /* 0x54 */
    f32 posY;        /* 0x58 */
    f32 posZ;        /* 0x5C */
    s16 angle;       /* 0x60 */
    s16 angleStep;   /* 0x62 */
    s16 ampMax;      /* 0x64 */
    u8 unk66;        /* 0x66 */
    u8 unk67;        /* 0x67 */
    u8 unk68;        /* 0x68 */
    u8 unk69[2];     /* 0x69 */
    u8 firstFrame;   /* 0x6B */
    u8 unk6C[12];    /* 0x6C */
    f32 unk78;       /* 0x78 */
} LgtFireFlyRec;

STATIC_ASSERT(offsetof(LgtFireFlyRec, src0X) == 0x04);
STATIC_ASSERT(offsetof(LgtFireFlyRec, offX) == 0x34);
STATIC_ASSERT(offsetof(LgtFireFlyRec, radius) == 0x50);
STATIC_ASSERT(offsetof(LgtFireFlyRec, angle) == 0x60);
STATIC_ASSERT(offsetof(LgtFireFlyRec, firstFrame) == 0x6B);
STATIC_ASSERT(offsetof(LgtFireFlyRec, unk78) == 0x78);

#endif /* MAIN_DLL_LGT_LGTCONTROLLIGHTREC_STRUCT_H_ */
