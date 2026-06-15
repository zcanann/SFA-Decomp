#include "main/dll/boulder.h"

extern u32 randomGetRange(int min, int max);

extern f32 lbl_803E5ED8;

/* Per-boulder shake record: three position-history rings (X/Y/Z, four
 * f32 deep) that scroll toward the live position triple at 0x34/0x38/0x3c
 * each tick, plus a randomized amplitude at 0x44. */
typedef struct BoulderShakeRec
{
    u8 pad0[0x04 - 0x00];
    f32 histX0;
    f32 histX1;
    f32 histX2;
    f32 histX3;
    f32 histY0;
    f32 histY1;
    f32 histY2;
    f32 histY3;
    f32 histZ0;
    f32 histZ1;
    f32 histZ2;
    f32 histZ3;
    f32 liveX;
    f32 liveY;
    f32 liveZ;
    u8 pad40[0x44 - 0x40];
    f32 amplitude;
} BoulderShakeRec;

STATIC_ASSERT(offsetof(BoulderShakeRec, histX0) == 0x04);
STATIC_ASSERT(offsetof(BoulderShakeRec, histY0) == 0x14);
STATIC_ASSERT(offsetof(BoulderShakeRec, histZ0) == 0x24);
STATIC_ASSERT(offsetof(BoulderShakeRec, liveX) == 0x34);
STATIC_ASSERT(offsetof(BoulderShakeRec, amplitude) == 0x44);

void fn_801F4ECC(int obj, u8* rec)
{
    ((BoulderShakeRec*)rec)->histX0 = ((BoulderShakeRec*)rec)->histX1;
    ((BoulderShakeRec*)rec)->histY0 = ((BoulderShakeRec*)rec)->histY1;
    ((BoulderShakeRec*)rec)->histZ0 = ((BoulderShakeRec*)rec)->histZ1;
    ((BoulderShakeRec*)rec)->histX1 = ((BoulderShakeRec*)rec)->histX2;
    ((BoulderShakeRec*)rec)->histY1 = ((BoulderShakeRec*)rec)->histY2;
    ((BoulderShakeRec*)rec)->histZ1 = ((BoulderShakeRec*)rec)->histZ2;
    ((BoulderShakeRec*)rec)->histX2 = ((BoulderShakeRec*)rec)->histX3;
    ((BoulderShakeRec*)rec)->histY2 = ((BoulderShakeRec*)rec)->histY3;
    ((BoulderShakeRec*)rec)->histZ2 = ((BoulderShakeRec*)rec)->histZ3;
    ((BoulderShakeRec*)rec)->amplitude =
        lbl_803E5ED8 * (f32)(s32)
    randomGetRange(0xa0, 0xb4);
    ((BoulderShakeRec*)rec)->histX3 = ((BoulderShakeRec*)rec)->liveX;
    ((BoulderShakeRec*)rec)->histY3 = ((BoulderShakeRec*)rec)->liveY;
    ((BoulderShakeRec*)rec)->histZ3 = ((BoulderShakeRec*)rec)->liveZ;
}
