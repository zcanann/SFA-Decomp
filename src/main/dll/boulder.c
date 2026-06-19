#include "global.h"
#include "main/gameplay_runtime.h"



extern f32 lbl_803E5ED8;

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
    BoulderShakeRec* r = (BoulderShakeRec*)rec;

    r->histX0 = r->histX1;
    r->histY0 = r->histY1;
    r->histZ0 = r->histZ1;
    r->histX1 = r->histX2;
    r->histY1 = r->histY2;
    r->histZ1 = r->histZ2;
    r->histX2 = r->histX3;
    r->histY2 = r->histY3;
    r->histZ2 = r->histZ3;
    r->amplitude = lbl_803E5ED8 * (f32)(s32)randomGetRange(0xa0, 0xb4);
    r->histX3 = r->liveX;
    r->histY3 = r->liveY;
    r->histZ3 = r->liveZ;
}
