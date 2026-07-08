#ifndef MAIN_DLL_DLL_018D_MMSHSCALES_H_
#define MAIN_DLL_DLL_018D_MMSHSCALES_H_

#include "global.h"

typedef struct MmshScalesState
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x14 - 0x10];
    s32 unk14;
    u8 pad18[0x24 - 0x18];
    f32 dampingFactor; /* 0x24: base/(base + def[36]) smoothing coefficient */
    s32 unk28;
    u8 pad2C[0x6A - 0x2C];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x140 - 0x70];
} MmshScalesState;

/* 0x24-byte spawn descriptor handed to Obj_SetupObject for the child
 * object. ObjPlacement-style head (color block + position). */
typedef struct MmshScalesSpawnSetup
{
    u8 pad0[4];  /* 0x00 */
    u8 color[4]; /* 0x04 */
    f32 posX;    /* 0x08 */
    f32 posY;    /* 0x0c */
    f32 posZ;    /* 0x10 */
    u8 pad14[0x24 - 0x14];
} MmshScalesSpawnSetup;

STATIC_ASSERT(offsetof(MmshScalesSpawnSetup, posX) == 0x8);
STATIC_ASSERT(sizeof(MmshScalesSpawnSetup) == 0x24);

int MMSH_Scales_getExtraSize(void);
int MMSH_Scales_getObjectTypeId(void);
void MMSH_Scales_free(int obj, int keepChild);
void MMSH_Scales_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MMSH_Scales_hitDetect(void);
void MMSH_Scales_update(int objArg);
void MMSH_Scales_init(int* obj, s16* def);
void MMSH_Scales_release(void);
void MMSH_Scales_initialise(void);

#endif /* MAIN_DLL_DLL_018D_MMSHSCALES_H_ */
