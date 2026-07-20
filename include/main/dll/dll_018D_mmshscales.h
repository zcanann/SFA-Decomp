#ifndef MAIN_DLL_DLL_018D_MMSHSCALES_H_
#define MAIN_DLL_DLL_018D_MMSHSCALES_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct MmshScalesState
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x14 - 0x10];
    s32 unk14;
    u8 pad18[0x24 - 0x18];
    f32 dampingFactor; /* 0x24: base/(base + def[36]) smoothing coefficient */
    s32 unk28;
    u8 pad2C[0x57 - 0x2C];
    s8 groupTag;
    u8 pad58[0x6A - 0x58];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x140 - 0x70];
} MmshScalesState;

typedef struct MmshScalesPlacement
{
    ObjPlacement base;
    s16 animationBank;
    s16 sequenceTag;
    u8 pad1C[0x24 - 0x1C];
    u8 damping;
} MmshScalesPlacement;

/* 0x24-byte spawn descriptor handed to Obj_SetupObject for the child
 * object. ObjPlacement-style head (color block + position). */
typedef struct MmshScalesSpawnSetup
{
    ObjPlacement base;
    u8 pad18[0x24 - 0x18];
} MmshScalesSpawnSetup;

STATIC_ASSERT(offsetof(MmshScalesState, groupTag) == 0x57);
STATIC_ASSERT(offsetof(MmshScalesState, unk6A) == 0x6A);
STATIC_ASSERT(sizeof(MmshScalesState) == 0x140);
STATIC_ASSERT(offsetof(MmshScalesPlacement, animationBank) == 0x18);
STATIC_ASSERT(offsetof(MmshScalesPlacement, sequenceTag) == 0x1A);
STATIC_ASSERT(offsetof(MmshScalesPlacement, damping) == 0x24);
STATIC_ASSERT(sizeof(MmshScalesSpawnSetup) == 0x24);

int MMSH_Scales_getExtraSize(void);
int MMSH_Scales_getObjectTypeId(void);
void MMSH_Scales_free(GameObject* obj, int keepChild);
void MMSH_Scales_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void MMSH_Scales_hitDetect(void);
void MMSH_Scales_update(GameObject* obj);
void MMSH_Scales_init(GameObject* obj, MmshScalesPlacement* placement);
void MMSH_Scales_release(void);
void MMSH_Scales_initialise(void);

#endif /* MAIN_DLL_DLL_018D_MMSHSCALES_H_ */
