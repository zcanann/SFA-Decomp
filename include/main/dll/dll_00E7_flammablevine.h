#ifndef MAIN_DLL_DLL_00E7_FLAMMABLEVINE_H_
#define MAIN_DLL_DLL_00E7_FLAMMABLEVINE_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct FlammableVinePlacement
{
    ObjPlacement base;
    s8 rotXByte;    /* 0x18: rotX in 1/256 turns */
    u8 setupParam;  /* 0x19: copied to state, 1 = position-dirty */
    s16 scaleParam; /* 0x1A: drives rootMotionScale */
    s16 unk1C;
    s16 burnedBit; /* 0x1E: game bit set when burned; -1 = none */
    s16 gateBit;   /* 0x20: game bit gating use; -1 = none */
    u8 pad22[0x28 - 0x22];
} FlammableVinePlacement;

typedef struct TrickyIfaceVtbl
{
    u8 pad0[0x28 - 0x0];
    void (*slot28)(GameObject* tricky, GameObject* target, s32 enabled, s32 command); /* 0x28 */
} TrickyIfaceVtbl;

typedef struct TrickyIface
{
    TrickyIfaceVtbl* vtbl; /* 0x0 */
} TrickyIface;

typedef struct FlammableVineState
{
    u8 flags;      /* 0x0: bit0 burning, bit1 consumed */
    u8 setupParam; /* 0x1: copied from placement+0x19 */
    u8 pad2[0x4 - 0x2];
    f32 burnTimer; /* 0x4 */
    u8 pad8[0xc - 0x8];
    f32 pulseTimer;    /* 0xc */
    f32 burnIntensity; /* 0x10 */
} FlammableVineState;

STATIC_ASSERT(sizeof(FlammableVinePlacement) == 0x28);
STATIC_ASSERT(offsetof(FlammableVinePlacement, base) == 0x0);
STATIC_ASSERT(offsetof(FlammableVinePlacement, setupParam) == 0x19);
STATIC_ASSERT(offsetof(FlammableVinePlacement, scaleParam) == 0x1A);
STATIC_ASSERT(offsetof(FlammableVinePlacement, burnedBit) == 0x1E);
STATIC_ASSERT(offsetof(FlammableVinePlacement, gateBit) == 0x20);
STATIC_ASSERT(offsetof(TrickyIfaceVtbl, slot28) == 0x28);
STATIC_ASSERT(sizeof(TrickyIface) == 0x4);
STATIC_ASSERT(sizeof(FlammableVineState) == 0x14);
STATIC_ASSERT(offsetof(FlammableVineState, burnTimer) == 0x4);
STATIC_ASSERT(offsetof(FlammableVineState, pulseTimer) == 0xC);
STATIC_ASSERT(offsetof(FlammableVineState, burnIntensity) == 0x10);

int FlammableVine_getExtraSize(void);
int FlammableVine_getObjectTypeId(void);
void FlammableVine_free(GameObject* obj);
void FlammableVine_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void FlammableVine_hitDetect(GameObject* obj);
void FlammableVine_update(GameObject* obj);
void FlammableVine_init(GameObject* obj, FlammableVinePlacement* placement);
void FlammableVine_release(void);
void FlammableVine_initialise(void);

#endif
