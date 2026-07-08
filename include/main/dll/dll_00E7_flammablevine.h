#ifndef MAIN_DLL_DLL_00E7_FLAMMABLEVINE_H_
#define MAIN_DLL_DLL_00E7_FLAMMABLEVINE_H_

#include "global.h"

typedef struct FlammablevineObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 objId;      /* 0x14 */
    s8 rotXByte;    /* 0x18: rotX in 1/256 turns */
    u8 setupParam;  /* 0x19: copied to state, 1 = position-dirty */
    s16 scaleParam; /* 0x1A: drives rootMotionScale */
    s16 unk1C;
    s16 burnedBit; /* 0x1E: game bit set when burned; -1 = none */
    s16 gateBit;   /* 0x20: game bit gating use; -1 = none */
    u8 pad22[0x28 - 0x22];
} FlammablevineObjectDef;

typedef struct TrickyIfaceVtbl
{
    u8 pad0[0x28 - 0x0];
    void (*slot28)(void* iface, int obj, int a, int b); /* 0x28 */
} TrickyIfaceVtbl;

typedef struct TrickyIface
{
    TrickyIfaceVtbl* vtbl; /* 0x0 */
} TrickyIface;

typedef struct FlammablevineState
{
    u8 flags;      /* 0x0: bit0 burning, bit1 consumed */
    u8 setupParam; /* 0x1: copied from def+0x19 */
    u8 pad2[0x4 - 0x2];
    f32 burnTimer; /* 0x4 */
    u8 pad8[0xc - 0x8];
    f32 pulseTimer;    /* 0xc */
    f32 burnIntensity; /* 0x10 */
} FlammablevineState;

int FlammableVine_getExtraSize(void);
int FlammableVine_getObjectTypeId(void);
void FlammableVine_free(int obj);
void FlammableVine_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FlammableVine_hitDetect(int obj);
void FlammableVine_update(int obj);
void FlammableVine_init(int obj, int def);
void FlammableVine_release(void);
void FlammableVine_initialise(void);

#endif
