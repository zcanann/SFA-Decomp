#ifndef MAIN_DLL_DIM_DLL_01C7_DIMLAVASMASH_H_
#define MAIN_DLL_DIM_DLL_01C7_DIMLAVASMASH_H_

#include "types.h"
#include "main/objanim_update.h"

typedef struct DimlavasmashPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 triggerGameBit;
    s16 gateGameBit;
    u8 pad22[0x28 - 0x22];
} DimlavasmashPlacement;

typedef struct DimlavasmashState
{
    s8 unk0;           /* 0x0 init source: def.unk1C */
    u8 surfaceLayerId; /* surface material/layer index passed to setBlockSurfaceFlags */
    u8 state;
    u8 pad3[0x7 - 0x3];
    u8 unk7;
    u8 pad8[0x9 - 0x8];
    s8 unk9;
    s8 unkA;
    s8 unkB;
    u8 padC[0x10 - 0xC];
} DimlavasmashState;

typedef struct DimlavasmashObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 rotByte;        /* 0x18 rotation byte (read raw as def[0x18] into anim.rotX) */
    s16 surfaceLayerId; /* 0x1A def source for state.surfaceLayerId */
    s16 unk1C;
    s16 gameBit;
} DimlavasmashObjectDef;

void dimlavasmash_free(void);
void dimlavasmash_hitDetect(void);
void dimlavasmash_update(int* obj);
int dimlavasmash_getExtraSize(void);
int dimlavasmash_getObjectTypeId(void);
void dimlavasmash_setBlockSurfaceFlags(int arg1, int arg2, int arg3);
void dimlavasmash_init(s16* obj, s8* def);
void dimlavasmash_release(void);
void dimlavasmash_initialise(void);

#endif
