#ifndef MAIN_DLL_DLL_01E4_MAGICMAKER_H_
#define MAIN_DLL_DLL_01E4_MAGICMAKER_H_

#include "global.h"
#include "main/obj_placement.h"

typedef struct MagicmakerPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 colorR; /* 0x4 -> spawn head.color[0] */
    u8 colorG; /* 0x5 -> spawn head.color[1] */
    u8 colorB; /* 0x6 -> spawn head.color[2] */
    u8 colorA; /* 0x7 -> spawn head.color[3] */
} MagicmakerPlacement;

/*
 * The 0x30-byte spawn descriptor handed back by Obj_AllocObjectSetup.
 * The head (0x00..0x17) is the common ObjPlacement record; the fields
 * past it are this creature class's per-spawn setup slots.
 */
typedef struct MagicmakerSetup
{
    ObjPlacement head;
    u8 pad18[0x1A - 0x18];
    u8 unk1A;
    u8 pad1B[0x1C - 0x1B];
    s16 unk1C;
    u8 pad1E[0x24 - 0x1E];
    s16 gameBit; /* 0x24: GameBit slot (-1 = none) */
    u8 pad26[0x2C - 0x26];
    s16 unk2C;
    s16 unk2E;
} MagicmakerSetup;

STATIC_ASSERT(offsetof(MagicmakerSetup, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(MagicmakerSetup, gameBit) == 0x24);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk2C) == 0x2C);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk2E) == 0x2E);
STATIC_ASSERT(sizeof(MagicmakerSetup) == 0x30);

int magicmaker_getExtraSize(void);
int magicmaker_getObjectTypeId(void);
void magicmaker_free(void);
void magicmaker_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void magicmaker_hitDetect(void);
void magicmaker_update(int obj);
void magicmaker_init(void);
void magicmaker_release(void);
void magicmaker_initialise(void);

#endif /* MAIN_DLL_DLL_01E4_MAGICMAKER_H_ */
