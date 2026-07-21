#ifndef MAIN_DLL_DLL_01E4_MAGICMAKER_H_
#define MAIN_DLL_DLL_01E4_MAGICMAKER_H_

#include "main/game_object.h"
#include "global.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct MagicmakerPlacement
{
    ObjPlacement base;
} MagicmakerPlacement;

/*
 * The 0x30-byte spawn descriptor handed back by Obj_AllocObjectSetup.
 * The head (0x00..0x17) is the common ObjPlacement record; the fields
 * past it are this creature class's per-spawn setup slots.
 */
typedef struct MagicmakerSetup
{
    ObjPlacement base;
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

STATIC_ASSERT(sizeof(MagicmakerPlacement) == 0x18);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(MagicmakerSetup, gameBit) == 0x24);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk2C) == 0x2C);
STATIC_ASSERT(offsetof(MagicmakerSetup, unk2E) == 0x2E);
STATIC_ASSERT(sizeof(MagicmakerSetup) == 0x30);

extern u16 gMagicMakerSpawnObjectIds[6];
extern ObjectDescriptor10WithPadding gMAGICMakerObjDescriptor;
extern f32 gMagicMakerRenderScale;
extern f32 gMagicMakerSpawnHeightOffset;

int magicmaker_getExtraSize(void);
int magicmaker_getObjectTypeId(void);
void magicmaker_free(void);
void magicmaker_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void magicmaker_hitDetect(void);
void magicmaker_update(GameObject* obj);
void magicmaker_init(void);
void magicmaker_release(void);
void magicmaker_initialise(void);

#endif /* MAIN_DLL_DLL_01E4_MAGICMAKER_H_ */
