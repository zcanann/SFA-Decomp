#ifndef MAIN_DLL_DLL_0191_ECSHCREATOR_H_
#define MAIN_DLL_DLL_0191_ECSHCREATOR_H_

#include "global.h"
#include "main/game_object.h"

typedef void (*EcshSetupFn)(s16*, int, int, int, int, int);

typedef struct EcshCreatorState
{
    s16 countdown;
    s16 active;
    s16 gameBit;
    s16 pad06;
    s16 groupSlot;
} EcshCreatorState;

STATIC_ASSERT(offsetof(EcshCreatorState, countdown) == 0);
STATIC_ASSERT(offsetof(EcshCreatorState, active) == 2);
STATIC_ASSERT(offsetof(EcshCreatorState, gameBit) == 4);
STATIC_ASSERT(offsetof(EcshCreatorState, groupSlot) == 8);
STATIC_ASSERT(sizeof(EcshCreatorState) == 0xa);

/* 0x38-byte spawn descriptor handed to Obj_SetupObject for the shrine
 * child (object type 0x11). Head is the common ObjPlacement layout
 * (type id at 0, color block, position, mapId); the tail is the
 * EarthWalker-shrine class fields. */
typedef struct EcshShrineSpawnSetup
{
    s16 objType;  /* 0x00 */
    s16 pad02;    /* 0x02 */
    u8 color[4];  /* 0x04 */
    f32 posX;     /* 0x08 */
    f32 posY;     /* 0x0c */
    f32 posZ;     /* 0x10 */
    s32 mapId;    /* 0x14 */
    s16 gameBit;  /* 0x18 */
    s16 unk1A;    /* 0x1a */
    u8 pad1C[2];  /* 0x1c */
    s16 unk1E;    /* 0x1e */
    s16 unk20;    /* 0x20 */
    s16 unk22;    /* 0x22 */
    s16 unk24;    /* 0x24 */
    u8 pad26;     /* 0x26 */
    u8 unk27;     /* 0x27 */
    u8 unk28;     /* 0x28 */
    u8 unk29;     /* 0x29 */
    s8 rotByte;   /* 0x2a: object yaw byte (anim.rotX >> 8) */
    u8 unk2B;     /* 0x2b */
    s16 unk2C;    /* 0x2c */
    s8 unk2E;     /* 0x2e */
    u8 pad2F;     /* 0x2f */
    s16 unk30;    /* 0x30 */
    u8 groupSlot; /* 0x32 */
    u8 pad33;     /* 0x33 */
    u16 unk34;    /* 0x34 */
    u8 pad36[2];  /* 0x36 */
} EcshShrineSpawnSetup;

STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, posX) == 0x8);
STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, mapId) == 0x14);
STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, gameBit) == 0x18);
STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, rotByte) == 0x2a);
STATIC_ASSERT(offsetof(EcshShrineSpawnSetup, unk34) == 0x34);
STATIC_ASSERT(sizeof(EcshShrineSpawnSetup) == 0x38);

int ecsh_creator_getExtraSize(void);
int ecsh_creator_getObjectTypeId(void);
void ecsh_creator_free(void);
void ecsh_creator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void ecsh_creator_hitDetect(void);
void ecsh_creator_update(GameObject* obj);
void ecsh_creator_init(GameObject* obj, s8* def);
void ecsh_creator_release(void);
void ecsh_creator_initialise(void);

#endif /* MAIN_DLL_DLL_0191_ECSHCREATOR_H_ */
