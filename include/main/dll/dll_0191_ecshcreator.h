#ifndef MAIN_DLL_DLL_0191_ECSHCREATOR_H_
#define MAIN_DLL_DLL_0191_ECSHCREATOR_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct EcshCreatorPlacement
{
    ObjPlacement base;
    s16 triggerGameBit;
    u8 pad1A[0x1E - 0x1A];
    s8 initialRotX;
    s8 childGameBitOffset;
    u8 groupSlotOffset;
} EcshCreatorPlacement;

typedef struct EcshCreatorState
{
    s16 spawnTimer;
    s16 spawnTimerStep;
    s16 triggerGameBit;
    s16 pad06;
    s16 childGroupSlot;
} EcshCreatorState;

STATIC_ASSERT(offsetof(EcshCreatorPlacement, triggerGameBit) == 0x18);
STATIC_ASSERT(offsetof(EcshCreatorPlacement, initialRotX) == 0x1E);
STATIC_ASSERT(offsetof(EcshCreatorPlacement, childGameBitOffset) == 0x1F);
STATIC_ASSERT(offsetof(EcshCreatorPlacement, groupSlotOffset) == 0x20);
STATIC_ASSERT(sizeof(EcshCreatorPlacement) == 0x24);
STATIC_ASSERT(offsetof(EcshCreatorState, spawnTimer) == 0);
STATIC_ASSERT(offsetof(EcshCreatorState, spawnTimerStep) == 2);
STATIC_ASSERT(offsetof(EcshCreatorState, triggerGameBit) == 4);
STATIC_ASSERT(offsetof(EcshCreatorState, childGroupSlot) == 8);
STATIC_ASSERT(sizeof(EcshCreatorState) == 0xa);

/* 0x38-byte spawn descriptor handed to Obj_SetupObject for the spawned
 * SharpClaw child (defNo 0x11 "sharpclawGr", DLL 0xC9). Head is the
 * common ObjPlacement layout (type id at 0, color block, position,
 * mapId); the tail is ground-baddie placement fields. */
typedef struct EcshSharpClawSpawnSetup
{
    ObjPlacement base;
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
    s8 rotX;      /* 0x2a: anim.rotX >> 8 */
    u8 unk2B;     /* 0x2b */
    s16 unk2C;    /* 0x2c */
    s8 unk2E;     /* 0x2e */
    u8 pad2F;     /* 0x2f */
    s16 unk30;    /* 0x30 */
    u8 groupSlot; /* 0x32 */
    u8 pad33;     /* 0x33 */
    u16 unk34;    /* 0x34 */
    u8 pad36[2];  /* 0x36 */
} EcshSharpClawSpawnSetup;

STATIC_ASSERT(offsetof(EcshSharpClawSpawnSetup, base.posX) == 0x8);
STATIC_ASSERT(offsetof(EcshSharpClawSpawnSetup, gameBit) == 0x18);
STATIC_ASSERT(offsetof(EcshSharpClawSpawnSetup, rotX) == 0x2a);
STATIC_ASSERT(offsetof(EcshSharpClawSpawnSetup, unk34) == 0x34);
STATIC_ASSERT(sizeof(EcshSharpClawSpawnSetup) == 0x38);

int ecsh_creator_getExtraSize(void);
int ecsh_creator_getObjectTypeId(void);
void ecsh_creator_free(void);
void ecsh_creator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void ecsh_creator_hitDetect(void);
void ecsh_creator_update(GameObject* obj);
void ecsh_creator_init(GameObject* obj, EcshCreatorPlacement* placement);
void ecsh_creator_release(void);
void ecsh_creator_initialise(void);

extern ObjectDescriptor gECSH_CreatorObjDescriptor;

#endif /* MAIN_DLL_DLL_0191_ECSHCREATOR_H_ */
