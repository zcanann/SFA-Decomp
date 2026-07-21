#ifndef MAIN_DLL_DLL_015D_SLIDINGDOOR_H_
#define MAIN_DLL_DLL_015D_SLIDINGDOOR_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct SlidingdoorPlacement
{
    ObjPlacement base;
    s16 openGameBit;      /* 0x18: door opens while this bit is set (gated by gateGameBit) */
    s16 openedGameBit;    /* 0x1A: set to 1 once the door opens */
    s16 preemptEvent;     /* 0x1C: event preempted by SlidingDoor_update if already moving */
    s8 startupSequenceId; /* 0x1E: startup sequence id */
    u8 rotXByte;
    u8 pad20;
    u8 scaleByte;
    s16 gateGameBit; /* 0x22: -1 = none; otherwise must also be set to open */
    u8 pad24[0x28 - 0x24];
} SlidingdoorPlacement;

/* 3-bit door state machine (see file header): */
enum SlidingdoorMode
{
    SLIDINGDOOR_MODE_CLOSED = 0,
    SLIDINGDOOR_MODE_OPEN = 1,
    SLIDINGDOOR_MODE_OPENING = 2,
    SLIDINGDOOR_MODE_CLOSING = 3
};

typedef struct SlidingdoorState
{
    u8 mode : 3;
    u8 rest : 5;
} SlidingdoorState;

STATIC_ASSERT(offsetof(SlidingdoorPlacement, openGameBit) == 0x18);
STATIC_ASSERT(offsetof(SlidingdoorPlacement, startupSequenceId) == 0x1e);
STATIC_ASSERT(offsetof(SlidingdoorPlacement, rotXByte) == 0x1f);
STATIC_ASSERT(offsetof(SlidingdoorPlacement, scaleByte) == 0x21);
STATIC_ASSERT(offsetof(SlidingdoorPlacement, gateGameBit) == 0x22);
STATIC_ASSERT(sizeof(SlidingdoorPlacement) == 0x28);
STATIC_ASSERT(sizeof(SlidingdoorState) == 0x1);

int SlidingDoor_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int SlidingDoor_getExtraSize(void);
int SlidingDoor_getObjectTypeId(void);
void SlidingDoor_free(void);
void SlidingDoor_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SlidingDoor_hitDetect(void);
void SlidingDoor_update(GameObject* obj);
void SlidingDoor_init(GameObject* obj, SlidingdoorPlacement* placement);
void SlidingDoor_release(void);
void SlidingDoor_initialise(void);

extern ObjectDescriptor gSlidingDoorObjDescriptor;

#endif /* MAIN_DLL_DLL_015D_SLIDINGDOOR_H_ */
