#ifndef MAIN_DLL_DLL_015D_SLIDINGDOOR_H_
#define MAIN_DLL_DLL_015D_SLIDINGDOOR_H_

#include "global.h"
#include "main/objanim_update.h"

typedef struct SlidingdoorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 openGameBit;      /* 0x18: door opens while this bit is set (gated by gateGameBit) */
    s16 openedGameBit;    /* 0x1A: set to 1 once the door opens */
    s16 preemptEvent;     /* 0x1C: event preempted by SlidingDoor_update if already moving */
    s8 startupSequenceId; /* 0x1E: startup sequence id */
    u8 pad1F[0x20 - 0x1F];
    s16 unk20;       /* 0x20 */
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

int SlidingDoor_SeqFn(u8* obj, int unused, ObjAnimUpdateState* animUpdate);
int SlidingDoor_getExtraSize(void);
int SlidingDoor_getObjectTypeId(void);
void SlidingDoor_free(void);
void SlidingDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SlidingDoor_hitDetect(void);
void SlidingDoor_update(u8* obj);
void SlidingDoor_init(u8* obj, u8* data);
void SlidingDoor_release(void);
void SlidingDoor_initialise(void);

#endif /* MAIN_DLL_DLL_015D_SLIDINGDOOR_H_ */
