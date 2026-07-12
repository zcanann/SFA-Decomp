#ifndef MAIN_DLL_WC_DLL_0296_WCTEMPLEDIA_H
#define MAIN_DLL_WC_DLL_0296_WCTEMPLEDIA_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct WCTempleDiaSetup
{
    ObjPlacement base;
    s8 type;
    u8 modelIndex;
    u8 pad1A[4];
    s16 solvedBit;
    u8 pad20[4];
} WCTempleDiaSetup;

typedef struct WCTempleDiaState
{
    f32 currentSpeed;
    f32 targetSpeed;
    u8 stageMask;
    u8 flags;
    u8 pad0A[2];
    f32* targetTable;
    s16* gamebits;
} WCTempleDiaState;

STATIC_ASSERT(sizeof(WCTempleDiaState) == 0x14);
STATIC_ASSERT(sizeof(WCTempleDiaSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTempleDiaState, currentSpeed) == 0x00);
STATIC_ASSERT(offsetof(WCTempleDiaState, targetSpeed) == 0x04);
STATIC_ASSERT(offsetof(WCTempleDiaState, stageMask) == 0x08);
STATIC_ASSERT(offsetof(WCTempleDiaState, flags) == 0x09);
STATIC_ASSERT(offsetof(WCTempleDiaState, targetTable) == 0x0C);
STATIC_ASSERT(offsetof(WCTempleDiaState, gamebits) == 0x10);
STATIC_ASSERT(offsetof(WCTempleDiaSetup, type) == 0x18);
STATIC_ASSERT(offsetof(WCTempleDiaSetup, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(WCTempleDiaSetup, solvedBit) == 0x1E);

extern ObjectDescriptor gWCTempleDiaObjDescriptor;
extern s16 gWcTempleDiaGameBitsA[4];
extern s16 gWcTempleDiaGameBitsB[4];
extern f32 gWcTempleDiaTargetSpeedTableA[3];
extern f32 gWcTempleDiaTargetSpeedTableB[3];
extern f32 gWcTempleDiaSpeedLerpRate;

void wctempledia_syncPartVisibility(GameObject* obj, u8 mask);
int wctempledia_getExtraSize(void);
int wctempledia_getObjectTypeId(void);
void wctempledia_free(void);
void wctempledia_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void wctempledia_hitDetect(void);
int wctempledia_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void wctempledia_update(GameObject* obj);
void wctempledia_init(GameObject* obj, WCTempleDiaSetup* setup);
void wctempledia_release(void);
void wctempledia_initialise(void);

#endif /* MAIN_DLL_WC_DLL_0296_WCTEMPLEDIA_H */
