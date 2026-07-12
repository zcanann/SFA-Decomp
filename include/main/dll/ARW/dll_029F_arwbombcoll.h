#ifndef MAIN_DLL_ARW_DLL_029F_ARWBOMBCOLL_H
#define MAIN_DLL_ARW_DLL_029F_ARWBOMBCOLL_H

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct RingState RingState;

typedef struct ArwbombcollHandleArwingHitPlacement
{
    u8 pad0[0x1E];
    s16 eventId;
} ArwbombcollHandleArwingHitPlacement;

typedef struct ARWBombCollSetup
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19[0x24 - 0x19];
} ARWBombCollSetup;

typedef struct ArwBombFlags
{
    u8 b80 : 1;
    u8 b40 : 1;
} ArwBombFlags;

typedef struct ARWBombCollState
{
    f32 lifetime;
    ArwBombFlags flags;
    u8 pad05[3];
} ARWBombCollState;

STATIC_ASSERT(sizeof(ARWBombCollSetup) == 0x24);
STATIC_ASSERT(offsetof(ARWBombCollSetup, rotX) == 0x18);
STATIC_ASSERT(sizeof(ArwBombFlags) == 0x1);
STATIC_ASSERT(sizeof(ARWBombCollState) == 0x8);
STATIC_ASSERT(offsetof(ARWBombCollState, flags) == 0x04);

extern f32 lbl_803E707C;
extern f32 gArwBombCollActivateDistanceZ;
extern f32 gArwBombCollAlphaFadeRate;
extern f32 gArwBombCollSpinRate;
extern f32 lbl_803E708C;
extern f32 gArwBombCollHitToleranceY;
extern f32 gArwBombCollHitRadiusSq;
extern f32 gArwBombCollPlaneHitRadius;

int ARWBombColl_getExtraSize(void);
int ARWBombColl_getObjectTypeId(void);
void ARWBombColl_free(void);
void ARWBombColl_hitDetect(void);
void ARWBombColl_render(int obj, int p2, int p3, int p4, int p5, f32 scale);
void ARWBombColl_init(GameObject* obj, int setup);
void ARWBombColl_release(void);
void ARWBombColl_initialise(void);
void ARWBombColl_update(int obj);
void arwbombcoll_setLifetime(GameObject* obj, int lifetime);

void arwbombcoll_updateMovingAxis(GameObject* obj, RingState* state);
void Ring_onCollect(GameObject* obj, RingState* state, GameObject* arwing);
int arwbombcoll_checkArwingCollision(GameObject* obj, RingState* state, int arwing);

#endif
