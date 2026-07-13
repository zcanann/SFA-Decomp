#ifndef MAIN_DLL_CF_DLL_163_H_
#define MAIN_DLL_CF_DLL_163_H_

#include "main/game_object.h"
#include "global.h"
#include "main/obj_placement.h"

typedef struct StaffActivatedState
{
    f32 targetX;
    f32 targetZ;
    u8 pad08[4];
    s32 liftVelocity;
    s32 previousLiftHeight;
    s32 liftHeight;
    s32 peakLiftHeight;
    u8 liftReset;
    u8 flags;
    u8 pad1E[2];
    f32 hitCooldown;
} StaffActivatedState;

typedef struct StaffActivatedSetup
{
    ObjPlacement base;
    u8 type;
    u8 unk19;
    u8 pad1A[2];
    u8 mode;
    u8 size;
    u8 debrisObjectSet;
    u8 debrisCount;
    u8 timedEventSeconds;
    u8 pad21;
    s16 activeGameBit;
    s16 lockGameBit;
    u8 pad26[0x28 - 0x26];
} StaffActivatedSetup;

int staffactivated_getExtraSize(void);
int staffactivated_getObjectTypeId(void);
void staffactivated_calcInteractionTargetXZ(GameObject* obj, f32* outX, f32* outZ);
u32 cfPrisonGuard_getLiftHeight(GameObject* obj);
void cfPrisonGuard_setLiftHeight(GameObject* obj, int height);
u8 objGetByteParam1C(GameObject* obj);

#endif /* MAIN_DLL_CF_DLL_163_H_ */
