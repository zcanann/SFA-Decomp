#ifndef MAIN_DLL_PLAYER_MOTION_H_
#define MAIN_DLL_PLAYER_MOTION_H_

#include "game/objects/object.h"
void objSetXRot(GameObject* playerObj, int heading);
f32 playerGetVerticalVel(GameObject* playerObj);
void playerSetVerticalVel(GameObject* playerObj, f32 liftVelocityY);
void playerGetAimAngles(GameObject* playerObj, s16* outYaw, s16* outPitch);

static inline void Player_SetHeading(GameObject* playerObj, int heading)
{
    objSetXRot(playerObj, heading);
}

static inline f32 Player_GetLiftVelocityY(GameObject* playerObj)
{
    return playerGetVerticalVel(playerObj);
}

static inline void Player_SetLiftVelocityY(GameObject* playerObj, f32 liftVelocityY)
{
    playerSetVerticalVel(playerObj, liftVelocityY);
}

static inline void Player_GetAimAngles(GameObject* playerObj, s16* outYaw, s16* outPitch)
{
    playerGetAimAngles(playerObj, outYaw, outPitch);
}

#endif
