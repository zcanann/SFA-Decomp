#ifndef MAIN_DLL_PLAYER_MOTION_H_
#define MAIN_DLL_PLAYER_MOTION_H_

void objSetXRot(int playerObj, int heading);
f32 fn_80296214(int playerObj);
void fn_80296220(int playerObj, f32 liftVelocityY);
void fn_8029697C(int playerObj, s16 *outYaw, s16 *outPitch);

static inline void Player_SetHeading(int playerObj, int heading)
{
    objSetXRot(playerObj, heading);
}

static inline f32 Player_GetLiftVelocityY(int playerObj)
{
    return fn_80296214(playerObj);
}

static inline void Player_SetLiftVelocityY(int playerObj, f32 liftVelocityY)
{
    fn_80296220(playerObj, liftVelocityY);
}

static inline void Player_GetAimAngles(int playerObj, s16 *outYaw, s16 *outPitch)
{
    fn_8029697C(playerObj, outYaw, outPitch);
}

#endif
