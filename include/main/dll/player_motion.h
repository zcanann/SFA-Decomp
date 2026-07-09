#ifndef MAIN_DLL_PLAYER_MOTION_H_
#define MAIN_DLL_PLAYER_MOTION_H_

void objSetXRot(struct GameObject* playerObj, int heading);
f32 fn_80296214(struct GameObject* playerObj);
void fn_80296220(struct GameObject* playerObj, f32 liftVelocityY);
void fn_8029697C(struct GameObject* playerObj, s16* outYaw, s16* outPitch);

static inline void Player_SetHeading(int playerObj, int heading)
{
    objSetXRot((struct GameObject*)(playerObj), heading);
}

static inline f32 Player_GetLiftVelocityY(int playerObj)
{
    return fn_80296214((struct GameObject*)(playerObj));
}

static inline void Player_SetLiftVelocityY(int playerObj, f32 liftVelocityY)
{
    fn_80296220((struct GameObject*)(playerObj), liftVelocityY);
}

static inline void Player_GetAimAngles(int playerObj, s16* outYaw, s16* outPitch)
{
    fn_8029697C((struct GameObject*)(playerObj), outYaw, outPitch);
}

#endif
