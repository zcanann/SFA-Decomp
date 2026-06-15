#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/dll/baddie_state.h"
#include "main/dll/landedArwing.h"
#include "main/objlib.h"
#include "main/player_control_interface.h"

typedef struct LandedArwingTriggerLaunchTargetState
{
    u8 pad0[0x3F0 - 0x0];
    s16 unk3F0;
    s16 unk3F2;
    u8 pad3F4[0x405 - 0x3F4];
    u8 unk405;
    u8 pad406[0x408 - 0x406];
} LandedArwingTriggerLaunchTargetState;

extern void* gBaddieControlInterface;

extern void Obj_FreeObject(int obj);
extern void objMove(int obj, f32 vx, f32 vy, f32 vz);
extern void fn_80165B3C(int obj, int state);
extern void landedarwing_moveSurfaceCrawler(int obj, int state);
extern void fn_80166444(int obj, int state);
extern void updateConstrainedChaseVelocity(int obj, f32 x, f32 y, f32 z, f32 scale);

extern u8 framesThisStep;
extern f32 lbl_803E2FD8;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E2FE0;
extern f32 lbl_803E2FE4;
extern f32 lbl_803E2FE8;
extern f32 lbl_803E2FEC;
extern f32 lbl_803E2FF0;
extern f32 lbl_803E2FF4;
extern f32 lbl_803E2FF8;
extern f32 lbl_803E2FFC;
extern f32 lbl_803E3000;

int LandedArwing_ReturnZero(void) { return 0x0; }

int LandedArwing_TriggerLaunchTarget(int obj, int target)
{
    int* aux = ((GameObject*)obj)->extra;
    if ((s8) * (u8*)(target + 0x27a) != 0)
    {
        (*(int(**)(int, int, int, int))(*(int*)gBaddieControlInterface + 0x4c))(
            obj, (int)((LandedArwingTriggerLaunchTargetState*)aux)->unk3F0, -1, 0);
        (*gPlayerInterface)->spawnPartfx((void*)obj, (void*)target, 0x3c, 0xa, 0);
        GameBit_Set((int)((LandedArwingTriggerLaunchTargetState*)aux)->unk3F2, 1);
        ((LandedArwingTriggerLaunchTargetState*)aux)->unk405 = 0;
    }
    return 0;
}

int LandedArwing_UpdateBounceFade(int obj, u32* stateWord)
{
    f32 horizontalDamping;
    LandedArwingState* state;
    ObjHitsPriorityState* hitState;

    state = (LandedArwingState*)((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
    *(u8*)((int)stateWord + 0x34d) = 3;
    if (*(s8*)((int)stateWord + 0x27a) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityX;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2FD8;
        ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityZ;
        ObjAnim_SetCurrentMove(obj, 3, lbl_803E2FDC, 0);
        state->animSpeed = lbl_803E2FE0;
    }
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->objectPairHitVolume = 0;
    *stateWord = *stateWord | 0x4000;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (horizontalDamping = lbl_803E2FE4);
    ((GameObject*)obj)->anim.velocityY = lbl_803E2FE8 * (((GameObject*)obj)->anim.velocityY - lbl_803E2FEC);
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * horizontalDamping;
    objMove(obj, ((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityY,
            ((GameObject*)obj)->anim.velocityZ);
    if (((GameObject*)obj)->anim.localPosX < state->boundsMinX)
    {
        ((GameObject*)obj)->anim.localPosX = state->boundsMinX;
        ((GameObject*)obj)->anim.velocityX = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityX;
    }
    if (((GameObject*)obj)->anim.localPosX > state->boundsMaxX)
    {
        ((GameObject*)obj)->anim.localPosX = state->boundsMaxX;
        ((GameObject*)obj)->anim.velocityX = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityX;
    }
    if (((GameObject*)obj)->anim.localPosY < state->boundsMinY)
    {
        ((GameObject*)obj)->anim.localPosY = state->boundsMinY;
        ((GameObject*)obj)->anim.velocityY = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityY;
    }
    if (((GameObject*)obj)->anim.localPosY > state->boundsMaxY)
    {
        ((GameObject*)obj)->anim.localPosY = state->boundsMaxY;
        ((GameObject*)obj)->anim.velocityY = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityY;
    }
    if (((GameObject*)obj)->anim.localPosZ < state->boundsMinZ)
    {
        ((GameObject*)obj)->anim.localPosZ = state->boundsMinZ;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityZ;
    }
    if (((GameObject*)obj)->anim.localPosZ > state->boundsMaxZ)
    {
        ((GameObject*)obj)->anim.localPosZ = state->boundsMaxZ;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E2FF0 * -((GameObject*)obj)->anim.velocityZ;
    }
    if (lbl_803E2FF4 == ((GameObject*)obj)->anim.currentMoveProgress)
    {
        ObjMsg_SendToObjects(0, 3, (void*)obj, 0xe0000, obj);
        Obj_FreeObject(obj);
        return 0;
    }
    else
    {
        ((GameObject*)obj)->anim.alpha =
            (u8)(255 - (s32)(lbl_803E2FF8 * ((GameObject*)obj)->anim.currentMoveProgress));
    }
    return 0;
}

int LandedArwing_UpdateRetreatChase(int obj, int stateWord)
{
    f32 scale;
    int player;
    LandedArwingState* state;
    GameObject* playerObj;
    f32 x;
    f32 y;
    f32 z;

    state = (LandedArwingState*)((GroundBaddieState*)*(int*)&((GameObject*)obj)->extra)->control;
    player = (int)Obj_GetPlayerObject();
    playerObj = (GameObject*)player;
    *(u8*)(stateWord + 0x34d) = 1;
    if (*(s8*)(stateWord + 0x27a) != 0)
    {
        state->scriptTimer = 0x3c;
        state->speed = lbl_803E2FFC;
        ObjHits_DisableObject(obj);
    }
    if (state->surfaceMode == 6)
    {
        goto use_player_reflect_position;
    }
    if ((u32)player == 0)
    {
        goto use_object_position;
    }
    if (playerObj->anim.worldPosX < state->boundsMinX)
    {
        goto use_object_position;
    }
    if (playerObj->anim.worldPosX > state->boundsMaxX)
    {
        if (playerObj->anim.worldPosY < state->boundsMinY)
        {
            goto use_object_position;
        }
    }
    if (playerObj->anim.worldPosY > state->boundsMaxY)
    {
        if (playerObj->anim.worldPosZ < state->boundsMinZ)
        {
            goto use_object_position;
        }
    }
    if (playerObj->anim.worldPosZ > state->boundsMaxZ)
    {
        goto use_object_position;
    }
    goto use_player_reflect_position;
use_object_position:
    {
        x = ((GameObject*)obj)->anim.localPosX;
        y = ((GameObject*)obj)->anim.localPosY;
        z = ((GameObject*)obj)->anim.localPosZ;
        scale = lbl_803E2FDC;
        goto update_action;
    }
use_player_reflect_position:
    {
        x = ((GameObject*)obj)->anim.localPosX - lbl_803E3000 * (playerObj->anim.localPosX - ((GameObject*)obj)->anim.
            localPosX);
        y = ((GameObject*)obj)->anim.localPosY - lbl_803E3000 * (playerObj->anim.localPosY - ((GameObject*)obj)->anim.
            localPosY);
        z = ((GameObject*)obj)->anim.localPosZ - lbl_803E3000 * (playerObj->anim.localPosZ - ((GameObject*)obj)->anim.
            localPosZ);
        scale = lbl_803E2FF4;
    }
update_action:
    updateConstrainedChaseVelocity(obj, x, y, z, scale);
    if (state->surfaceMode == 6)
    {
        if ((u32)((state->flags92 >> 2) & 1) != 0U)
        {
            fn_80165B3C(obj, (int)state);
        }
        else
        {
            fn_80166444(obj, (int)state);
        }
    }
    else
    {
        landedarwing_moveSurfaceCrawler(obj, (int)state);
    }
    if ((int)state->scriptTimer <= (int)(u32)framesThisStep)
    {
        return 2;
    }
    state->scriptTimer -= framesThisStep;
    return 0;
}
