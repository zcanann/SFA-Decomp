/* DLL 0x4A - CameraModeShipBattle [8010BF08-8010C0D8) */
#include "main/mm.h"

extern f32 timeDelta;

#include "main/camera_object.h"
#include "main/dll/CAM/camshipbattle_state.h"
#include "main/game_object.h"
#include "main/object_transform.h"

extern CameraModeShipBattleState* gCamShipBattleState;
extern f32 lbl_803E1948;
extern f32 lbl_803E194C;
extern f32 lbl_803E1950;
extern f32 lbl_803E1954;
extern f32 lbl_803E1958;
extern f32 lbl_803E195C;
extern f32 gCamShipBattleBlendRate;
extern f32 lbl_803E1964;
extern f32 lbl_803E1968;
extern f32 lbl_803E196C;
extern f32 lbl_803E1970;
extern f32 gCamShipBattleFov;
extern f32 lbl_803E1978;
extern f32 lbl_803E197C;
extern f32 lbl_803E1980;

extern int shipBattleFn_801eed24(int focus);

#pragma opt_common_subs off
void CameraModeShipBattle_update(short* cam)
{
    f32 fa;
    f32 fb;
    f32 fc;
    f32 r;
    CameraModeShipBattleState* s;
    int m = 0;
    GameObject* focus = (GameObject*)((CameraObject*)cam)->anim.targetObj;
    if (focus != NULL)
    {
        m = shipBattleFn_801eed24((int)focus);
    }
    s = gCamShipBattleState;
    if (m != s->mode)
    {
        if (m == 2)
        {
            fa = lbl_803E1948;
        }
        else
        {
            fa = lbl_803E194C;
        }
        if (m != 2 && m != 5)
        {
            fb = lbl_803E1950;
            fc = lbl_803E1954;
        }
        else
        {
            fb = lbl_803E1958;
            fc = s->smoothedYOffset;
        }
        s->mode = m;
        gCamShipBattleState->lateralDelta = fa - gCamShipBattleState->targetLateralOffset;
        gCamShipBattleState->startLateralOffset = gCamShipBattleState->targetLateralOffset;
        gCamShipBattleState->verticalDelta = fb - (gCamShipBattleState->verticalOffset + fc);
        gCamShipBattleState->startVerticalOffset = gCamShipBattleState->verticalOffset;
        gCamShipBattleState->blendTimer = lbl_803E1954;
    }
    if (gCamShipBattleState->blendTimer < (fa = 1.0f))
    {
        gCamShipBattleState->blendTimer = gCamShipBattleBlendRate * timeDelta + gCamShipBattleState->blendTimer;
        if (gCamShipBattleState->blendTimer > fa)
        {
            gCamShipBattleState->blendTimer = fa;
        }
        gCamShipBattleState->targetLateralOffset = gCamShipBattleState->blendTimer * gCamShipBattleState->lateralDelta + gCamShipBattleState->
            startLateralOffset;
        gCamShipBattleState->verticalOffset = gCamShipBattleState->blendTimer * gCamShipBattleState->verticalDelta + gCamShipBattleState->
            startVerticalOffset;
    }
    if (m != 2 && m != 5)
    {
        fa = (f32)focus->anim.rotZ / lbl_803E1964;
        gCamShipBattleState->smoothedZOffset = -(fa * timeDelta - gCamShipBattleState->smoothedZOffset);
        fa = (f32)focus->anim.rotY / lbl_803E1968;
        gCamShipBattleState->smoothedYOffset = -(fa * timeDelta - gCamShipBattleState->smoothedYOffset);
        fb = gCamShipBattleState->smoothedZOffset;
        fc = lbl_803E196C;
        fa = fc * fb;
        gCamShipBattleState->smoothedZOffset = -(fa * timeDelta - fb);
        fb = gCamShipBattleState->smoothedYOffset;
        fa = fc * fb;
        gCamShipBattleState->smoothedYOffset = -(fa * timeDelta - fb);
        ((CameraObject*)cam)->anim.worldPosY = gCamShipBattleState->smoothedYOffset + (focus->anim.worldPosY + gCamShipBattleState->
            verticalOffset);
    }
    else
    {
        fa = (f32)focus->anim.rotZ / lbl_803E1964;
        gCamShipBattleState->smoothedZOffset = -(fa * timeDelta - gCamShipBattleState->smoothedZOffset);
        fa = (f32)focus->anim.rotY / lbl_803E1968;
        gCamShipBattleState->smoothedYOffset = -(fa * timeDelta - gCamShipBattleState->smoothedYOffset);
        fb = gCamShipBattleState->smoothedZOffset;
        fc = lbl_803E196C;
        fa = fc * fb;
        gCamShipBattleState->smoothedZOffset = -(fa * timeDelta - fb);
        fb = gCamShipBattleState->smoothedYOffset;
        fa = fc * fb;
        gCamShipBattleState->smoothedYOffset = -(fa * timeDelta - fb);
        ((CameraObject*)cam)->anim.worldPosY = gCamShipBattleState->smoothedYOffset + (focus->anim.worldPosY + gCamShipBattleState->
            verticalOffset);
    }
    fa = lbl_803E1970 + focus->anim.worldPosX;
    ((CameraObject*)cam)->anim.worldPosX = fa + gCamShipBattleState->lateralOffset;
    ((CameraObject*)cam)->anim.worldPosZ = focus->anim.worldPosZ + gCamShipBattleState->smoothedZOffset;
    cam[1] = 0x708;
    cam[0] = 0x4000;
    cam[2] = (s16)(-focus->anim.rotZ >> 3);
    ((CameraObject*)cam)->fov = gCamShipBattleFov;
    s = gCamShipBattleState;
    r = (s->targetLateralOffset - s->lateralOffset) / lbl_803E1978;
    if (r > lbl_803E197C)
    {
        r = lbl_803E197C;
    }
    else if (r < lbl_803E1980)
    {
        r = lbl_803E1980;
    }
    r = r * timeDelta;
    s->lateralOffset = s->lateralOffset + r;
    Obj_TransformWorldPointToLocal(((CameraObject*)cam)->anim.worldPosX, ((CameraObject*)cam)->anim.worldPosY,
                                   ((CameraObject*)cam)->anim.worldPosZ,
                                   &((CameraObject*)cam)->anim.localPosX, &((CameraObject*)cam)->anim.localPosY,
                                   &((CameraObject*)cam)->anim.localPosZ,
                                   *(int*)&((CameraObject*)cam)->anim.parent);
}
#pragma opt_common_subs reset

void CameraModeShipBattle_init(void)
{
    float fval;
    u8 zero;

    if (gCamShipBattleState == (CameraModeShipBattleState*)0x0)
    {
        gCamShipBattleState = (CameraModeShipBattleState*)mmAlloc(sizeof(CameraModeShipBattleState), 0xf, 0);
    }
    fval = lbl_803E1954;
    gCamShipBattleState->smoothedZOffset = lbl_803E1954;
    gCamShipBattleState->smoothedYOffset = fval;
    gCamShipBattleState->lateralOffset = lbl_803E1978;
    fval = lbl_803E194C;
    gCamShipBattleState->startLateralOffset = lbl_803E194C;
    gCamShipBattleState->targetLateralOffset = fval;
    gCamShipBattleState->blendTimer = lbl_803E195C;
    zero = 0;
    gCamShipBattleState->mode = zero;
    fval = lbl_803E1950;
    gCamShipBattleState->startVerticalOffset = lbl_803E1950;
    gCamShipBattleState->verticalOffset = fval;
    return;
}

void CameraModeCombat_release(void);

void CameraModeShipBattle_copyToCurrent_nop(void)
{
}

void CameraModeShipBattle_release(void)
{
}

void CameraModeShipBattle_initialise(void)
{
}

void CameraModeClimb_copyToCurrent_nop(void);

void CameraModeShipBattle_free(void)
{
    mm_free(gCamShipBattleState);
    gCamShipBattleState = 0;
}

void CameraModeClimb_free(void);
