/* DLL 0x4A - CameraModeShipBattle [8010BF08-8010C0D8) */
#include "main/mm.h"

extern f32 timeDelta;

#include "main/camera_object.h"
#include "main/dll/CAM/camshipbattle_state.h"
#include "main/game_object.h"
#include "main/object_transform.h"

extern CameraModeShipBattleState* lbl_803DD570;
extern f32 lbl_803E1948;
extern f32 lbl_803E194C;
extern f32 lbl_803E1950;
extern f32 lbl_803E1954;
extern f32 lbl_803E1958;
extern f32 lbl_803E195C;
extern f32 lbl_803E1960;
extern f32 lbl_803E1964;
extern f32 lbl_803E1968;
extern f32 lbl_803E196C;
extern f32 lbl_803E1970;
extern f32 lbl_803E1974;
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
    int m = 0;
    GameObject* focus = (GameObject*)((CameraObject*)cam)->anim.targetObj;
    if (focus != NULL)
    {
        m = shipBattleFn_801eed24((int)focus);
    }
    if (m != lbl_803DD570->mode)
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
            fc = lbl_803DD570->smoothedYOffset;
        }
        lbl_803DD570->mode = m;
        lbl_803DD570->lateralDelta = fa - lbl_803DD570->targetLateralOffset;
        lbl_803DD570->startLateralOffset = lbl_803DD570->targetLateralOffset;
        lbl_803DD570->verticalDelta = fb - (lbl_803DD570->verticalOffset + fc);
        lbl_803DD570->startVerticalOffset = lbl_803DD570->verticalOffset;
        lbl_803DD570->blendTimer = lbl_803E1954;
    }
    fa = lbl_803E195C;
    if (lbl_803DD570->blendTimer < lbl_803E195C)
    {
        lbl_803DD570->blendTimer = lbl_803E1960 * timeDelta + lbl_803DD570->blendTimer;
        if (lbl_803DD570->blendTimer > fa)
        {
            lbl_803DD570->blendTimer = fa;
        }
        lbl_803DD570->targetLateralOffset = lbl_803DD570->blendTimer * lbl_803DD570->lateralDelta + lbl_803DD570->
            startLateralOffset;
        lbl_803DD570->verticalOffset = lbl_803DD570->blendTimer * lbl_803DD570->verticalDelta + lbl_803DD570->
            startVerticalOffset;
    }
    if (m != 2 && m != 5)
    {
        lbl_803DD570->smoothedZOffset = -(((f32)focus->anim.rotZ / lbl_803E1964) * timeDelta - lbl_803DD570->
            smoothedZOffset);
        lbl_803DD570->smoothedYOffset = -(((f32)focus->anim.rotY / lbl_803E1968) * timeDelta - lbl_803DD570->
            smoothedYOffset);
        fc = lbl_803E196C;
        fa = lbl_803E196C * lbl_803DD570->smoothedZOffset;
        lbl_803DD570->smoothedZOffset = -(fa * timeDelta - lbl_803DD570->smoothedZOffset);
        fa = fc * lbl_803DD570->smoothedYOffset;
        lbl_803DD570->smoothedYOffset = -(fa * timeDelta - lbl_803DD570->smoothedYOffset);
        ((CameraObject*)cam)->anim.worldPosY = lbl_803DD570->smoothedYOffset + (focus->anim.worldPosY + lbl_803DD570->
            verticalOffset);
    }
    else
    {
        lbl_803DD570->smoothedZOffset = -(((f32)focus->anim.rotZ / lbl_803E1964) * timeDelta - lbl_803DD570->
            smoothedZOffset);
        lbl_803DD570->smoothedYOffset = -(((f32)focus->anim.rotY / lbl_803E1968) * timeDelta - lbl_803DD570->
            smoothedYOffset);
        fc = lbl_803E196C;
        fa = lbl_803E196C * lbl_803DD570->smoothedZOffset;
        lbl_803DD570->smoothedZOffset = -(fa * timeDelta - lbl_803DD570->smoothedZOffset);
        fa = fc * lbl_803DD570->smoothedYOffset;
        lbl_803DD570->smoothedYOffset = -(fa * timeDelta - lbl_803DD570->smoothedYOffset);
        ((CameraObject*)cam)->anim.worldPosY = lbl_803DD570->smoothedYOffset + (focus->anim.worldPosY + lbl_803DD570->
            verticalOffset);
    }
    ((CameraObject*)cam)->anim.worldPosX = (lbl_803E1970 + focus->anim.worldPosX) + lbl_803DD570->lateralOffset;
    ((CameraObject*)cam)->anim.worldPosZ = focus->anim.worldPosZ + lbl_803DD570->smoothedZOffset;
    cam[1] = 0x708;
    cam[0] = 0x4000;
    cam[2] = (s16)(-focus->anim.rotZ >> 3);
    ((CameraObject*)cam)->fov = lbl_803E1974;
    r = (lbl_803DD570->targetLateralOffset - lbl_803DD570->lateralOffset) / lbl_803E1978;
    if (r > lbl_803E197C)
    {
        r = lbl_803E197C;
    }
    else if (r < lbl_803E1980)
    {
        r = lbl_803E1980;
    }
    r = r * timeDelta;
    lbl_803DD570->lateralOffset = lbl_803DD570->lateralOffset + r;
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

    if (lbl_803DD570 == (CameraModeShipBattleState*)0x0)
    {
        lbl_803DD570 = (CameraModeShipBattleState*)mmAlloc(sizeof(CameraModeShipBattleState), 0xf, 0);
    }
    fval = lbl_803E1954;
    lbl_803DD570->smoothedZOffset = lbl_803E1954;
    lbl_803DD570->smoothedYOffset = fval;
    lbl_803DD570->lateralOffset = lbl_803E1978;
    fval = lbl_803E194C;
    lbl_803DD570->startLateralOffset = lbl_803E194C;
    lbl_803DD570->targetLateralOffset = fval;
    lbl_803DD570->blendTimer = lbl_803E195C;
    zero = 0;
    lbl_803DD570->mode = zero;
    fval = lbl_803E1950;
    lbl_803DD570->startVerticalOffset = lbl_803E1950;
    lbl_803DD570->verticalOffset = fval;
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
    mm_free(lbl_803DD570);
    lbl_803DD570 = 0;
}

void CameraModeClimb_free(void);
