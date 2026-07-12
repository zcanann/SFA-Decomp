/*
 * drbarrelgr (DLL 0x283) - a barrel-grabber: a magnet/tractor device
 * that pulls a nearby gunpowder barrel to itself and carries it along a
 * rom-curve path.
 *
 * update is a small state machine (mode in state->mode): mode 0 scans
 * group 25 for a grabbable barrel in range/below it and locks on (mode
 * 4); mode 4 drags the held barrel toward the grab point and, once close,
 * marks it held; mode 5 follows the rom curve at a speed derived from the
 * placement speed; mode 2 ramps the carry speed; modes 1/3 release. A
 * placement game bit (0x20) gates the whole device. init clamps the
 * placement speed/range defaults, seeds the curve and start position,
 * and render draws the device, its path light pulses and the held barrel.
 */
#include "main/dll/dll_80220608_shared.h"
#include "dolphin/mtx.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/dll_0158_gunpowderbarrel.h"
#include "main/dll/DR/dll_0283_drbarrelgr.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objfx.h"

#define DRBARRELGR_OBJFLAG_RENDERED     0x800
#define GUNPOWDERBARREL_UPDATE_OBJGROUP 0x19 /* DLL 0x158 gunpowderbarrel (update group) */

enum DrbarrelgrMode
{
    DRBARRELGR_MODE_SCAN = 0,       /* look for a grabbable barrel in range */
    DRBARRELGR_MODE_WAIT = 1,       /* hold at curve waypoint; release if holding */
    DRBARRELGR_MODE_RAMP_SPEED = 2, /* ramp the carry speed before moving */
    DRBARRELGR_MODE_RELEASE = 3,    /* drop the held barrel */
    DRBARRELGR_MODE_GRAB = 4,       /* reel the locked-on barrel toward the grab point */
    DRBARRELGR_MODE_CARRY = 5       /* follow the rom curve carrying the barrel */
};

int DR_BarrelGr_getExtraSize(void)
{
    return 0x12c;
}

int DR_BarrelGr_getObjectTypeId(void)
{
    return 0;
}

void DR_BarrelGr_free(GameObject* obj)
{
    DrbarrelgrState* state = obj->extra;
    GameObject* heldObj = state->heldBarrel;

    if (heldObj != NULL)
    {
        gunpowderbarrel_clearHeldState(heldObj);
        state->flags.bit80 = 0;
    }
}

void DR_BarrelGr_render(GameObject* obj, int p2, int p3, int p4, int p5)
{
    f32* vp2;
    f32* vp1;
    f32* vp;
    DrbarrelgrState* state = obj->extra;
    GameObject* objRef;
    int nearest;
    int match;
    int i;
    f32 dval;
    f32 pathPoint[3];
    DrBarrelGrRenderParams params;

    ((void (*)(void*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E6CA0);
    ((void (*)(void*, int, f32*, f32*, f32*, int))ObjPath_GetPointWorldPosition)(
        obj, 0, &state->grabX, &state->grabY, &state->grabZ, 0);
    params.a = 0;
    params.c = 0;
    params.b = 0x4000;
    i = 0;
    vp2 = &pathPoint[2];
    vp1 = &pathPoint[1];
    vp = &pathPoint[0];
    dval = lbl_803E6CA4;
    for (; i < 4; i++)
    {
        ((void (*)(void*, int, f32*, f32*, f32*, int))ObjPath_GetPointWorldPosition)(obj, i + 1, vp, vp1, vp2, 0);
        PSVECSubtract((Vec*)vp, (const Vec*)&obj->anim.localPosX, (Vec*)vp);
        params.d = dval;
        objfx_spawnLightPulseLegacy(obj, lbl_803E6CA8, 3, 0, 0, lbl_803E6CAC, &params);
    }
    objRef = state->heldBarrel;
    if ((u32)objRef != 0)
    {
        nearest = ((int (*)(int, void*, f32*))ObjGroup_FindNearestObject)(GUNPOWDERBARREL_UPDATE_OBJGROUP, obj, 0);
        match = 0;
        if ((u32)nearest != 0 && objRef == (GameObject*)nearest)
        {
            match = 1;
        }
        if (match && *(int*)state != 4)
        {
            state->heldBarrel->anim.localPosX = state->grabX;
            state->heldBarrel->anim.localPosY = state->grabY;
            state->heldBarrel->anim.localPosZ = state->grabZ;
            objRenderModelAndHitVolumes((int)state->heldBarrel, p2, p3, p4, p5, lbl_803E6CA0);
        }
    }
}

void DR_BarrelGr_hitDetect(void)
{
}

void DR_BarrelGr_update(GameObject* obj)
{
    DrbarrelgrState* state = obj->extra;
    DrbarrelgrPlacement* setup = (DrbarrelgrPlacement*)obj->anim.placementData;
    int newMode = -1;
    DrBarrelGrFlags* flags = &state->flags;
    int nearest;
    int match;
    int gameBit;
    f32 traceTarget[3];
    f32 throwDir[3];

    {
        GameObject* held = state->heldBarrel;
        if (held != NULL)
        {
            nearest = ((int (*)(int, void*, f32*))ObjGroup_FindNearestObject)(GUNPOWDERBARREL_UPDATE_OBJGROUP, obj, 0);
            match = 0;
            if ((u32)nearest != 0 && held == (GameObject*)nearest)
            {
                match = 1;
            }
            if (match == 0 || (flags->bit80 != 0 && gunpowderbarrel_isHeld(state->heldBarrel) == 0))
            {
                state->heldBarrel = 0;
                flags->bit80 = 0;
            }
        }
    }

    gameBit = setup->gameBit;
    if (gameBit != -1 && mainGetBit(gameBit) == 0)
    {
        flags->bit40 = 0;
        return;
    }
    flags->bit40 = 1;
    ((void (*)(void*, u16))Sfx_KeepAliveLoopedObjectSound)(obj, SFXTRIG_bcrek1_c);

    switch (state->mode)
    {
    case DRBARRELGR_MODE_SCAN:
        if (state->heldBarrel == NULL)
        {
            nearest = ((int (*)(int, void*, f32*))ObjGroup_FindNearestObject)(GUNPOWDERBARREL_UPDATE_OBJGROUP, obj, 0);
            if ((u32)nearest != 0 &&
                ((f32 (*)(void*, int))Vec_xzDistance)((char*)obj + 24, nearest + 24) < gDrBarrelGenGrabRange &&
                ((GameObject*)nearest)->anim.localPosY < obj->anim.localPosY)
            {
                traceTarget[0] = ((GameObject*)nearest)->anim.localPosX;
                traceTarget[1] = lbl_803E6CB4 + ((GameObject*)nearest)->anim.localPosY;
                traceTarget[2] = ((GameObject*)nearest)->anim.localPosZ;
                if (voxmaps_traceWorldLine((void*)&obj->anim.localPosX, traceTarget) != 0 &&
                    gunpowderbarrel_canBeGrabbed((GameObject*)nearest) != 0)
                {
                    ((void (*)(void*, u16))Sfx_PlayFromObject)(obj, SFXTRIG_jbike_snowspray);
                    newMode = DRBARRELGR_MODE_GRAB;
                    state->heldBarrel = (GameObject*)nearest;
                }
                break;
            }
        }
        if (timerCountDown(&state->timer) != 0)
        {
            newMode = DRBARRELGR_MODE_CARRY;
        }
        break;
    case DRBARRELGR_MODE_GRAB:
        if (state->heldBarrel == NULL || gunpowderbarrel_canBeGrabbed(state->heldBarrel) == 0)
        {
            state->mode = DRBARRELGR_MODE_SCAN;
            state->heldBarrel = NULL;
            flags->bit80 = 0;
            break;
        }
        if (Vec_xzDistance(&obj->anim.worldPosX, &state->heldBarrel->anim.worldPosX) >
            gDrBarrelGenGrabRange)
        {
            newMode = state->prevMode;
            flags->bit80 = 0;
            state->heldBarrel = NULL;
            break;
        }
        PSVECSubtract((const Vec*)&state->grabX, (const Vec*)&state->heldBarrel->anim.localPosX, (Vec*)throwDir);
        if (throwDir[0] != lbl_803E6CA4 || throwDir[1] != lbl_803E6CA4 || throwDir[2] != lbl_803E6CA4)
        {
            PSVECNormalize((const Vec*)throwDir, (Vec*)throwDir);
        }
        PSVECScale((const Vec*)throwDir, (Vec*)throwDir, lbl_803DC3B0);
        gunpowderbarrel_addThrowVelocity(state->heldBarrel, throwDir);
        if (PSVECDistance((const Vec*)&state->grabX, (const Vec*)&state->heldBarrel->anim.localPosX) < lbl_803E6CA0 ||
            state->heldBarrel->anim.localPosY > state->grabY)
        {
            ((void (*)(void*, u16))Sfx_PlayFromObject)(obj, SFXTRIG_jbike_boost);
            gunpowderbarrel_setHeldState(state->heldBarrel);
            newMode = state->prevMode;
            flags->bit80 = 1;
            ((int (*)(void*, int, f32, int))ObjAnim_SetCurrentMove)(obj, 0, lbl_803E6CA4, 0);
        }
        break;
    case DRBARRELGR_MODE_CARRY:
    {
        f32 spd = gDrBarrelGenCarrySpeedScale * (f32)state->carrySpeed;
        int r = Obj_UpdateRomCurveFollowVelocity(obj, &state->curve, spd * timeDelta,
                                                 lbl_803E6CBC, lbl_803E6CB4, 1);
        ((void (*)(void*, f32, f32, f32))objMove)(obj, obj->anim.velocityX, obj->anim.velocityY, obj->anim.velocityZ);
        if (r != 0)
        {
            newMode = r - 1;
            storeZeroToFloatParam(&state->timer);
            s16toFloat(&state->timer, setup->range);
            {
                f32 z = lbl_803E6CA4;
                obj->anim.velocityX = z;
                obj->anim.velocityY = z;
                obj->anim.velocityZ = z;
            }
        }
        break;
    }
    case DRBARRELGR_MODE_RAMP_SPEED:
        if (state->carrySpeed == setup->speed)
        {
            state->carrySpeed = (f32)state->carrySpeed * lbl_803E6CA8;
        }
        else
        {
            state->carrySpeed = setup->speed;
        }
        storeZeroToFloatParam(&state->timer);
        newMode = DRBARRELGR_MODE_CARRY;
        break;
    case DRBARRELGR_MODE_WAIT:
        if (state->heldBarrel != NULL)
        {
            newMode = DRBARRELGR_MODE_RELEASE;
        }
        else if (timerCountDown(&state->timer) != 0)
        {
            newMode = DRBARRELGR_MODE_CARRY;
        }
        break;
    case DRBARRELGR_MODE_RELEASE:
        if (state->heldBarrel != NULL)
        {
            gunpowderbarrel_clearHeldState(state->heldBarrel);
            flags->bit80 = 0;
            ((int (*)(void*, int, f32, int))ObjAnim_SetCurrentMove)(obj, 0, lbl_803E6CA4, 0);
        }
        state->heldBarrel = NULL;
        newMode = state->prevMode;
        break;
    }

    ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E6CC0, timeDelta, 0);
    if (newMode != -1 && newMode != state->mode)
    {
        state->prevMode = state->mode;
        state->mode = newMode;
    }
    if ((obj->objectFlags & DRBARRELGR_OBJFLAG_RENDERED) == 0 &&
        state->heldBarrel != NULL)
    {
        state->grabX = obj->anim.localPosX;
        state->grabY = obj->anim.localPosY + gDrBarrelGenGrabYOffset;
        state->grabZ = obj->anim.localPosZ;
        state->heldBarrel->anim.localPosX = state->grabX;
        state->heldBarrel->anim.localPosY = state->grabY;
        state->heldBarrel->anim.localPosZ = state->grabZ;
    }
}

void DR_BarrelGr_init(GameObject* obj, int setup)
{
    int one;
    DrbarrelgrState* state;
    DrbarrelgrPlacement* placement = (DrbarrelgrPlacement*)setup;

    one = 1;
    state = obj->extra;
    if (placement->speed == 0)
    {
        placement->speed = 0xa;
    }
    if (placement->range <= 0)
    {
        placement->range = 0x64;
    }
    state->mode = DRBARRELGR_MODE_CARRY;
    state->heldBarrel = NULL;
    state->flags.bit80 = 0;
    state->carrySpeed = placement->speed;
    state->unk10 = lbl_803E6CA4;
    state->prevMode = -3;
    state->flags.bit40 = 0;
    storeZeroToFloatParam(&state->timer);
    s16toFloat(&state->timer, placement->range);
    obj->anim.rotX = (s16)((s8)placement->spawnYawByte << 8);
    (*gRomCurveInterface)->initCurve(&state->curve, (void*)obj, lbl_803E6CD0, &one, 0);
    obj->anim.localPosX = state->curve.posX;
    obj->anim.localPosZ = state->curve.posZ;
    obj->anim.localPosY = state->curve.posY;
}

void DR_BarrelGr_release(void)
{
}

void DR_BarrelGr_initialise(void)
{
}
