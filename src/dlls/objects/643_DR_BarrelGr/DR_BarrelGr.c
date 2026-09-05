#include "dlls/objects/643_DR_BarrelGr.h"

/*
 * DR_BarrelGr (DLL 643) - a barrel-grabber: a magnet/tractor device
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
#include "dolphin/mtx.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/maketex_timer_api.h"
#include "main/obj_path.h"
#include "main/objtype.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "dlls/objects/344.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objfx.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"
#include "dolphin/mtx/vec.h"
#include "sys/objects.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"

f32 gDRBarrelGrThrowScale = 2.0f;
f32 gDrBarrelGenGrabYOffset = -50.0f;

enum DrbarrelgrMode {
    DRBARRELGR_MODE_SCAN = 0,       /* look for a grabbable barrel in range */
    DRBARRELGR_MODE_WAIT = 1,       /* hold at curve waypoint; release if holding */
    DRBARRELGR_MODE_RAMP_SPEED = 2, /* ramp the carry speed before moving */
    DRBARRELGR_MODE_RELEASE = 3,    /* drop the held barrel */
    DRBARRELGR_MODE_GRAB = 4,       /* reel the locked-on barrel toward the grab point */
    DRBARRELGR_MODE_CARRY = 5       /* follow the rom curve carrying the barrel */
};

int DR_BarrelGr_getExtraSize(void) {
    return sizeof(DrbarrelgrState);
}

int DR_BarrelGr_getObjectTypeId(void) {
    return 0;
}

void DR_BarrelGr_free(GameObject* obj) {
    DrbarrelgrState* state = obj->extra;
    GameObject* heldObj = state->heldBarrel;

    if (heldObj != NULL) {
        gunpowderBarrel_clearHeldState(heldObj);
        state->flags.bit80 = 0;
    }
}

void DR_BarrelGr_render(GameObject* obj, int p2, int p3, int p4, int p5) {
    f32* pathPointZ;
    f32* pathPointY;
    f32* pathPointCoords;
    DrbarrelgrState* state = obj->extra;
    GameObject* objRef;
    GameObject* nearest;
    int match;
    int i;
    f32 dval;
    f32 pathPoint[3];
    DrBarrelGrRenderParams params;

    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    ObjPath_GetPointWorldPosition(obj, 0, &state->grabX, &state->grabY, &state->grabZ, 0);
    params.a = 0;
    params.c = 0;
    params.b = 0x4000;
    i = 0;
    pathPointZ = &pathPoint[2];
    pathPointY = &pathPoint[1];
    pathPointCoords = &pathPoint[0];
    dval = 0.0f;
    for (; i < 4; i++) {
        ObjPath_GetPointWorldPosition(obj, i + 1, pathPointCoords, pathPointY, pathPointZ, 0);
        PSVECSubtract((Vec*)pathPointCoords, (const Vec*)&obj->anim.localPosX, (Vec*)pathPointCoords);
        params.d = dval;
        objfx_spawnLightPulse(obj, 0.3f, 3, 0, 0, 0.15f, &params);
    }
    objRef = state->heldBarrel;
    if (objRef != NULL) {
        nearest = objGetNearestTypeTo(GUNPOWDER_BARREL_OBJECT_GROUP, obj, NULL);
        match = 0;
        if (nearest != NULL && objRef == nearest) {
            match = 1;
        }
        if (match && state->mode != DRBARRELGR_MODE_GRAB) {
            state->heldBarrel->anim.localPosX = state->grabX;
            state->heldBarrel->anim.localPosY = state->grabY;
            state->heldBarrel->anim.localPosZ = state->grabZ;
            objRenderModelAndHitVolumes(state->heldBarrel, p2, p3, p4, p5, 1.0f);
        }
    }
}

void DR_BarrelGr_hitDetect(void) {
}

void DR_BarrelGr_update(GameObject* obj) {
    DrbarrelgrState* state = obj->extra;
    DrbarrelgrPlacement* setup = (DrbarrelgrPlacement*)obj->anim.placementData;
    int newMode = -1;
    DrBarrelGrFlags* flags = &state->flags;
    GameObject* nearest;
    int match;
    int gameBit;
    f32 traceTarget[3];
    f32 throwDir[3];

    {
        GameObject* held = state->heldBarrel;
        if (held != NULL) {
            nearest = objGetNearestTypeTo(GUNPOWDER_BARREL_OBJECT_GROUP, obj, NULL);
            match = 0;
            if (nearest != NULL && held == nearest) {
                match = 1;
            }
            if (match == 0 || (flags->bit80 != 0 && gunpowderBarrel_isHeld(state->heldBarrel) == 0)) {
                state->heldBarrel = 0;
                flags->bit80 = 0;
            }
        }
    }

    gameBit = setup->gameBit;
    if (gameBit != -1 && mainGetBit(gameBit) == 0) {
        flags->bit40 = 0;
        return;
    }
    flags->bit40 = 1;
    Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_bcrek1_c);

    switch (state->mode) {
    case DRBARRELGR_MODE_SCAN:
        if (state->heldBarrel == NULL) {
            nearest = objGetNearestTypeTo(GUNPOWDER_BARREL_OBJECT_GROUP, obj, NULL);
            if (nearest != NULL && Vec_xzDistance(&obj->anim.worldPosX, &nearest->anim.worldPosX) < 20.0f &&
                nearest->anim.localPosY < obj->anim.localPosY) {
                traceTarget[0] = nearest->anim.localPosX;
                traceTarget[1] = 10.0f + nearest->anim.localPosY;
                traceTarget[2] = nearest->anim.localPosZ;
                if (voxmaps_traceWorldLine((void*)&obj->anim.localPosX, traceTarget) != 0 &&
                    gunpowderBarrel_canBeGrabbed(nearest) != 0) {
                    Sfx_PlayFromObject(obj, SFXTRIG_jbike_snowspray);
                    newMode = DRBARRELGR_MODE_GRAB;
                    state->heldBarrel = nearest;
                }
                break;
            }
        }
        if (timerCountDown(&state->timer) != 0) {
            newMode = DRBARRELGR_MODE_CARRY;
        }
        break;
    case DRBARRELGR_MODE_GRAB:
        if (state->heldBarrel == NULL || gunpowderBarrel_canBeGrabbed(state->heldBarrel) == 0) {
            state->mode = DRBARRELGR_MODE_SCAN;
            state->heldBarrel = NULL;
            flags->bit80 = 0;
            break;
        }
        if (Vec_xzDistance(&obj->anim.worldPosX, &state->heldBarrel->anim.worldPosX) > 20.0f) {
            newMode = state->prevMode;
            flags->bit80 = 0;
            state->heldBarrel = NULL;
            break;
        }
        PSVECSubtract((const Vec*)&state->grabX, (const Vec*)&state->heldBarrel->anim.localPosX, (Vec*)throwDir);
        {
            f32 zero = 0.0f;
            if (throwDir[0] != zero || throwDir[1] != zero || throwDir[2] != zero) {
                PSVECNormalize((const Vec*)throwDir, (Vec*)throwDir);
            }
        }
        PSVECScale((const Vec*)throwDir, (Vec*)throwDir, gDRBarrelGrThrowScale);
        gunpowderBarrel_addThrowVelocity(state->heldBarrel, throwDir);
        if (PSVECDistance((const Vec*)&state->grabX, (const Vec*)&state->heldBarrel->anim.localPosX) < 1.0f ||
            state->heldBarrel->anim.localPosY > state->grabY) {
            Sfx_PlayFromObject(obj, SFXTRIG_jbike_boost);
            gunpowderBarrel_setHeldState(state->heldBarrel);
            newMode = state->prevMode;
            flags->bit80 = 1;
            ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        }
        break;
    case DRBARRELGR_MODE_CARRY: {
        f32 spd = 0.1f * (f32)state->carrySpeed;
        int r = Obj_UpdateRomCurveFollowVelocity(obj, &state->curve, spd * timeDelta, 200.0f, 10.0f, 1);
        objMove(obj, obj->anim.velocityX, obj->anim.velocityY, obj->anim.velocityZ);
        if (r != 0) {
            newMode = r - 1;
            storeZeroToFloatParam(&state->timer);
            s16toFloat(&state->timer, setup->range);
            {
                f32 z = 0.0f;
                obj->anim.velocityX = z;
                obj->anim.velocityY = z;
                obj->anim.velocityZ = z;
            }
        }
        break;
    }
    case DRBARRELGR_MODE_RAMP_SPEED:
        if (state->carrySpeed == setup->speed) {
            f32 slowdown = 0.3f;
            state->carrySpeed = (f32)state->carrySpeed * slowdown;
        } else {
            state->carrySpeed = setup->speed;
        }
        storeZeroToFloatParam(&state->timer);
        newMode = DRBARRELGR_MODE_CARRY;
        break;
    case DRBARRELGR_MODE_WAIT:
        if (state->heldBarrel != NULL) {
            newMode = DRBARRELGR_MODE_RELEASE;
        } else if (timerCountDown(&state->timer) != 0) {
            newMode = DRBARRELGR_MODE_CARRY;
        }
        break;
    case DRBARRELGR_MODE_RELEASE:
        if (state->heldBarrel != NULL) {
            gunpowderBarrel_clearHeldState(state->heldBarrel);
            flags->bit80 = 0;
            ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        }
        state->heldBarrel = NULL;
        newMode = state->prevMode;
        break;
    }

    ObjAnim_AdvanceCurrentMove(obj, 0.05f, timeDelta, 0);
    if (newMode != -1 && newMode != state->mode) {
        state->prevMode = state->mode;
        state->mode = newMode;
    }
    if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) == 0 && state->heldBarrel != NULL) {
        state->grabX = obj->anim.localPosX;
        state->grabY = obj->anim.localPosY + gDrBarrelGenGrabYOffset;
        state->grabZ = obj->anim.localPosZ;
        state->heldBarrel->anim.localPosX = state->grabX;
        state->heldBarrel->anim.localPosY = state->grabY;
        state->heldBarrel->anim.localPosZ = state->grabZ;
    }
}

void DR_BarrelGr_init(GameObject* obj, DrbarrelgrPlacement* setup) {
    int one;
    DrbarrelgrState* state;
    DrbarrelgrPlacement* placement = setup;

    one = 1;
    state = obj->extra;
    if (placement->speed == 0) {
        placement->speed = 0xa;
    }
    if (placement->range <= 0) {
        placement->range = 0x64;
    }
    state->mode = DRBARRELGR_MODE_CARRY;
    state->heldBarrel = NULL;
    state->flags.bit80 = 0;
    state->carrySpeed = placement->speed;
    state->unk10 = 0.0f;
    state->prevMode = -3;
    state->flags.bit40 = 0;
    storeZeroToFloatParam(&state->timer);
    s16toFloat(&state->timer, placement->range);
    obj->anim.rotX = (s16)(placement->spawnYawByte << 8);
    (*gRomCurveInterface)->initCurve(&state->curve, (void*)obj, 500.0f, &one, 0);
    obj->anim.localPosX = state->curve.posX;
    obj->anim.localPosZ = state->curve.posZ;
    obj->anim.localPosY = state->curve.posY;
}

void DR_BarrelGr_release(void) {
}

void DR_BarrelGr_initialise(void) {
}

ObjectDescriptor gDrBarrelGrObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DR_BarrelGr_initialise,
    (ObjectDescriptorCallback)DR_BarrelGr_release,
    0,
    (ObjectDescriptorCallback)DR_BarrelGr_init,
    (ObjectDescriptorCallback)DR_BarrelGr_update,
    (ObjectDescriptorCallback)DR_BarrelGr_hitDetect,
    (ObjectDescriptorCallback)DR_BarrelGr_render,
    (ObjectDescriptorCallback)DR_BarrelGr_free,
    (ObjectDescriptorCallback)DR_BarrelGr_getObjectTypeId,
    DR_BarrelGr_getExtraSize,
};
