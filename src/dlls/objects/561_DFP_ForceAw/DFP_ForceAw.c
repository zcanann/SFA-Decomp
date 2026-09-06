/*
 * tesla / "Tricky curve" trigger object.
 *
 * A box-shaped trigger volume centred on the object that watches the
 * player's offset from the object on each axis. When the player is inside
 * the half-extents on all three axes (insideAxes == 3) the object reacts:
 *  - TrickyCurve_updateCooldownHit is the cooldown variant: throttled by state->cooldown
 *    (decremented by timeDelta, reset to TRICKY_CURVE_COOLDOWN_TICKS after
 *    a hit). A sliding player (player anim state ==
 *    TRICKY_CURVE_PLAYER_ANIM_SLIDE) sets the hit game bit and spawns the
 *    cooldown partfx; otherwise the player takes a recorded hit. Either
 *    way a sfx plays.
 *  - TrickyCurve_updateBurstHit is the burst variant: spawns a directional burst partfx
 *    (the PartFxSpawnParams packet carries the player-relative deltas and an
 *    x-rotation flip when the player crosses the x midline) and, off the
 *    slide path, messages the player and plays the burst sfx. The
 *    gTrickyCurveBurstCounter gates the bit/sfx to once every
 *    TRICKY_CURVE_BURST_LIMIT ticks while sliding.
 *
 * Both variants cache the entry side per axis (xSide/ySide/zSide) in the
 * trigger state so the burst variant can detect a midline crossing.
 */
#include "main/dll/partfx_interface.h"
#include "main/gamebits.h"
#include "sys/objects.h"
#include "main/frame_timing.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll_000A_expgfx.h"
#include "game/objects/object_setup.h"
#include "main/dll/trickycurve_state.h"
#include "main/dll/TrickyCurve.h"
#include "main/gamebit_ids.h"
#include "dlls/object_descriptor.h"
#include "main/vecmath.h"
#include "main/dll/player_api.h"
#include "main/objhits.h"
#include "main/obj_message.h"
#include "main/audio/sfx_play_api.h"

#define TRICKY_CURVE_GAMEBIT_HIT       0x468
#define TRICKY_CURVE_PLAYER_ANIM_SLIDE 0x1d7
#define TRICKY_CURVE_COOLDOWN_TICKS    200
#define TRICKY_CURVE_BURST_LIMIT       0x14
#define TRICKY_CURVE_HIT_PRIORITY      0x14
#define TRICKY_CURVE_MESSAGE_BURST     0x60004
#define TRICKY_CURVE_PARTFX_COOLDOWN   0x397
#define TRICKY_CURVE_PARTFX_BURST      0x399
#define TRICKY_CURVE_SFX_BURST         0x1c9
#define TRICKY_CURVE_SFX_COOLDOWN      0x1ca


u8
    gTrickyCurveBurstCounter; /* inter-frame burst-fire counter; reset to 0 after TRICKY_CURVE_BURST_LIMIT ticks */

void TrickyCurve_updateCooldownHit(GameObject* obj)
{
    u8 insideAxes;
    TrickyCurveObjState* state;
    GameObject* player;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    f32 xDelta;
    f32 zDelta;
    f32 yDelta;

    state = (TrickyCurveObjState*)obj->extra;
    player = (GameObject*)Obj_GetPlayerObject();
    insideAxes = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;

    xDelta = player->anim.localPosX - obj->anim.localPosX;
    yDelta = player->anim.localPosY - obj->anim.localPosY;
    zDelta = player->anim.localPosZ - obj->anim.localPosZ;

    if (xDelta <= 0.0f)
    {
        if (xDelta > -(f32)state->rangeX)
        {
            insideAxes = 1;
            xSide = 1;
        }
    }
    if (xDelta > 0.0f)
    {
        if (xDelta < state->rangeX)
        {
            insideAxes++;
            xSide--;
        }
    }
    if (zDelta <= 0.0f)
    {
        if (zDelta > -(f32)state->rangeZ)
        {
            insideAxes++;
            zSide = 1;
        }
    }
    if (zDelta > 0.0f)
    {
        if (zDelta < state->rangeZ)
        {
            insideAxes++;
            zSide--;
        }
    }
    if (yDelta <= 0.0f)
    {
        if (yDelta > -(f32)state->rangeY)
        {
            insideAxes++;
            ySide = 1;
        }
    }
    if (yDelta > 0.0f)
    {
        if (yDelta < state->rangeY)
        {
            insideAxes++;
            ySide--;
        }
    }

    if (state->cooldown >= 0)
    {
        state->cooldown -= (s16)timeDelta;
    }
    if (insideAxes == 3 && state->cooldown <= 0)
    {
        if (objGetAnimState80A(player) == TRICKY_CURVE_PLAYER_ANIM_SLIDE)
        {
            mainSetBits(TRICKY_CURVE_GAMEBIT_HIT, 1);
            (*gPartfxInterface)->spawnObject(player, TRICKY_CURVE_PARTFX_COOLDOWN, NULL, 2, -1, NULL);
        }
        else
        {
            ObjHits_RecordObjectHit(player, NULL, TRICKY_CURVE_HIT_PRIORITY, 2, 0);
        }
        Sfx_PlayFromObject(player, TRICKY_CURVE_SFX_COOLDOWN);
        state->cooldown = TRICKY_CURVE_COOLDOWN_TICKS;
    }

    state->xSide = xSide;
    state->ySide = ySide;
    state->zSide = zSide;
}

void TrickyCurve_updateBurstHit(GameObject* obj)
{
    u8 insideAxes;
    TrickyCurveObjState* state;
    GameObject* player;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    f32 xDelta;
    f32 zDelta;
    f32 yDelta;
    PartFxSpawnParams partfxArgs;

    state = (TrickyCurveObjState*)obj->extra;
    player = (GameObject*)Obj_GetPlayerObject();
    insideAxes = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;

    xDelta = player->anim.localPosX - obj->anim.localPosX;
    yDelta = player->anim.localPosY - obj->anim.localPosY;
    zDelta = player->anim.localPosZ - obj->anim.localPosZ;
    gTrickyCurveBurstCounter++;

    if (xDelta <= 0.0f)
    {
        if (xDelta > -(f32)state->rangeX)
        {
            insideAxes = 1;
            xSide = 1;
        }
    }
    if (xDelta > 0.0f)
    {
        if (xDelta < state->rangeX)
        {
            insideAxes++;
            xSide--;
        }
    }
    if (zDelta <= 0.0f)
    {
        if (zDelta > -(f32)state->rangeZ)
        {
            insideAxes++;
            zSide = 1;
        }
    }
    if (zDelta > 0.0f)
    {
        if (zDelta < state->rangeZ)
        {
            insideAxes++;
            zSide--;
        }
    }
    if (yDelta <= 0.0f)
    {
        if (yDelta > -(f32)state->rangeY)
        {
            insideAxes++;
            ySide = 1;
        }
    }
    if (yDelta > 0.0f)
    {
        if (yDelta < state->rangeY)
        {
            insideAxes++;
            ySide--;
        }
    }

    if (insideAxes == 3)
    {
        partfxArgs.posX = xDelta;
        partfxArgs.posY = yDelta;
        partfxArgs.posZ = zDelta;
        partfxArgs.scale = 1.0f;
        partfxArgs.rotZ = 0;
        partfxArgs.rotY = 0;
        partfxArgs.rotX = 0;
        if (xSide != state->xSide)
        {
            partfxArgs.rotX = 0x3fff;
        }

        if (objGetAnimState80A(player) == TRICKY_CURVE_PLAYER_ANIM_SLIDE)
        {
            if (gTrickyCurveBurstCounter > TRICKY_CURVE_BURST_LIMIT)
            {
                gTrickyCurveBurstCounter = 0;
                mainSetBits(TRICKY_CURVE_GAMEBIT_HIT, 1);
                Sfx_PlayFromObject(obj, TRICKY_CURVE_SFX_BURST);
            }
            (*gPartfxInterface)->spawnObject(player, TRICKY_CURVE_PARTFX_COOLDOWN, NULL, 2, -1, NULL);
        }
        else
        {
            mainSetBits(TRICKY_CURVE_GAMEBIT_HIT, 1);
            ObjMsg_SendToObject(player, TRICKY_CURVE_MESSAGE_BURST, obj, 2);
            (*gPartfxInterface)->spawnObject(obj, TRICKY_CURVE_PARTFX_BURST, &partfxArgs, 2, -1, NULL);
            Sfx_PlayFromObject(obj, TRICKY_CURVE_SFX_BURST);
        }
    }

    state->xSide = xSide;
    state->ySide = ySide;
    state->zSide = zSide;
}

/*
 * TrickyCurve (DLL 0xEC) - axis-aligned box trigger that applies a random
 * velocity kick to the player when they enter the volume. Used for the
 * "Tricky curve" current-like push zone. The box half-extents are stored in
 * TrickyCurveState; the object's world position is the centre. On each update
 * the function counts how many of the three axis intervals contain the player
 * (requires all three = axisCount 3) then fires a random horizontal nudge.
 */
void TrickyCurve_updateCooldownTrigger(GameObject* obj)
{
    GameObject* curve;
    TrickyCurveObjState* state;
    GameObject* player;
    int axisCount;
    f32 deltaX;
    f32 deltaZ;
    f32 deltaY;
    f32 bound;
    f32 randomX;
    f32 randomZ;

    curve = obj;
    state = (TrickyCurveObjState*)curve->extra;
    player = Obj_GetPlayerObject();
    axisCount = 0;
    deltaX = player->anim.localPosX - curve->anim.localPosX;
    deltaY = player->anim.localPosY - curve->anim.localPosY;
    deltaZ = player->anim.localPosZ - curve->anim.localPosZ;

    if (deltaX <= 0.0f)
    {
        bound = state->rangeX;
        if (deltaX > -bound)
        {
            axisCount = 1;
        }
    }
    if (deltaX > 0.0f)
    {
        bound = state->rangeX;
        if (deltaX < bound)
        {
            axisCount = axisCount + 1;
        }
    }

    if (deltaZ <= 0.0f)
    {
        bound = state->rangeZ;
        if (deltaZ > -bound)
        {
            axisCount = axisCount + 1;
        }
    }
    if (deltaZ > 0.0f)
    {
        bound = state->rangeZ;
        if (deltaZ < bound)
        {
            axisCount = axisCount + 1;
        }
    }

    if (deltaY <= 0.0f)
    {
        bound = state->rangeY;
        if (deltaY > -bound)
        {
            axisCount = axisCount + 1;
        }
    }
    if (deltaY > 0.0f)
    {
        bound = state->rangeY;
        if (deltaY < bound)
        {
            axisCount = axisCount + 1;
        }
    }

    if ((u8)axisCount == 3)
    {
        randomX = 0.01f * randomGetRange(-0x17, 0x17);
        randomZ = 0.01f * randomGetRange(-0x17, 0x17);
        playerApplyHorizontalVelocity_nop((int)player, randomX, randomZ);
    }
    return;
}

/*
 * Ocean Force Point Temple force-field object (DLL 0x231; "DFP_ForceAw"),
 * implemented on the shared TrickyCurve state machine and sfxplayer: a
 * curve-driven hazard/barrier with per-state update handlers.
 */
typedef struct TrickyCurveObjectDef
{
    ObjPlacement head; /* 0x00 */
    s8 rangeYRaw; /* 0x18 << 2 -> state.rangeY */
    u8 variant; /* 0x19 -> state.variant and state.mode */
    s16 rangeX;         /* 0x1A -> state.rangeX (X-axis half-extent) */
    s16 rangeZ;         /* 0x1C -> state.rangeZ */
    s16 triggerGameBit; /* 0x1E -> state.triggerGameBit */
    s16 gateGameBit;    /* 0x20 -> state.gateGameBit */
    u8 pad22[0x28 - 0x22];
} TrickyCurveObjectDef;

#define DFPFORCEAW_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DFPFORCEAW_MSG_PLAYER_BURST           0x60004 /* knock the player back with a burst hit */

/* partfx ids spawned on the player-burst trigger: single burst flash plus a
 * 10-count spray of burst particles (same shape in both mainGetBit(0x1d9) arms) */
#define DFPFORCEAW_PARTFX_BURST          0x5ed /* spawned once */
#define DFPFORCEAW_PARTFX_BURST_PARTICLE 0x5fd /* spawned 10x */

void TrickyCurve_updateBurstTrigger(GameObject* obj)
{
    TrickyCurveObjState* state;
    GameObject* player;
    f32 dx;
    f32 dz;
    f32 dy;
    u8 insideCount;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    PartFxSpawnParams fxParams;
    int burstParticles;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    insideCount = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;
    dx = player->anim.localPosX - obj->anim.localPosX;
    dy = player->anim.localPosY - obj->anim.localPosY;
    dz = player->anim.localPosZ - obj->anim.localPosZ;

    if ((state->gateGameBit != -1) &&
        (mainGetBit(state->gateGameBit) != 0))
    {
        return;
    }

    if (mainGetBit(state->triggerGameBit) != 0)
    {
        mainSetBits(state->triggerGameBit, 0);
    }

    if (dx <= 0.0f)
    {
        if (dx > -(f32)state->rangeX)
        {
            insideCount = 1;
            xSide = 1;
        }
    }
    if (dx > 0.0f)
    {
        if (dx < (f32)state->rangeX)
        {
            insideCount++;
            xSide--;
        }
    }
    if (dz <= 0.0f)
    {
        if (dz > -(f32)state->rangeZ)
        {
            insideCount++;
            zSide = 1;
        }
    }
    if (dz > 0.0f)
    {
        if (dz < (f32)state->rangeZ)
        {
            insideCount++;
            zSide--;
        }
    }
    if (dy <= 0.0f)
    {
        if (dy > -(f32)state->rangeY)
        {
            insideCount++;
            ySide = 1;
        }
    }
    if (dy > 0.0f)
    {
        if (dy < (f32)state->rangeY)
        {
            insideCount++;
            ySide--;
        }
    }

    if (insideCount == 3)
    {
        fxParams.posX = dx;
        fxParams.posY = dy;
        fxParams.posZ = dz;
        fxParams.scale = 1.0f;
        fxParams.rotZ = 0;
        fxParams.rotY = 0;
        fxParams.rotX = 0;
        if (xSide != state->xSide)
        {
            fxParams.rotX = 0x3fff;
        }

        if (mainGetBit(0x1d9) != 0)
        {
            mainSetBits(GAMEBIT_TRICKYCURVE_PLAYER_HIT, 1);
            ObjMsg_SendToObject((void*)player, DFPFORCEAW_MSG_PLAYER_BURST, obj, 0);
            (*gPartfxInterface)->spawnObject((void*)obj, DFPFORCEAW_PARTFX_BURST, &fxParams, 2, -1, NULL);
            burstParticles = 9;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, DFPFORCEAW_PARTFX_BURST_PARTICLE, &fxParams, 2, -1, NULL);
            } while (burstParticles-- != 0);
        }
        else
        {
            ObjMsg_SendToObject((void*)player, DFPFORCEAW_MSG_PLAYER_BURST, obj, 1);
            (*gPartfxInterface)->spawnObject((void*)obj, DFPFORCEAW_PARTFX_BURST, &fxParams, 2, -1, NULL);
            burstParticles = 9;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, DFPFORCEAW_PARTFX_BURST_PARTICLE, &fxParams, 2, -1, NULL);
            } while (burstParticles-- != 0);
        }
        mainSetBits(state->triggerGameBit, 1);
        Sfx_PlayFromObject(obj, SFXTRIG_wp_fball2_c_1c9);
    }

    state->xSide = xSide;
    state->ySide = ySide;
    state->zSide = zSide;
}

int TrickyCurve_getExtraSize(void)
{
    return 0x14;
}
int TrickyCurve_getObjectTypeId(void)
{
    return 0x0;
}

void TrickyCurve_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void TrickyCurve_render(void)
{
}

void TrickyCurve_hitDetect(void)
{
}

void TrickyCurve_update(GameObject* obj)
{
    TrickyCurveObjState* inner = obj->extra;
    u32 state = inner->mode;
    if (state == 0)
    {
        TrickyCurve_updateBurstTrigger(obj);
    }
    else if (state == 1)
    {
        TrickyCurve_updateCooldownTrigger(obj);
    }
    else if (state == 2)
    {
        TrickyCurve_updateBurstHit(obj);
    }
    else if (state == 3)
    {
        TrickyCurve_updateCooldownHit(obj);
    }
}

void TrickyCurve_init(GameObject* obj, u8* def)
{
    TrickyCurveObjState* state = obj->extra;
    state->variant = ((TrickyCurveObjectDef*)def)->variant;
    state->rangeY = (s16)((s32)((TrickyCurveObjectDef*)def)->rangeYRaw << 2);
    state->rangeX = ((TrickyCurveObjectDef*)def)->rangeX;
    state->rangeZ = ((TrickyCurveObjectDef*)def)->rangeZ;
    state->mode = ((TrickyCurveObjectDef*)def)->variant;
    state->xSide = 0;
    state->ySide = 0;
    state->zSide = 0;
    state->gateGameBit = ((TrickyCurveObjectDef*)def)->gateGameBit;
    state->triggerGameBit = ((TrickyCurveObjectDef*)def)->triggerGameBit;
    state->cooldown = 0;
    obj->objectFlags = (u16)(obj->objectFlags | DFPFORCEAW_OBJFLAG_HITDETECT_DISABLED);
}

void TrickyCurve_release(void)
{
}

void TrickyCurve_initialise(void)
{
}

ObjectDescriptor gTrickyCurveObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)TrickyCurve_initialise,
    (ObjectDescriptorCallback)TrickyCurve_release,
    0,
    (ObjectDescriptorCallback)TrickyCurve_init,
    (ObjectDescriptorCallback)TrickyCurve_update,
    (ObjectDescriptorCallback)TrickyCurve_hitDetect,
    (ObjectDescriptorCallback)TrickyCurve_render,
    (ObjectDescriptorCallback)TrickyCurve_free,
    (ObjectDescriptorCallback)TrickyCurve_getObjectTypeId,
    TrickyCurve_getExtraSize,
};
