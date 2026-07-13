/*
 * fxemit (DLL 0x12B, class 0x6B) - the CF "FxEmit" particle-emitter
 * object. Each instance reads an FxEmitPlacement and drifts/spins by a
 * per-axis step (FXEMIT_ROTATION_STEP_AUTO = framesThisStep auto-spin,
 * otherwise step*framesThisStep*100), optionally moving along its
 * velocity, and emits a particle effect when the player comes within
 * triggerRadius (or always, at the sentinel radius).
 *
 * Emission (fxemit_emitEffect) dispatches on the placement spawnMode:
 *   OBJECT/OBJECT_ALT/WORLD pick partfx spawn flags from effectMode,
 *   then either spawn a partfx object (effectMode 0), or acquire a
 *   resource (effectId+0x58 / effectId+0xAB) and call its slot-1 fn.
 *   The WORLD/mode-0 path (flag 1) instead spawns with explicit
 *   yaw/pitch/roll/scale/position args. emitCount>0 spawns that many;
 *   <=0 spawns the alt effect once and seeds a re-emit cooldown.
 *
 * Gated by enableBit/stopBit game bits; sfxPeriod drives a periodic
 * Sfx_PlayFromObject. SeqFn responds to anim events 1 (emit now) and 2
 * (toggle continuous emit). init lives here too; the placement is
 * defined by FXEMIT_DEF_ID 0x5A7.
 */
#include "main/dll/CF/dll_012B_fxemit.h"
#include "main/object_api.h"
#include "main/game_object.h"
#include "main/debug.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

typedef struct FxEmitWorldSpawnArgs
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} FxEmitWorldSpawnArgs;

extern char sCFTreasSharpyDebugFormat[];
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E3E30 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E3E34 = 0.2f;
__declspec(section ".sdata2") f32 lbl_803E3E38 = 400.0f;
__declspec(section ".sdata2") f32 lbl_803E3E3C = -1.0f;
__declspec(section ".sdata2") f32 lbl_803E3E40 = 600.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E3E44 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E3E48 = 1.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E3E4C = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E3E50 = 0.1f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E3E54 = 0.0f;
#pragma explicit_zero_data off

#define CFTREAS_PARTFX_SPAWN(obj, id, data, flags, model, arg)                                                         \
    (*gPartfxInterface)->spawnObject((void*)(obj), id, data, flags, model, (void*)(arg))

void fxemit_emitEffect(FxEmitObject* obj)
{
    FxEmitState* state;
    FxEmitPlacement* def;
    int spawnFlags;
    s16 i;

    state = obj->state;
    def = (FxEmitPlacement*)obj->objAnim.placementData;
    spawnFlags = 0;
    if (state->effectId == 0x11)
    {
        logPrintf(sCFTreasSharpyDebugFormat, obj, obj->objAnim.localPosX, obj->objAnim.localPosZ);
    }

    switch (def->spawnMode)
    {
    case FXEMIT_SPAWN_MODE_OBJECT:
    {
        s16 mode = state->effectMode;
        if (mode == 0)
        {
            spawnFlags = 2;
        }
        if (mode == 1)
        {
            spawnFlags = 2;
        }
        if (mode == 2)
        {
            spawnFlags = 2;
        }
        break;
    }
    case FXEMIT_SPAWN_MODE_OBJECT_ALT:
    {
        s16 mode = state->effectMode;
        if (mode == 0)
        {
            spawnFlags = 4;
        }
        if (mode == 1)
        {
            spawnFlags = 4;
        }
        if (mode == 2)
        {
            spawnFlags = 4;
        }
        break;
    }
    case FXEMIT_SPAWN_MODE_WORLD:
    {
        s16 mode = state->effectMode;
        if (mode == 0)
        {
            spawnFlags = 0x200001;
        }
        if (mode == 1)
        {
            spawnFlags = 1;
        }
        if (mode == 2)
        {
            spawnFlags = 1;
        }
        break;
    }
    case FXEMIT_SPAWN_MODE_NONE:
        spawnFlags = 0;
        break;
    default:
        spawnFlags = 2;
        break;
    }

    if ((spawnFlags & 1) != 0)
    {
        FxEmitWorldSpawnArgs args;

        args.x = obj->objAnim.localPosX;
        args.y = obj->objAnim.localPosY;
        args.z = obj->objAnim.localPosZ;
        args.yaw = obj->objAnim.rotX;
        args.roll = obj->objAnim.rotZ;
        args.pitch = obj->objAnim.rotY;
        args.scale = lbl_803E3E48;
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                CFTREAS_PARTFX_SPAWN(obj, state->effectId, &args, spawnFlags, -1, 0);
            }
        }
        else
        {
            CFTREAS_PARTFX_SPAWN(obj, state->altEffectId, &args, spawnFlags, -1, 0);
        }
    }
    else
    {
        void* resource;
        s16 mode = state->effectMode;

        if (mode == 0)
        {
            if (state->emitCount > 0)
            {
                for (i = 0; i < state->emitCount; i++)
                {
                    CFTREAS_PARTFX_SPAWN(obj, state->effectId, NULL, spawnFlags, -1, 0);
                }
            }
            else
            {
                CFTREAS_PARTFX_SPAWN(obj, state->effectId, NULL, spawnFlags, -1, 0);
            }
        }
        else if (mode == 1)
        {
            resource = Resource_Acquire((u16)(state->effectId + 0x58), 1);
            if (state->emitCount > 0)
            {
                for (i = 0; i < state->emitCount; i++)
                {
                    ((void (*)(int, int, int, int, int, int))((void**)*(int*)resource)[1])((int)obj, 0, 0, spawnFlags,
                                                                                           -1, 0);
                }
            }
            else
            {
                ((void (*)(int, int, int, int, int, int))((void**)*(int*)resource)[1])((int)obj, 0, 0, spawnFlags, -1,
                                                                                       0);
            }
            Resource_Release(resource);
        }
        else if (mode == 2)
        {
            resource = Resource_Acquire((u16)(state->effectId + 0xab), 1);
            if (state->emitCount > 0)
            {
                for (i = 0; i < state->emitCount; i++)
                {
                    ((void (*)(int, int, int, int, int, int, int))((void**)*(int*)resource)[1])(
                        (int)obj, 0, 0, spawnFlags, -1, state->effectId & 0xff, 0);
                }
            }
            else
            {
                ((void (*)(int, int, int, int, int, int, int))((void**)*(int*)resource)[1])(
                    (int)obj, 0, 0, spawnFlags, -1, state->effectId & 0xff, 0);
            }
            Resource_Release(resource);
        }
    }
}

#undef CFTREAS_PARTFX_SPAWN

int FxEmit_SeqFn(FxEmitObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    FxEmitState* state;
    FxEmitPlacement* def;
    u8 event;
    int i;
    s8 rotStep;

    state = obj->state;
    def = (FxEmitPlacement*)obj->objAnim.placementData;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        event = animUpdate->eventIds[i];
        if (event == 1)
        {
            fxemit_emitEffect(obj);
        }
        if (animUpdate->eventIds[i] == 2)
        {
            state->seqToggle = (u8)(1 - state->seqToggle);
        }
        animUpdate->eventIds[i] = 0;
    }

    if (state->seqToggle != 0)
    {
        rotStep = def->yawStep;
        if (rotStep == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotX = obj->objAnim.rotX + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotX = obj->objAnim.rotX + rotStep * framesThisStep * 100;
        }

        rotStep = def->pitchStep;
        if (rotStep == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotY = obj->objAnim.rotY + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotY = obj->objAnim.rotY + rotStep * framesThisStep * 100;
        }

        rotStep = def->rollStep;
        if (rotStep == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotZ = obj->objAnim.rotZ + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotZ = obj->objAnim.rotZ + rotStep * framesThisStep * 100;
        }
        fxemit_emitEffect(obj);
    }

    return 0;
}

int FxEmit_getExtraSize(void)
{
    return sizeof(FxEmitState);
}

int FxEmit_getObjectTypeId(void)
{
    return 0;
}

void FxEmit_free(FxEmitObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects(obj);
}

void FxEmit_hitDetect(void)
{
}

void FxEmit_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
        return;
}

void FxEmit_update(FxEmitObject* obj)
{
    FxEmitState* state;
    FxEmitPlacement* def;
    GameObject* player;
    s16 emitCount;
    s8 rotStep;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;

    state = obj->state;
    def = (FxEmitPlacement*)obj->objAnim.placementData;
    if (state->startDelay != 0)
    {
        state->startDelay -= (s16)timeDelta;
        if (state->startDelay < 0)
        {
            state->startDelay = 0;
        }
    }
    else
    {
        obj->objAnim.localPosX = obj->objAnim.velocityX * timeDelta + obj->objAnim.localPosX;
        obj->objAnim.localPosY = obj->objAnim.velocityY * timeDelta + obj->objAnim.localPosY;
        obj->objAnim.localPosZ = obj->objAnim.velocityZ * timeDelta + obj->objAnim.localPosZ;
        obj->objAnim.worldPosX = obj->objAnim.localPosX;
        obj->objAnim.worldPosY = obj->objAnim.localPosY;
        obj->objAnim.worldPosZ = obj->objAnim.localPosZ;
        player = Obj_GetPlayerObject();
        if (player == NULL || def == NULL)
        {
            return;
        }
        if (def->sfxPeriod != 0 && def->sfxPeriod != FXEMIT_SFX_SUPPRESS)
        {
            if (state->sfxTimer <= 0)
            {
                int sfx;
                state->suppressed = 0;
                state->sfxTimer = def->sfxPeriod * 100;
                sfx = def->sfxId;
                if (sfx != 0)
                {
                    Sfx_PlayFromObject((int)obj, (u16)sfx);
                }
            }
            else
            {
                state->suppressed = 1;
            }
            state->sfxTimer -= framesThisStep;
        }

        rotStep = def->yawStep;
        if (rotStep == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotX = obj->objAnim.rotX + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotX = obj->objAnim.rotX + rotStep * framesThisStep * 100;
        }

        rotStep = def->pitchStep;
        if (rotStep == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotY = obj->objAnim.rotY + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotY = obj->objAnim.rotY + rotStep * framesThisStep * 100;
        }

        rotStep = def->rollStep;
        if (rotStep == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotZ = obj->objAnim.rotZ + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotZ = obj->objAnim.rotZ + rotStep * framesThisStep * 100;
        }

        if (state->enableBit == -1 || mainGetBit(state->enableBit) != 0)
        {
            switch (state->suppressed)
            {
            case 0:
            {
                if (state->stopBit != -1 && mainGetBit(state->stopBit) != 0)
                {
                    state->suppressed = 1;
                }
                if (def->sfxPeriod == FXEMIT_SFX_SUPPRESS)
                {
                    state->suppressed = 1;
                }
                emitCount = state->emitCount;
                if (emitCount >= 0 || (emitCount < 0 && obj->emitCooldown <= 0))
                {
                    dx = obj->objAnim.worldPosX - player->anim.worldPosX;
                    dy = obj->objAnim.worldPosY - player->anim.worldPosY;
                    dz = obj->objAnim.worldPosZ - player->anim.worldPosZ;
                    if (emitCount == 0)
                    {
                        state->suppressed = 1;
                    }
                    dist = sqrtf(dx * dx + dy * dy + dz * dz);
                    if (dist <= state->triggerRadius || lbl_803E3E4C == state->triggerRadius)
                    {
                        fxemit_emitEffect(obj);
                    }
                    obj->emitCooldown = -state->emitCount;
                }
                else if (emitCount < 0 && obj->emitCooldown > 0)
                {
                    obj->emitCooldown -= framesThisStep;
                }
                break;
            }
            }
        }
    }
}

void FxEmit_init(FxEmitObject* obj, FxEmitPlacement* setup)
{
    FxEmitState* state;

    obj->objAnim.rotX = 0;
    obj->seqCallback = FxEmit_SeqFn;
    state = obj->state;

    state->triggerRadius = (f32)((s32)setup->triggerRadius << 2);
    state->effectMode = setup->effectMode;
    state->effectId = setup->effectId;
    state->emitCount = setup->emitCount;
    obj->objAnim.rootMotionScale = lbl_803E3E50;
    state->enableBit = setup->enableBit;
    state->stopBit = setup->stopBit;
    state->suppressed = 0;

    if (state->emitCount < 1)
    {
        obj->emitCooldown = state->emitCount;
    }
    else
    {
        obj->emitCooldown = 0;
    }

    if (state->stopBit != -1 && mainGetBit(state->stopBit) != 0)
    {
        state->suppressed = 1;
    }

    obj->objAnim.rotX = (s16)(setup->initialYaw << 8);
    obj->objAnim.rotY = (s16)(setup->initialPitch << 8);
    obj->objAnim.rotZ = (s16)(setup->initialRoll << 8);
    state->sfxTimer = (s16)(setup->sfxPeriod * 100);
    state->initialX = obj->objAnim.localPosX;
    state->startDelay = randomGetRange(0, 10);
    state->altEffectId = 0;
}

void FxEmit_release(void)
{
}

void FxEmit_initialise(void)
{
}

char sCFTreasSharpyDebugFormat[12] = "%x   %f %f\n\000";
