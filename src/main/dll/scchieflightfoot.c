/*
 * scchieflightfoot - Thorntail dust/sand effect spawner.
 *
 * Provides SHthorntail_updateDustEffects, called once per frame by the
 * Thorntail boss/creature update (dll_01B0_shswapston). While the runtime's
 * dust state is ACTIVE, a free-running timer (runtime->dustEffectTimer,
 * advanced by timeDelta each frame) sweeps through phases keyed off the
 * tuning thresholds in .sdata2 (0, 120, 360, 420, 480 frames):
 *   - rising:  randomly emit small dust puffs (effect 0x7ca)
 *   - 120..360: also emit a growing ground cloud (0x7d2) and arm the burst
 *   - 360..420: on the armed burst, emit 15 large cloud puffs
 *   - 420..480: hold
 *   - >=480:    reset the timer and clear the ACTIVE flag
 * Spawn probability is gated by randomGetRange against the timer scaled by
 * the tuning floats. All effects are parented to the player object.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/SC/SCchieflightfoot.h"
#include "main/object_api.h"
#include "main/frame_timing.h"

typedef struct SHthorntailDustEffectParams
{
    s16 flags;
    s16 count;
    s16 effectType;
    s16 radius;
    f32 scale;
    Vec position;
} SHthorntailDustEffectParams;

#define DUST_PUFF_EFFECT_ID     0x7ca
#define DUST_CLOUD_EFFECT_ID    0x7d2
#define DUST_PUFF_PARAM_TYPE    0xc0e
#define DUST_SPAWN_CHANCE_RANGE 0x1e0
#define DUST_BURST_PUFF_COUNT   0xf

f32 gChiefLightfootDustCloudScale = 0.0009f;
f32 gChiefLightfootDustBurstScale = 0.00036f;

void SHthorntail_updateDustEffects(SHthorntailObject* obj)
{
    void* playerObj;
    SHthorntailRuntime* runtime;
    int burstCount;
    SHthorntailDustEffectParams effectParams;

    playerObj = Obj_GetPlayerObject();
    runtime = obj->runtime;
    effectParams.position.x = 0.0f;
    effectParams.position.y = 55.0f;
    effectParams.position.z = 0.0f;
    effectParams.effectType = DUST_PUFF_PARAM_TYPE;
    effectParams.count = 1;
    if ((runtime->dustEffectFlags & SHTHORNTAIL_DUST_FLAG_ACTIVE) != 0)
    {
        if (runtime->dustEffectTimer < 120.0f)
        {
            if ((f32)(s32)randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) < runtime->dustEffectTimer * 0.5f)
            {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
        }
        else if (runtime->dustEffectTimer < 360.0f)
        {
            if ((f32)(s32)randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) < runtime->dustEffectTimer / 3.0f)
            {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
            effectParams.radius = 0x28;
            effectParams.flags = 0;
            effectParams.scale =
                gChiefLightfootDustCloudScale * ((runtime->dustEffectTimer - 120.0f) / 240.0f);
            (*gPartfxInterface)->spawnObject(playerObj, DUST_CLOUD_EFFECT_ID, &effectParams, 2, -1, NULL);
            runtime->dustEffectFlags = runtime->dustEffectFlags | SHTHORNTAIL_DUST_FLAG_BURST_READY;
        }
        else if (runtime->dustEffectTimer < 420.0f)
        {
            if ((f32)(s32)randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) < runtime->dustEffectTimer * 0.5f)
            {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
            if ((runtime->dustEffectFlags & SHTHORNTAIL_DUST_FLAG_BURST_READY) != 0)
            {
                runtime->dustEffectFlags = runtime->dustEffectFlags & ~SHTHORNTAIL_DUST_FLAG_BURST_READY;
                effectParams.radius = 0x46;
                effectParams.scale = gChiefLightfootDustBurstScale;
                for (burstCount = DUST_BURST_PUFF_COUNT; (u8)burstCount != 0; burstCount--)
                {
                    (*gPartfxInterface)->spawnObject(playerObj, DUST_CLOUD_EFFECT_ID, &effectParams, 2, -1, NULL);
                }
            }
        }
        else
        {
            if (runtime->dustEffectTimer < 480.0f)
            {
            }
            else
            {
                runtime->dustEffectTimer = 0.0f;
                runtime->dustEffectFlags = runtime->dustEffectFlags & ~SHTHORNTAIL_DUST_FLAG_ACTIVE;
            }
        }
        runtime->dustEffectTimer = runtime->dustEffectTimer + timeDelta;
    }
}
