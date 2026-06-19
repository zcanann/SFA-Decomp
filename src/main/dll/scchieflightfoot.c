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
#include "main/dll/SC/SCchieflightfoot.h"
#include "main/effect_interfaces.h"

extern int randomGetRange(int min, int max);
extern void* Obj_GetPlayerObject(void);

extern f32 timeDelta;

extern f32 lbl_803E5460; /* 0.0   timer reset / origin base */
extern f32 lbl_803E5464; /* 55.0  emit position y */
extern f32 lbl_803E5468; /* 120.0 phase 1 threshold */
extern f32 lbl_803E546C; /* 0.5   puff spawn-chance scale */
extern f32 lbl_803E5470; /* 360.0 phase 2 threshold */
extern f32 lbl_803E5474; /* 3.0   puff spawn-chance divisor */
extern f32 lbl_803E5478; /* 0.0009 ground-cloud ramp scale */
extern f32 lbl_803E547C; /* 240.0  ground-cloud ramp duration */
extern f32 lbl_803E5480; /* 420.0 phase 3 threshold */
extern f32 lbl_803E5484; /* 0.00036 burst-cloud scale */
extern f32 lbl_803E5488; /* 480.0 end threshold */

typedef struct SHthorntailDustEffectParams
{
    s16 flags;
    s16 count;
    s16 effectType;
    s16 radius;
    f32 scale;
    Vec position;
} SHthorntailDustEffectParams;

#define DUST_PUFF_EFFECT_ID 0x7ca
#define DUST_CLOUD_EFFECT_ID 0x7d2
#define DUST_PUFF_PARAM_TYPE 0xc0e
#define DUST_SPAWN_CHANCE_RANGE 0x1e0
#define DUST_BURST_PUFF_COUNT 0xf

void SHthorntail_updateDustEffects(SHthorntailObject* obj)
{
    void *playerObj;
    SHthorntailRuntime* runtime;
    int burstCount;
    SHthorntailDustEffectParams effectParams;

    playerObj = Obj_GetPlayerObject();
    runtime = obj->runtime;
    effectParams.position.x = lbl_803E5460;
    effectParams.position.y = lbl_803E5464;
    effectParams.position.z = lbl_803E5460;
    effectParams.effectType = DUST_PUFF_PARAM_TYPE;
    effectParams.count = 1;
    if ((runtime->dustEffectFlags & SHTHORNTAIL_DUST_FLAG_ACTIVE) != 0)
    {
        if (runtime->dustEffectTimer < lbl_803E5468)
        {
            if ((f32)(s32)
                randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) <
                    runtime->dustEffectTimer * lbl_803E546C
            )
            {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
        }
        else if (runtime->dustEffectTimer < lbl_803E5470)
        {
            if ((f32)(s32)
                randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) <
                    runtime->dustEffectTimer / lbl_803E5474
            )
            {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
            effectParams.radius = 0x28;
            effectParams.flags = 0;
            effectParams.scale = lbl_803E5478 * ((runtime->dustEffectTimer - lbl_803E5468) / lbl_803E547C);
            (*gPartfxInterface)->spawnObject(playerObj, DUST_CLOUD_EFFECT_ID, &effectParams, 2, -1, NULL);
            runtime->dustEffectFlags = runtime->dustEffectFlags | SHTHORNTAIL_DUST_FLAG_BURST_READY;
        }
        else if (runtime->dustEffectTimer < lbl_803E5480)
        {
            if ((f32)(s32)
                randomGetRange(0, DUST_SPAWN_CHANCE_RANGE) <
                    runtime->dustEffectTimer * lbl_803E546C
            )
            {
                (*gPartfxInterface)->spawnObject(playerObj, DUST_PUFF_EFFECT_ID, &effectParams, 2, -1, NULL);
            }
            if ((runtime->dustEffectFlags & SHTHORNTAIL_DUST_FLAG_BURST_READY) != 0)
            {
                runtime->dustEffectFlags = runtime->dustEffectFlags & ~SHTHORNTAIL_DUST_FLAG_BURST_READY;
                effectParams.radius = 0x46;
                effectParams.scale = lbl_803E5484;
                for (burstCount = DUST_BURST_PUFF_COUNT; (u8)burstCount != 0; burstCount--)
                {
                    (*gPartfxInterface)->spawnObject(playerObj, DUST_CLOUD_EFFECT_ID, &effectParams, 2, -1, NULL);
                }
            }
        }
        else
        {
            if (runtime->dustEffectTimer < lbl_803E5488)
            {
            }
            else
            {
                runtime->dustEffectTimer = lbl_803E5460;
                runtime->dustEffectFlags = runtime->dustEffectFlags & ~SHTHORNTAIL_DUST_FLAG_ACTIVE;
            }
        }
        runtime->dustEffectTimer = runtime->dustEffectTimer + timeDelta;
    }
}
