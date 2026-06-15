#include "main/dll/SC/SCchieflightfoot.h"
#include "main/effect_interfaces.h"

extern int randomGetRange(int min, int max);
extern undefined4 Obj_GetPlayerObject();

extern f32 timeDelta;
extern f32 lbl_803E5460;
extern f32 lbl_803E5464;
extern f32 lbl_803E5468;
extern f32 lbl_803E546C;
extern f32 lbl_803E5470;
extern f32 lbl_803E5474;
extern f32 lbl_803E5478;
extern f32 lbl_803E547C;
extern f32 lbl_803E5480;
extern f32 lbl_803E5484;
extern f32 lbl_803E5488;

typedef struct SHthorntailDustEffectParams
{
    undefined2 flags;
    undefined2 count;
    undefined2 effectType;
    undefined2 radius;
    f32 scale;
    Vec position;
} SHthorntailDustEffectParams;

void SHthorntail_updateDustEffects(SHthorntailObject* obj)
{
    undefined4 playerObj;
    SHthorntailRuntime* runtime;
    int burstCount;
    SHthorntailDustEffectParams effectParams;

    playerObj = Obj_GetPlayerObject();
    runtime = obj->runtime;
    effectParams.position.x = lbl_803E5460;
    effectParams.position.y = lbl_803E5464;
    effectParams.position.z = lbl_803E5460;
    effectParams.effectType = 0xc0e;
    effectParams.count = 1;
    if ((runtime->dustEffectFlags & SHTHORNTAIL_DUST_FLAG_ACTIVE) != 0)
    {
        if (runtime->dustEffectTimer < lbl_803E5468)
        {
            if ((f32)(s32)
                randomGetRange(0, 0x1e0) <
                    runtime->dustEffectTimer * lbl_803E546C
            )
            {
                (*gPartfxInterface)->spawnObject((void*)playerObj, 0x7ca, &effectParams, 2, -1, NULL);
            }
        }
        else if (runtime->dustEffectTimer < lbl_803E5470)
        {
            if ((f32)(s32)
                randomGetRange(0, 0x1e0) <
                    runtime->dustEffectTimer / lbl_803E5474
            )
            {
                (*gPartfxInterface)->spawnObject((void*)playerObj, 0x7ca, &effectParams, 2, -1, NULL);
            }
            effectParams.radius = 0x28;
            effectParams.flags = 0;
            effectParams.scale = lbl_803E5478 * ((runtime->dustEffectTimer - lbl_803E5468) / lbl_803E547C);
            (*gPartfxInterface)->spawnObject((void*)playerObj, 0x7d2, &effectParams, 2, -1, NULL);
            runtime->dustEffectFlags = runtime->dustEffectFlags | SHTHORNTAIL_DUST_FLAG_BURST_READY;
        }
        else if (runtime->dustEffectTimer < lbl_803E5480)
        {
            if ((f32)(s32)
                randomGetRange(0, 0x1e0) <
                    runtime->dustEffectTimer * lbl_803E546C
            )
            {
                (*gPartfxInterface)->spawnObject((void*)playerObj, 0x7ca, &effectParams, 2, -1, NULL);
            }
            if ((runtime->dustEffectFlags & SHTHORNTAIL_DUST_FLAG_BURST_READY) != 0)
            {
                runtime->dustEffectFlags = runtime->dustEffectFlags & ~SHTHORNTAIL_DUST_FLAG_BURST_READY;
                effectParams.radius = 0x46;
                effectParams.scale = lbl_803E5484;
                for (burstCount = 0xf; (u8)burstCount != 0; burstCount = burstCount + -1)
                {
                    (*gPartfxInterface)->spawnObject((void*)playerObj, 0x7d2, &effectParams, 2, -1, NULL);
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
