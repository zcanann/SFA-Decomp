#include "main/dll/SH/SHroot.h"
#include "main/dll/SC/SCchieflightfoot.h"
#include "main/effect_interfaces.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

extern void Sfx_PlayFromObject(SHthorntailObject* obj, u16 volumeId);
extern f32 getXZDistance(f32 * posA, f32 * posB);
extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern int randomGetRange(int min, int max);
extern undefined4 Obj_GetActiveModel();
extern undefined4 Obj_GetPlayerObject();
extern undefined4 modelInitBones();
extern undefined4 ObjGroup_AddObject();
extern int ObjTrigger_IsSet();
extern void ObjPath_GetPointWorldPosition(SHthorntailObject* obj, int pointIndex, f32* x, f32* y, f32* z, int param_6);
extern void characterDoEyeAnims(int obj, int collisionShapeState);
extern void fn_8003B228(int obj, int collisionShapeState);
extern int ViewFrustum_IsSphereVisible(f32* pos, f32 radius);
extern void objAudioFn_8006ef38(int obj, int joint, int pointCount, int pathPoints, int scratch, f32 scaleX,
                                f32 scaleY);
extern undefined4 dll_2E_func05();
extern undefined4 dll_2E_func08();
extern void dll_2E_func03(SHthorntailObject * obj, SHthorntailRuntime * runtime);
extern undefined4 FUN_80286888();
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

extern SHthorntailDataTables gSHthorntailDataTables;
extern u8 gSHthorntailPathHeaders[0x30];
extern u8 gSHthorntailPathData[0x4AC];
extern undefined4 lbl_803E5410;
extern EffectInterface** gPartfxInterface;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern SHthorntailPathControlInterface** gPathControlInterface;
extern f32 timeDelta;
extern f64 lbl_803E5428;
extern f64 lbl_803E5440;
extern f32 SHTHORNTAIL_TIMER_DONE_THRESHOLD;
extern f32 lbl_803E5448;
extern f32 lbl_803E544C;
extern f32 lbl_803E5450;
extern f32 lbl_803E5454;
extern f32 lbl_803E5458;
extern f32 lbl_803E545C;
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
extern f64 lbl_803E5490;

#define gSHthorntailPathControlInterface gPathControlInterface

#define SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES_OFFSET 0x0A0
#define SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES_OFFSET 0x294
#define SHTHORNTAIL_STATE_MOVE_IDS_OFFSET 0x488
#define SHTHORNTAIL_STATE_MOVE_STEP_SCALES_OFFSET 0x4AC
#define SHTHORNTAIL_STATE_FLAGS_OFFSET 0x4F0
#define SHTHORNTAIL_STATE_TRIGGER0_SFX_OFFSET 0x504
#define SHTHORNTAIL_STATE_TRIGGER7_SFX_OFFSET 0x528

#define SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES(tables) \
  ((ObjHitReactEntry *)((tables) + SHTHORNTAIL_NORMAL_HIT_REACT_ENTRIES_OFFSET))
#define SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES(tables) \
  ((ObjHitReactEntry *)((tables) + SHTHORNTAIL_HEAVY_HIT_REACT_ENTRIES_OFFSET))
#define SHTHORNTAIL_STATE_MOVE_IDS(tables) ((s16 *)((tables) + SHTHORNTAIL_STATE_MOVE_IDS_OFFSET))
#define SHTHORNTAIL_STATE_MOVE_STEP_SCALES(tables) \
  ((f32 *)((tables) + SHTHORNTAIL_STATE_MOVE_STEP_SCALES_OFFSET))
#define SHTHORNTAIL_STATE_FLAGS(tables) ((u8 *)((tables) + SHTHORNTAIL_STATE_FLAGS_OFFSET))
#define SHTHORNTAIL_STATE_TRIGGER0_SFX(tables) \
  ((u16 *)((tables) + SHTHORNTAIL_STATE_TRIGGER0_SFX_OFFSET))
#define SHTHORNTAIL_STATE_TRIGGER7_SFX(tables) \
  ((u8 *)((tables) + SHTHORNTAIL_STATE_TRIGGER7_SFX_OFFSET))

typedef struct SHthorntailDustEffectParams
{
    undefined2 flags;
    undefined2 count;
    undefined2 effectType;
    undefined2 radius;
    f32 scale;
    Vec position;
} SHthorntailDustEffectParams;

typedef struct SHthorntailTailSwingEffectScratch
{
    undefined particleParams[12];
    Vec position;
} SHthorntailTailSwingEffectScratch;

/*
 * --INFO--
 *
 * Function: SHthorntail_update
 * EN v1.0 Address: 0x801D5F58
 * EN v1.0 Size: 1928b
 * EN v1.1 Address: 0x801D6548
 * EN v1.1 Size: 1928b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: SHthorntail_init
 * EN v1.0 Address: 0x801D66E0
 * EN v1.0 Size: 564b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: SHthorntail_updateDustEffects
 * EN v1.0 Address: 0x801D6914
 * EN v1.0 Size: 752b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
