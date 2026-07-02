/*
 * DragonRock Shrine laser beam (DLL 0x17B; "DFSH_LaserBeam") - the shrine's
 * sweeping/pulsing laser-beam hazard: it tracks the player, animates beam
 * geometry and texture, drives sfx channels and proximity damage.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/resource.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/texture.h"
#include "main/objlib.h"
extern int randomGetRange(int lo, int hi);
extern f32 timeDelta;
extern ModgfxInterface** gModgfxInterface;
extern void* gLaserBeamEffectResource;
extern void* Obj_GetPlayerObject(void);
extern void Sfx_StopObjectChannel(void* obj, int channel);
extern void Sfx_SetObjectChannelVolume(void* obj, int channel, int volume, f32 pitch);
extern int getAngle(float y, float x);
extern f32 Vec_xzDistance(f32* a, f32* b);
extern void fn_8011F6D4(u32 x);
extern void fearTestMeterSetRange(u8 channel, u8 param, s16 value);
extern u8 padGetStickX(int port);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern int objGetAnimState80A(void* obj);
extern u8 framesThisStep;
extern f32 lbl_803E4EC0;
extern f32 lbl_803E4EC4;
extern f32 lbl_803E4EC8;
extern f32 lbl_803E4ECC;
extern const f32 lbl_803E4ED0;
extern const f32 lbl_803E4ED4;
extern const f32 gLaserBeamAimPi;
extern const f32 gLaserBeamAimAngleScale;
extern const f32 lbl_803E4EE0;
extern const f32 lbl_803E4EE4;
extern const f32 lbl_803E4EE8;
extern const f32 lbl_803E4EEC;
extern const f32 lbl_803E4EF0;
extern const f32 lbl_803E4EF4;
extern const f32 lbl_803E4EF8;
extern const f32 lbl_803E4F08;
extern const f32 lbl_803E4F0C;
extern const f32 lbl_803E4F10;
extern const f32 lbl_803E4F14;
extern const f32 gLaserBeamOrbitPi;
extern const f32 gLaserBeamOrbitAngleScale;
extern const f32 lbl_803E4F20;
extern const f32 lbl_803E4F24;
extern const f32 lbl_803E4F28;
extern const f32 lbl_803E4F2C;
extern const f32 lbl_803E4F30;
extern f32 lbl_803E4F40;
extern const f32 lbl_803E4F44;
extern const f32 lbl_803E4F48;
extern const f32 lbl_803E4F4C;

void DFSH_LaserBeam_init(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(gLaserBeamEffectResource);
    gLaserBeamEffectResource = NULL;
    if (*(void**)state != NULL)
    {
        textureFree(*(void**)state);
    }
    *(void**)state = NULL;
}

void dfsh_objcreator_init(int obj, s8* def);

void DFSH_LaserBeam_render(void)
{
}

void DFSH_LaserBeam_hitDetect(void)
{
}

int DFSH_LaserBeam_getExtraSize(void) { return 0x4c; }
int DFSH_LaserBeam_getObjectTypeId(void) { return 0x0; }

typedef struct DFSHLaserBeamConfig
{
    u8 pad00[0x18];
    s8 yawByte;
    u8 proximityMode;
    s16 rangeAngle;
    u8 pad1C[0x1E - 0x1C];
    s16 disableGameBit;
} DFSHLaserBeamConfig;

typedef struct DFSHLaserBeamRuntime
{
    void* beamTexture;
    f32 swayPhase;
    f32 swayVelocity;
    f32 swayAccel;
    f32 swayTarget;
    u8 pad14[0x18 - 0x14];
    s32 flags;
    f32 beamVolumeScale;
    s16 orbitAngleA;
    s16 orbitAngleB;
    s16 orbitAngleC;
    u8 beamActive;
    u8 beamLocked;
    s8 proximityHalfWidth;
    s8 hitCooldown;
    s16 hitStrength;
    s16 lockTimer;
    s16 cycleTimer;
    s16 warmupThreshold;
    f32 hitPos[3];
    f32 hitX;
    u8 pad40[0x44 - 0x40];
    f32 hitZ;
    u8 modgfxAttached;
    u8 blastPhase;
    u8 proximityMode;
    u8 pad4B[0x4C - 0x4B];
} DFSHLaserBeamRuntime;

typedef struct DFSHLaserBeamObject
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    s16 flags06;
    u8 pad08[0x0C - 0x08];
    f32 localPosX;
    f32 localPosY;
    f32 localPosZ;
    f32 worldPosX;
    f32 worldPosY;
    f32 worldPosZ;
    u8 pad24[0x36 - 0x24];
    u8 alpha;
    u8 pad37[0x4C - 0x37];
    DFSHLaserBeamConfig* config;
    u8 pad50[0xB8 - 0x50];
    DFSHLaserBeamRuntime* runtime;
} DFSHLaserBeamObject;

#define DFSH_LASER_ORBIT_A(runtime) (*(s16 *)((u8 *)(runtime) + 0x1E))
#define DFSH_LASER_ORBIT_B(runtime) (*(s16 *)((u8 *)(runtime) + 0x20))
#define DFSH_LASER_ORBIT_C(runtime) (*(s16 *)((u8 *)(runtime) + 0x22))
#define DFSH_LASER_ACTIVE(runtime) (*(u8 *)((u8 *)(runtime) + 0x24))
#define DFSH_LASER_BLOCKED(runtime) (*(u8 *)((u8 *)(runtime) + 0x25))
#define DFSH_LASER_HEIGHT_WINDOW(runtime) (*(s8 *)((u8 *)(runtime) + 0x26))
#define DFSH_LASER_DAMAGE_COOLDOWN(runtime) (*(s8 *)((u8 *)(runtime) + 0x27))
#define DFSH_LASER_HIT_STRENGTH(runtime) (*(s16 *)((u8 *)(runtime) + 0x28))
#define DFSH_LASER_BLOCK_TIMER(runtime) (*(s16 *)((u8 *)(runtime) + 0x2A))
#define DFSH_LASER_CYCLE_TIMER(runtime) (*(s16 *)((u8 *)(runtime) + 0x2C))
#define DFSH_LASER_WARMUP_THRESHOLD(runtime) (*(s16 *)((u8 *)(runtime) + 0x2E))
#define DFSH_LASER_HIT_POS(runtime) ((f32 *)((u8 *)(runtime) + 0x30))
#define DFSH_LASER_HIT_X(runtime) (*(f32 *)((u8 *)(runtime) + 0x3C))
#define DFSH_LASER_HIT_Z(runtime) (*(f32 *)((u8 *)(runtime) + 0x44))
#define DFSH_LASER_MODGFX_ATTACHED(runtime) (*(u8 *)((u8 *)(runtime) + 0x48))
#define DFSH_LASER_BLAST_PHASE(runtime) (*(u8 *)((u8 *)(runtime) + 0x49))
#define DFSH_LASER_PROXIMITY_MODE(runtime) (*(u8 *)((u8 *)(runtime) + 0x4A))
#define DFSH_LASER_RANGE_VALUE(runtime) (*(f32 *)((u8 *)(runtime) + 0x18))
#define DFSH_LASER_FLAGS(runtime) (*(s32 *)((u8 *)(runtime) + 0x18))

#define MODGFX_DETACH(obj) (*gModgfxInterface)->detachSource(obj)
#define PARTFX_SPAWN(obj,id,a,b,c,d) \
  (*gPartfxInterface)->spawnObject((obj),(id),(void *)(a),(b),(c),(void *)(d))
#define RESOURCE_SPAWN(obj,id,a,flags,owner,unk) \
  ((void (*)(void *,int,int,int,int,int))(*(int *)((u8 *)*(int *)gLaserBeamEffectResource + 0x4)))(obj,id,a,flags,owner,unk)

void DFSH_LaserBeam_update(u32 objAddr)
{
    extern int Sfx_PlayFromObject(void* obj, int sfxId);
    DFSHLaserBeamConfig* config;
    DFSHLaserBeamRuntime* runtime;
    void* playerObj;
    DFSHLaserBeamObject* obj;
    f32 range;
    f32 rangeSq;
    f32 yawSin;
    f32 yawCos;
    f32 heightThreshold;
    f32 beamPlane;
    f32 heightDelta;
    f32 xDelta;
    f32 zDelta;
    f32 lateralAbs;
    f32 damageDistance;
    f32 pushDistance;

    obj = (DFSHLaserBeamObject*)objAddr;
    config = obj->config;
    runtime = obj->runtime;

    DFSH_LASER_CYCLE_TIMER(runtime) -= framesThisStep;
    if (GameBit_Get(config->disableGameBit) == 0)
    {
        if (DFSH_LASER_CYCLE_TIMER(runtime) < 0)
        {
            if (DFSH_LASER_BLOCKED(runtime) == 0)
            {
                DFSH_LASER_CYCLE_TIMER(runtime) = 0x190;
                Sfx_PlayFromObject(obj, SFXmn_spdrcollapse11);
                runtime->beamVolumeScale = lbl_803E4EC0;
            }
            else
            {
                DFSH_LASER_CYCLE_TIMER(runtime) = 0x113;
            }
            DFSH_LASER_BLAST_PHASE(runtime) = 0;
        }
        else if (DFSH_LASER_CYCLE_TIMER(runtime) < DFSH_LASER_WARMUP_THRESHOLD(runtime))
        {
            if (DFSH_LASER_BLAST_PHASE(runtime) == 0)
            {
                Sfx_PlayFromObject(obj, SFXmn_spdrmove11);
                if (DFSH_LASER_BLOCKED(runtime) == 0)
                {
                    Sfx_PlayFromObject(obj, SFXmn_lummy311);
                }
                DFSH_LASER_BLAST_PHASE(runtime) = 1;
                if (gLaserBeamEffectResource != NULL)
                {
                    RESOURCE_SPAWN(obj, 10, 0, 0x10004, -1, 0);
                }
            }
            if (DFSH_LASER_CYCLE_TIMER(runtime) < 0x28)
            {
                Sfx_StopObjectChannel(obj, 0x40);
                if ((runtime->beamVolumeScale >= lbl_803E4EC0) &&
                    (DFSH_LASER_BLOCKED(runtime) == 0))
                {
                    runtime->beamVolumeScale -= lbl_803E4EC4 * timeDelta;
                }
            }
            else if (DFSH_LASER_CYCLE_TIMER(runtime) < 0x8C)
            {
                if (DFSH_LASER_BLAST_PHASE(runtime) == 1)
                {
                    DFSH_LASER_BLAST_PHASE(runtime) = 2;
                    if (gLaserBeamEffectResource != NULL)
                    {
                        RESOURCE_SPAWN(obj, 0xB, 0, 0x10004, -1, 0);
                    }
                }
            }
            else if (runtime->beamVolumeScale <= lbl_803E4EC8)
            {
                runtime->beamVolumeScale += lbl_803E4ECC * timeDelta;
            }
        }
    }

    if (DFSH_LASER_ACTIVE(runtime) != 0)
    {
        Sfx_SetObjectChannelVolume(obj, 0x40, (int)(lbl_803E4ED0 * runtime->beamVolumeScale),
                                   lbl_803E4ED4);
    }

    range = (f32)(int)config->rangeAngle;
    rangeSq = range * range;
    yawSin = mathCosf((gLaserBeamAimPi * obj->yaw) / gLaserBeamAimAngleScale);
    yawCos = mathSinf((gLaserBeamAimPi * obj->yaw) / gLaserBeamAimAngleScale);
    beamPlane = -(obj->localPosX * yawSin + obj->localPosZ * yawCos);
    playerObj = Obj_GetPlayerObject();

    DFSH_LASER_DAMAGE_COOLDOWN(runtime) =
        (s8)(DFSH_LASER_DAMAGE_COOLDOWN(runtime) - framesThisStep);
    if (DFSH_LASER_DAMAGE_COOLDOWN(runtime) < 0)
    {
        DFSH_LASER_DAMAGE_COOLDOWN(runtime) = 0;
    }

    damageDistance = beamPlane + (yawSin * ((GameObject*)playerObj)->anim.localPosX +
            yawCos * ((GameObject*)playerObj)->anim.localPosZ);
    if ((DFSH_LASER_PROXIMITY_MODE(runtime) == 1) ||
        ((damageDistance > lbl_803E4EC0) &&
            (DFSH_LASER_PROXIMITY_MODE(runtime) != 0)))
    {
        DFSH_LASER_BLOCK_TIMER(runtime) -= framesThisStep;
        if (DFSH_LASER_BLOCK_TIMER(runtime) < 0)
        {
            DFSH_LASER_BLOCK_TIMER(runtime) = 0;
            DFSH_LASER_BLOCKED(runtime) = 0;
        }
    }
    else
    {
        DFSH_LASER_BLOCK_TIMER(runtime) += framesThisStep;
        if (DFSH_LASER_BLOCK_TIMER(runtime) > 0x3C)
        {
            DFSH_LASER_BLOCK_TIMER(runtime) = 0x3C;
            DFSH_LASER_BLOCKED(runtime) = 1;
        }
    }

    if (DFSH_LASER_BLOCKED(runtime) == 0)
    {
        DFSH_LASER_ACTIVE(runtime) = DFSH_LASER_BLAST_PHASE(runtime) & 3;
    }
    else
    {
        DFSH_LASER_ACTIVE(runtime) = 1;
    }
    if (GameBit_Get(config->disableGameBit) != 0)
    {
        DFSH_LASER_ACTIVE(runtime) = 0;
    }

    if (DFSH_LASER_DAMAGE_COOLDOWN(runtime) == 0)
    {
        DFSH_LASER_HIT_STRENGTH(runtime) = 0;
    }
    if (((playerObj != NULL) && (DFSH_LASER_DAMAGE_COOLDOWN(runtime) == 0)) &&
        (DFSH_LASER_ACTIVE(runtime) != 0))
    {
        heightThreshold = lbl_803E4EE0 + (f32)(int)DFSH_LASER_HEIGHT_WINDOW(runtime);
        heightDelta = ((GameObject*)playerObj)->anim.localPosY - obj->localPosY;
        if ((heightDelta < heightThreshold) &&
            (heightDelta > -(lbl_803E4EE4 + heightThreshold)))
        {
            xDelta = ((GameObject*)playerObj)->anim.localPosX - obj->localPosX;
            zDelta = ((GameObject*)playerObj)->anim.localPosZ - obj->localPosZ;
            if ((xDelta * xDelta + zDelta * zDelta) < rangeSq)
            {
                damageDistance = beamPlane + (yawSin * ((GameObject*)playerObj)->anim.localPosX +
                    yawCos * ((GameObject*)playerObj)->anim.localPosZ);
                lateralAbs = damageDistance;
                if (damageDistance < lbl_803E4EC0)
                {
                    lateralAbs = -damageDistance;
                }
                if (lateralAbs > lbl_803E4EE8)
                {
                    lateralAbs = lbl_803E4EE8;
                }
                lateralAbs = *(f32*)&lbl_803E4EE8 - lateralAbs;
                DFSH_LASER_HIT_STRENGTH(runtime) =
                    (s16)(int)(lbl_803E4EEC * lateralAbs);
                if (DFSH_LASER_MODGFX_ATTACHED(runtime) == 1)
                {
                    MODGFX_DETACH(obj);
                    DFSH_LASER_MODGFX_ATTACHED(runtime) = 0;
                }
                if ((damageDistance < heightThreshold) &&
                    (damageDistance > -heightThreshold))
                {
                    pushDistance =
                        ((beamPlane + (yawSin * ((GameObject*)playerObj)->anim.previousLocalPosX +
                            yawCos * ((GameObject*)playerObj)->anim.previousLocalPosZ)) <
                        lbl_803E4EC0)
                            ? lbl_803E4EF0
                            : lbl_803E4EF4;
                    if (objGetAnimState80A(playerObj) != 0x1D7)
                    {
                        int i;
                        Sfx_PlayFromObject(obj, SFXmn_spithit6);
                        for (i = 0; i < 4; i++)
                        {
                            PARTFX_SPAWN(Obj_GetPlayerObject(), 0x28B, 0, 4, -1, 0);
                        }
                        DFSH_LASER_HIT_X(runtime) = yawSin * pushDistance + ((GameObject*)playerObj)->anim.localPosX;
                        DFSH_LASER_HIT_Z(runtime) = yawCos * pushDistance + ((GameObject*)playerObj)->anim.localPosZ;
                        if ((DFSH_LASER_PROXIMITY_MODE(runtime) == 0) ||
                            (DFSH_LASER_PROXIMITY_MODE(runtime) == 1))
                        {
                            ObjMsg_SendToObject(playerObj, 0x60003,DFSH_LASER_HIT_POS(runtime), 0);
                        }
                        DFSH_LASER_DAMAGE_COOLDOWN(runtime) = 0x14;
                    }
                    else
                    {
                        GameBit_Set(0x468, 1);
                    }
                }
            }
        }
    }

    if ((DFSH_LASER_ACTIVE(runtime) == 0) && (DFSH_LASER_MODGFX_ATTACHED(runtime) == 1))
    {
        MODGFX_DETACH(obj);
        DFSH_LASER_MODGFX_ATTACHED(runtime) = 0;
    }

    *(f32*)((u8*)runtime + 0x14) = runtime->swayAccel = runtime->swayPhase = lbl_803E4EC0;
    runtime->swayVelocity = runtime->swayPhase;
    runtime->swayTarget = runtime->swayAccel;
    DFSH_LASER_RANGE_VALUE(runtime) =
        *(f32*)((u8*)runtime + 0x14) + range;
    DFSH_LASER_HEIGHT_WINDOW(runtime) = 8;
    ((GameObject*)obj)->anim.currentMoveProgress += lbl_803E4EF8 * timeDelta;
    if (((GameObject*)obj)->anim.currentMoveProgress > *(f32*)&lbl_803E4EC8)
    {
        ((GameObject*)obj)->anim.currentMoveProgress -= lbl_803E4EC8;
    }
}

/*
 * Object setup: initializes the rotating DragonRock Shrine laser beam state.
 */
void DFSH_LaserBeam_free(void* objArg, void* configArg)
{
    DFSHLaserBeamObject* obj;
    DFSHLaserBeamConfig* config;
    DFSHLaserBeamRuntime* runtime;
    int timer;

    obj = (DFSHLaserBeamObject*)objArg;
    config = (DFSHLaserBeamConfig*)configArg;
    runtime = obj->runtime;
    ObjMsg_AllocQueue(obj, 2);
    obj->yaw = (s16)((s32)config->yawByte << 8);
    timer = randomGetRange(-0x50, 0x50);
    runtime->lockTimer = (s16)(timer + 0x190);
    *(u8*)((u8*)runtime + 0x49) = 0;
    gLaserBeamEffectResource = Resource_Acquire(0x81, 1);
    runtime->beamVolumeScale = lbl_803E4EC0;
    *(u8*)((u8*)runtime + 0x4A) = config->proximityMode;
    runtime->cycleTimer = 0x118;
    if (runtime->beamTexture == NULL)
    {
        runtime->beamTexture = textureLoadAsset(0x2E);
    }
}

void DFSH_LaserBeam_release(void)
{
}

void DFSH_LaserBeam_initialise(void)
{
}

/*
 * Advances the ambient laser-beam bob, aim, and player proximity alpha.
 */
#pragma opt_common_subs off
void fn_801C4664(void* objArg)
{
    DFSHLaserBeamConfig* config;
    DFSHLaserBeamRuntime* runtime;
    void* playerObj;
    DFSHLaserBeamObject* obj;
    f32 trigA;
    f32 trigB;
    s32 angleDelta;
    f32 distance;
    ObjAnimEventList animEvents;

    obj = (DFSHLaserBeamObject*)objArg;
    config = obj->config;
    runtime = obj->runtime;
    playerObj = Obj_GetPlayerObject();

    if ((obj->flags06 & 0x4000) != 0)
    {
        obj->yaw = 0;
        obj->localPosY = *(f32*)((u8*)config + 0xC);
        return;
    }

    DFSH_LASER_ORBIT_A(runtime) =
        (s16)(DFSH_LASER_ORBIT_A(runtime) + (int)(lbl_803E4F08 * timeDelta));
    DFSH_LASER_ORBIT_B(runtime) =
        (s16)(DFSH_LASER_ORBIT_B(runtime) + (int)(lbl_803E4F0C * timeDelta));
    DFSH_LASER_ORBIT_C(runtime) =
        (s16)(DFSH_LASER_ORBIT_C(runtime) + (int)(lbl_803E4F10 * timeDelta));

    obj->localPosY = lbl_803E4F14 +
    (*(f32*)((u8*)config + 0xC) +
        mathSinf((gLaserBeamOrbitPi * DFSH_LASER_ORBIT_A(runtime)) /
            gLaserBeamOrbitAngleScale));

    trigA = mathSinf((gLaserBeamOrbitPi * DFSH_LASER_ORBIT_B(runtime)) /
        gLaserBeamOrbitAngleScale);
    trigB = mathSinf((gLaserBeamOrbitPi * DFSH_LASER_ORBIT_A(runtime)) /
        gLaserBeamOrbitAngleScale);
    trigB = trigB + trigA;
    obj->roll = (s16)(lbl_803E4F20 * trigB);

    trigA = mathSinf((gLaserBeamOrbitPi * DFSH_LASER_ORBIT_C(runtime)) /
        gLaserBeamOrbitAngleScale);
    trigB = mathSinf((gLaserBeamOrbitPi * DFSH_LASER_ORBIT_A(runtime)) /
        gLaserBeamOrbitAngleScale);
    trigB = trigB + trigA;
    obj->pitch = (s16)(lbl_803E4F20 * trigB);

    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E4F24, timeDelta,
                                                                 &animEvents);
    if (playerObj == NULL)
    {
        return;
    }

    angleDelta = (u16)getAngle(obj->worldPosX - ((GameObject*)playerObj)->anim.worldPosX,
                               obj->worldPosZ - ((GameObject*)playerObj)->anim.worldPosZ) -
        (u16)obj->yaw;
    if (angleDelta > 0x8000)
    {
        angleDelta -= 0xFFFF;
    }
    if (angleDelta < -0x8000)
    {
        angleDelta += 0xFFFF;
    }

    obj->yaw = (s16)(obj->yaw + (s16)(((f32)angleDelta * timeDelta) / lbl_803E4F28));
    distance = Vec_xzDistance(&obj->worldPosX, &((GameObject*)playerObj)->anim.worldPosX);
    if (distance <= lbl_803E4F2C)
    {
        obj->alpha = (u8)(int)(lbl_803E4F30 * (distance / lbl_803E4F2C));
    }
    else
    {
        obj->alpha = 0xFF;
    }
}
#pragma opt_common_subs reset

/*
 * Drives the DragonRock Shrine laser-beam sway controller.
 */
int fn_801C49B8(void* objArg)
{
    DFSHLaserBeamObject* obj;
    DFSHLaserBeamRuntime* runtime;
    f32 stickAccel;
    f32 target;
    f32 zero;
    int swayValue;

    obj = (DFSHLaserBeamObject*)objArg;
    runtime = obj->runtime;
    if ((DFSH_LASER_FLAGS(runtime) & 0x20) == 0)
    {
        fn_8011F6D4(1);
        DFSH_LASER_FLAGS(runtime) |= 0x20;
        zero = lbl_803E4F40;
        runtime->swayPhase = zero;
        runtime->swayVelocity = zero;
        runtime->swayAccel = zero;
    }

    stickAccel = (f32)(s8)padGetStickX(0) / lbl_803E4F44;
    stickAccel = stickAccel * lbl_803E4F48;
    runtime->swayVelocity += stickAccel * timeDelta;

    target = runtime->swayTarget;
    if (target < lbl_803E4F40 && runtime->swayAccel > target)
    {
        runtime->swayAccel -= lbl_803E4F48 * timeDelta;
    }
    else if (target > *(f32*)&lbl_803E4F40)
    {
        if (runtime->swayAccel < target)
        {
            runtime->swayAccel += *(f32*)&lbl_803E4F48 * timeDelta;
        }
    }

    runtime->swayPhase += timeDelta * (runtime->swayVelocity + runtime->swayAccel);
    swayValue = (int)(lbl_803E4F4C * runtime->swayPhase);
    fearTestMeterSetRange(0x60, 0x39, swayValue);
    if ((swayValue > 0x39) || (swayValue < -0x39))
    {
        return 1;
    }
    return 0;
}
