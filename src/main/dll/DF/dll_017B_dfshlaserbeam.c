/*
 * DragonRock Shrine laser beam (DLL 0x17B; "DFSH_LaserBeam") - the shrine's
 * sweeping/pulsing laser-beam hazard: it tracks the player, animates beam
 * geometry and texture, drives sfx channels and proximity damage.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_play_pointer_legacy_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/vecmath_distance_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/dll/tricky_api.h"
#include "main/object_api.h"
#include "main/pad.h"
#include "main/resource.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/texture.h"
#include "main/obj_message.h"
#include "main/gamebit_ids.h"
#include "main/object_descriptor.h"

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

/* texture asset loaded into runtime->beamTexture */
#define DFSHLASERBEAM_TEXTURE_ID         0x2E
#define DFSHLASERBEAM_EFFECT_RESOURCE_ID 0x81

#define DFSH_LASER_ORBIT_A(runtime)          (*(s16*)((u8*)(runtime) + 0x1E))
#define DFSH_LASER_ORBIT_B(runtime)          (*(s16*)((u8*)(runtime) + 0x20))
#define DFSH_LASER_ORBIT_C(runtime)          (*(s16*)((u8*)(runtime) + 0x22))
#define DFSH_LASER_ACTIVE(runtime)           (*(u8*)((u8*)(runtime) + 0x24))
#define DFSH_LASER_BLOCKED(runtime)          (*(u8*)((u8*)(runtime) + 0x25))
#define DFSH_LASER_HEIGHT_WINDOW(runtime)    (*(s8*)((u8*)(runtime) + 0x26))
#define DFSH_LASER_DAMAGE_COOLDOWN(runtime)  (*(s8*)((u8*)(runtime) + 0x27))
#define DFSH_LASER_HIT_STRENGTH(runtime)     (*(s16*)((u8*)(runtime) + 0x28))
#define DFSH_LASER_BLOCK_TIMER(runtime)      (*(s16*)((u8*)(runtime) + 0x2A))
#define DFSH_LASER_CYCLE_TIMER(runtime)      (*(s16*)((u8*)(runtime) + 0x2C))
#define DFSH_LASER_WARMUP_THRESHOLD(runtime) (*(s16*)((u8*)(runtime) + 0x2E))
#define DFSH_LASER_HIT_POS(runtime)          ((f32*)((u8*)(runtime) + 0x30))
#define DFSH_LASER_HIT_X(runtime)            (*(f32*)((u8*)(runtime) + 0x3C))
#define DFSH_LASER_HIT_Z(runtime)            (*(f32*)((u8*)(runtime) + 0x44))
#define DFSH_LASER_MODGFX_ATTACHED(runtime)  (*(u8*)((u8*)(runtime) + 0x48))
#define DFSH_LASER_BLAST_PHASE(runtime)      (*(u8*)((u8*)(runtime) + 0x49))
#define DFSH_LASER_PROXIMITY_MODE(runtime)   (*(u8*)((u8*)(runtime) + 0x4A))
#define DFSH_LASER_RANGE_VALUE(runtime)      (*(f32*)((u8*)(runtime) + 0x18))
#define DFSH_LASER_FLAGS(runtime)            (*(s32*)((u8*)(runtime) + 0x18))
#define DFSH_MSG_PLAYER_HIT                  0x60003 /* message the player on a laser hit */

#define MODGFX_DETACH(obj) (*gModgfxInterface)->detachSource(obj)
#define PARTFX_SPAWN(obj, id, a, b, c, d)                                                                              \
    (*gPartfxInterface)->spawnObject((obj), (id), (void*)(a), (b), (c), (void*)(d))
#define RESOURCE_SPAWN(obj, id, a, flags, owner, unk)                                                                  \
    ((void (*)(void*, int, int, int, int, int))(*(int*)((u8*)*(int*)gLaserBeamEffectResource + 0x4)))(                 \
        obj, id, a, flags, owner, unk)

void* gLaserBeamEffectResource;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E4EC0 = 0.0f;
#pragma explicit_zero_data reset
__declspec(section ".sdata2") f32 lbl_803E4EC4 = 0.0026000000070780516f;
__declspec(section ".sdata2") f32 lbl_803E4EC8 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E4ECC = 0.052000001072883606f;
__declspec(section ".sdata2") const f32 lbl_803E4ED0 = 127.0f;
__declspec(section ".sdata2") const f32 lbl_803E4ED4 = 0.5f;
__declspec(section ".sdata2") const f32 gLaserBeamAimPi = 3.1415927f;
__declspec(section ".sdata2") const f32 gLaserBeamAimAngleScale = 32768.0f;
__declspec(section ".sdata2") const f32 lbl_803E4EE0 = 5.0f;
__declspec(section ".sdata2") const f32 lbl_803E4EE4 = 25.0f;
__declspec(section ".sdata2") f32 lbl_803E4EE8 = 63.0f;
__declspec(section ".sdata2") const f32 lbl_803E4EEC = 2.0f;
__declspec(section ".sdata2") const f32 lbl_803E4EF0 = -20.0f;
__declspec(section ".sdata2") const f32 lbl_803E4EF4 = 20.0f;
__declspec(section ".sdata2") const f32 lbl_803E4EF8 = 0.04f;

int DFSH_LaserBeam_getExtraSize(void)
{
    return 0x4c;
}

int DFSH_LaserBeam_getObjectTypeId(void)
{
    return 0x0;
}

void DFSH_LaserBeam_free(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(gLaserBeamEffectResource);
    gLaserBeamEffectResource = NULL;
    if (*(void**)state != NULL)
    {
        textureFree((Texture*)(*(void**)state));
    }
    *(void**)state = NULL;
}

void DFSH_LaserBeam_render(void)
{
}

void DFSH_LaserBeam_hitDetect(void)
{
}

void DFSH_LaserBeam_update(u32 objAddr)
{
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
    if (mainGetBit(config->disableGameBit) == 0)
    {
        if (DFSH_LASER_CYCLE_TIMER(runtime) < 0)
        {
            if (DFSH_LASER_BLOCKED(runtime) == 0)
            {
                DFSH_LASER_CYCLE_TIMER(runtime) = 0x190;
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_78);
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
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_79);
                if (DFSH_LASER_BLOCKED(runtime) == 0)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_77);
                }
                DFSH_LASER_BLAST_PHASE(runtime) = 1;
                if (gLaserBeamEffectResource != NULL)
                {
                    RESOURCE_SPAWN(obj, 10, 0, 0x10004, -1, 0);
                }
            }
            if (DFSH_LASER_CYCLE_TIMER(runtime) < 0x28)
            {
                Sfx_StopObjectChannelPtrLegacy(obj, 0x40);
                if ((runtime->beamVolumeScale >= lbl_803E4EC0) && (DFSH_LASER_BLOCKED(runtime) == 0))
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
        Sfx_SetObjectChannelVolumePtrIntLegacy(obj, 0x40, (int)(*(f32*)&lbl_803E4ED0 * runtime->beamVolumeScale),
                                               *(f32*)&lbl_803E4ED4);
    }

    range = (f32)(int)config->rangeAngle;
    rangeSq = range * range;
    yawSin = mathCosf((*(f32*)&gLaserBeamAimPi * obj->yaw) / *(f32*)&gLaserBeamAimAngleScale);
    yawCos = mathSinf((*(f32*)&gLaserBeamAimPi * obj->yaw) / *(f32*)&gLaserBeamAimAngleScale);
    beamPlane = -(obj->localPosX * yawSin + obj->localPosZ * yawCos);
    playerObj = Obj_GetPlayerObject();

    DFSH_LASER_DAMAGE_COOLDOWN(runtime) = (s8)(DFSH_LASER_DAMAGE_COOLDOWN(runtime) - framesThisStep);
    if (DFSH_LASER_DAMAGE_COOLDOWN(runtime) < 0)
    {
        DFSH_LASER_DAMAGE_COOLDOWN(runtime) = 0;
    }

    damageDistance = beamPlane + (yawSin * ((GameObject*)playerObj)->anim.localPosX +
                                  yawCos * ((GameObject*)playerObj)->anim.localPosZ);
    if ((DFSH_LASER_PROXIMITY_MODE(runtime) == 1) ||
        ((damageDistance > lbl_803E4EC0) && (DFSH_LASER_PROXIMITY_MODE(runtime) != 0)))
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
    if (mainGetBit(config->disableGameBit) != 0)
    {
        DFSH_LASER_ACTIVE(runtime) = 0;
    }

    if (DFSH_LASER_DAMAGE_COOLDOWN(runtime) == 0)
    {
        DFSH_LASER_HIT_STRENGTH(runtime) = 0;
    }
    if (((playerObj != NULL) && (DFSH_LASER_DAMAGE_COOLDOWN(runtime) == 0)) && (DFSH_LASER_ACTIVE(runtime) != 0))
    {
        heightThreshold = *(f32*)&lbl_803E4EE0 + (f32)(int)DFSH_LASER_HEIGHT_WINDOW(runtime);
        heightDelta = ((GameObject*)playerObj)->anim.localPosY - obj->localPosY;
        if ((heightDelta < heightThreshold) && (heightDelta > -(*(f32*)&lbl_803E4EE4 + heightThreshold)))
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
                DFSH_LASER_HIT_STRENGTH(runtime) = (s16)(int)(*(f32*)&lbl_803E4EEC * lateralAbs);
                if (DFSH_LASER_MODGFX_ATTACHED(runtime) == 1)
                {
                    MODGFX_DETACH(obj);
                    DFSH_LASER_MODGFX_ATTACHED(runtime) = 0;
                }
                if ((damageDistance < heightThreshold) && (damageDistance > -heightThreshold))
                {
                    pushDistance =
                        ((beamPlane + (yawSin * ((GameObject*)playerObj)->anim.previousLocalPosX +
                                       yawCos * ((GameObject*)playerObj)->anim.previousLocalPosZ)) < lbl_803E4EC0)
                            ? *(f32*)&lbl_803E4EF0
                            : *(f32*)&lbl_803E4EF4;
                    if (objGetAnimState80A((GameObject*)(playerObj)) != 0x1D7)
                    {
                        int i;
                        Sfx_PlayFromObject(obj, SFXTRIG_wp_espk2_c);
                        for (i = 0; i < 4; i++)
                        {
                            PARTFX_SPAWN(Obj_GetPlayerObject(), 0x28B, 0, 4, -1, 0);
                        }
                        DFSH_LASER_HIT_X(runtime) = yawSin * pushDistance + ((GameObject*)playerObj)->anim.localPosX;
                        DFSH_LASER_HIT_Z(runtime) = yawCos * pushDistance + ((GameObject*)playerObj)->anim.localPosZ;
                        if ((DFSH_LASER_PROXIMITY_MODE(runtime) == 0) || (DFSH_LASER_PROXIMITY_MODE(runtime) == 1))
                        {
                            ObjMsg_SendToObject(playerObj, DFSH_MSG_PLAYER_HIT, DFSH_LASER_HIT_POS(runtime), 0);
                        }
                        DFSH_LASER_DAMAGE_COOLDOWN(runtime) = 0x14;
                    }
                    else
                    {
                        mainSetBits(GAMEBIT_TRICKYCURVE_PLAYER_HIT, 1);
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
    DFSH_LASER_RANGE_VALUE(runtime) = *(f32*)((u8*)runtime + 0x14) + range;
    DFSH_LASER_HEIGHT_WINDOW(runtime) = 8;
    ((GameObject*)obj)->anim.currentMoveProgress += *(f32*)&lbl_803E4EF8 * timeDelta;
    if (((GameObject*)obj)->anim.currentMoveProgress > *(f32*)&lbl_803E4EC8)
    {
        ((GameObject*)obj)->anim.currentMoveProgress -= lbl_803E4EC8;
    }
}

/*
 * Object setup: initializes the rotating DragonRock Shrine laser beam state.
 */
void DFSH_LaserBeam_init(void* objArg, void* configArg)
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
    gLaserBeamEffectResource = Resource_Acquire(DFSHLASERBEAM_EFFECT_RESOURCE_ID, 1);
    runtime->beamVolumeScale = lbl_803E4EC0;
    *(u8*)((u8*)runtime + 0x4A) = config->proximityMode;
    runtime->cycleTimer = 0x118;
    if (runtime->beamTexture == NULL)
    {
        runtime->beamTexture = textureLoadAsset(DFSHLASERBEAM_TEXTURE_ID);
    }
}

void DFSH_LaserBeam_release(void)
{
}

void DFSH_LaserBeam_initialise(void)
{
}

ObjectDescriptor gDFSH_LaserBeamObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)DFSH_LaserBeam_initialise,
    (ObjectDescriptorCallback)DFSH_LaserBeam_release,
    0,
    (ObjectDescriptorCallback)DFSH_LaserBeam_init,
    (ObjectDescriptorCallback)DFSH_LaserBeam_update,
    (ObjectDescriptorCallback)DFSH_LaserBeam_hitDetect,
    (ObjectDescriptorCallback)DFSH_LaserBeam_render,
    (ObjectDescriptorCallback)DFSH_LaserBeam_free,
    (ObjectDescriptorCallback)DFSH_LaserBeam_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)DFSH_LaserBeam_getExtraSize,
};
