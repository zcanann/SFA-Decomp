/*
 * mmshshrine (DLL 0x18C) - the Krazoa shrine object in the MMSH map
 * (the shrine whose sway/test sequence rewards a Krazoa spirit).
 *
 * The shrine drives a small phase machine (runtime->phase 0..5): idle
 * SFX while waiting, then on activation runs object-trigger sequence 0,
 * lights the shrine model (flags06 & MMSH_SHRINE_FLAG_LIT), and on
 * completion runs the result sequences and grants the Krazoa game bit
 * (0x12a). A load-trigger countdown enables the sky and env fx once the
 * map has settled, and three SCGameBitLatch updates gate the open /
 * music-lock / completion ambient state from world game bits. The
 * sequence callback (MMSH_Shrine_SeqFn) interprets per-frame command
 * opcodes that toggle the light and drive the model sway parameters.
 */
#include "main/dll/dll_018C_mmshshrine.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/vecmath_distance_api.h"
#include "main/pad.h"
#include "main/dll/objfx_api.h"
#include "main/frame_timing.h"
#include "main/audio/music_api.h"
#include "main/vecmath.h"
#include "main/render_envfx_api.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object_render_legacy.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/audio_control_api.h"
#include "main/map_load.h"
#include "main/model_light.h"
#include "main/pi_dolphin_api.h"
#include "main/sky_api.h"
#include "main/dll/dll_018D_mmshscales.h"
#include "main/dll/dll_018E_mmshwaterspike.h"
#include "main/object_descriptor.h"
#include "main/dll/player_api.h"

/* env-effect ids fired when the shrine load-trigger timer expires (index-style; roles opaque) */
/* camera mode DLL 0x4c = dll_004C_camDebug */
#define MMSH_SHRINE_CAMMODE_CAMDEBUG 0x4c
#define MMSH_SHRINE_ENVFX_A          0x20d
#define MMSH_SHRINE_ENVFX_B          0x20e
#define MMSH_SHRINE_ENVFX_C          0x222

#define MMSH_SHRINE_FLAG_LIT                  0x4000
#define MMSH_SHRINE_LOAD_MAP_DIR              0x20
#define MMSH_SHRINE_LOAD_TRIGGER_TIMER        0xf4
#define MMSH_SHRINE_LATCH_FLAG_OPEN_READY     0x1
#define MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE    0x2
#define MMSH_SHRINE_LATCH_FLAG_CHECK_COMPLETE 0x4
#define MMSH_SHRINE_LATCH_FLAG_AMBIENT_LOCK   0x8
#define MMSH_SHRINE_LATCH_FLAG_MUSIC_LOCK     0x10
#define MMSH_SHRINE_LATCH_FLAG_SWAY_RESET     0x20
#define MMSH_SHRINE_SEQ_RESULT_COMPLETE       4
#define MMSH_SHRINE_SEQ_MAP_DIR               0xb
#define MMSH_SHRINE_SEQ_MAP_EVENT             3
#define MMSH_SHRINE_SEQ_GB_KRYSTAL            0x12a
#define MMSH_SHRINE_SEQ_GB_UNKNOWN_FF         0xff
#define MMSH_SHRINE_SEQ_GB_RESET0             0xe82
#define MMSH_SHRINE_SEQ_GB_RESET1             0xe83
#define MMSH_SHRINE_SEQ_GB_RESET2             0xe84
#define MMSH_SHRINE_SEQ_GB_RESET3             0xe85
#define MMSH_SHRINE_GB_OPEN                   0xae6
#define MMSH_SHRINE_GB_COMPLETE               0xae4
#define MMSH_SHRINE_GB_RESET_A                0x12b
#define MMSH_SHRINE_GB_RESET_B                0xae5
#define MMSH_SHRINE_GB_MUSIC_LOCK             0xcbb
#define MMSH_SHRINE_SFX_IDLE                  0x343
#define MMSH_SHRINE_MUSIC_RUMBLE              0xd8
#define MMSH_SHRINE_MUSIC_RUMBLE_STOP         0xd9
#define MMSH_SHRINE_MUSIC_STOP_8              0x8
#define MMSH_SHRINE_MUSIC_STOP_A              0xa
#define MMSH_SHRINE_GB_EFA                    0xefa
#define MMSH_SHRINE_GB_12D                    0x12d
#define MMSH_SHRINE_GB_F07                    0xf07

enum MMSHShrinePhase
{
    MMSH_SHRINE_PHASE_IDLE = 0,       /* idle SFX, wait for activation flag  */
    MMSH_SHRINE_PHASE_ACTIVATING = 1, /* wait for open-ready latch, then lit */
    MMSH_SHRINE_PHASE_LIT = 2,        /* shrine lit, await player test anim  */
    MMSH_SHRINE_PHASE_RESULT = 3,     /* end sway seq, run result sequence   */
    MMSH_SHRINE_PHASE_COMPLETE = 4,   /* grant completion game bit           */
    MMSH_SHRINE_PHASE_RESET = 5       /* clear flags, return to idle         */
};

extern void fn_8011F6D4(u32 x);
extern void fearTestMeterSetRange(u8 channel, u8 param, s16 value);

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

#define DFSH_LASER_ORBIT_A(runtime)          (*(s16*)((u8*)(runtime) + 0x1E))
#define DFSH_LASER_ORBIT_B(runtime)          (*(s16*)((u8*)(runtime) + 0x20))
#define DFSH_LASER_ORBIT_C(runtime)          (*(s16*)((u8*)(runtime) + 0x22))
#define DFSH_LASER_FLAGS(runtime)            (*(s32*)((u8*)(runtime) + 0x18))
typedef struct MMSHShrineRuntime
{
    ModelLightStruct* light;
    f32 swayBase;
    f32 swayAccel;
    f32 swayVelocity;
    f32 swayTarget;
    f32 idleSfxTimer;
    SCGameBitLatchState latch;
    s16 initCount;
    u8 pad1E[0x24 - 0x1E];
    u8 phase;
    u8 pad25[3];
} MMSHShrineRuntime;

typedef struct MMSHShrinePlacement
{
    u8 pad00[0x1a];
    s16 initCountParam; /* 0x1a: >>8 seeds runtime initCount */
} MMSHShrinePlacement;

typedef struct MMSHShrineObject
{
    s16 yaw;
    u8 pad02[0x06 - 0x02];
    s16 flags06;
    u8 pad08[0x0C - 0x08];
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 prevPosX;
    f32 prevPosY;
    f32 prevPosZ;
    u8 pad24[0xAF - 0x24];
    u8 objectFlags;
    u8 padB0[0xB4 - 0xB0];
    s16 triggerHandle;
    u8 padB6[0xB8 - 0xB6];
    MMSHShrineRuntime* runtime;
    u8 padBC[MMSH_SHRINE_LOAD_TRIGGER_TIMER - 0xBC];
    s32 loadTriggerTimer;
} MMSHShrineObject;

int MMSH_Shrine_getExtraSize(void);
int MMSH_Shrine_getObjectTypeId(void);
void MMSH_Shrine_free(GameObject* obj);
void MMSH_Shrine_render(GameObject* obj, u32 a2, u32 a3, u32 a4, u32 a5, char visible);
void MMSH_Shrine_hitDetect(void);
void MMSH_Shrine_update(int objArg);
void MMSH_Shrine_init(GameObject* obj, int def);
void MMSH_Shrine_release(void);
void MMSH_Shrine_initialise(void);

ObjectDescriptor gMMSH_ShrineObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)MMSH_Shrine_initialise,
    (ObjectDescriptorCallback)MMSH_Shrine_release,
    0,
    (ObjectDescriptorCallback)MMSH_Shrine_init,
    (ObjectDescriptorCallback)MMSH_Shrine_update,
    (ObjectDescriptorCallback)MMSH_Shrine_hitDetect,
    (ObjectDescriptorCallback)MMSH_Shrine_render,
    (ObjectDescriptorCallback)MMSH_Shrine_free,
    (ObjectDescriptorCallback)MMSH_Shrine_getObjectTypeId,
    MMSH_Shrine_getExtraSize,
};

const f32 lbl_803E4F08 = 512.0f;
const f32 lbl_803E4F0C = 128.0f;
const f32 lbl_803E4F10 = 192.0f;
const f32 lbl_803E4F14 = 20.0f;
const f32 gLaserBeamOrbitPi = 3.1415927f;
const f32 gLaserBeamOrbitAngleScale = 32768.0f;
const f32 lbl_803E4F20 = 600.0f;
const f32 lbl_803E4F24 = 0.005f;
const f32 lbl_803E4F28 = 12.0f;
const f32 lbl_803E4F2C = 30.0f;
const f32 lbl_803E4F30 = 255.0f;

#pragma dont_inline on
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

    if ((obj->flags06 & OBJANIM_FLAG_HIDDEN) != 0)
    {
        obj->yaw = 0;
        obj->localPosY = *(f32*)((u8*)config + 0xC);
        return;
    }

    DFSH_LASER_ORBIT_A(runtime) = (s16)(DFSH_LASER_ORBIT_A(runtime) + (int)(*(f32*)&lbl_803E4F08 * timeDelta));
    DFSH_LASER_ORBIT_B(runtime) = (s16)(DFSH_LASER_ORBIT_B(runtime) + (int)(*(f32*)&lbl_803E4F0C * timeDelta));
    DFSH_LASER_ORBIT_C(runtime) = (s16)(DFSH_LASER_ORBIT_C(runtime) + (int)(*(f32*)&lbl_803E4F10 * timeDelta));

    obj->localPosY =
        *(f32*)&lbl_803E4F14 + (*(f32*)((u8*)config + 0xC) +
                        mathSinf((*(f32*)&gLaserBeamOrbitPi * DFSH_LASER_ORBIT_A(runtime)) / *(f32*)&gLaserBeamOrbitAngleScale));

    trigA = mathSinf((*(f32*)&gLaserBeamOrbitPi * DFSH_LASER_ORBIT_B(runtime)) / *(f32*)&gLaserBeamOrbitAngleScale);
    trigB = mathSinf((*(f32*)&gLaserBeamOrbitPi * DFSH_LASER_ORBIT_A(runtime)) / *(f32*)&gLaserBeamOrbitAngleScale);
    trigB = trigB + trigA;
    obj->roll = (s16)(*(f32*)&lbl_803E4F20 * trigB);

    trigA = mathSinf((*(f32*)&gLaserBeamOrbitPi * DFSH_LASER_ORBIT_C(runtime)) / *(f32*)&gLaserBeamOrbitAngleScale);
    trigB = mathSinf((*(f32*)&gLaserBeamOrbitPi * DFSH_LASER_ORBIT_A(runtime)) / *(f32*)&gLaserBeamOrbitAngleScale);
    trigB = trigB + trigA;
    obj->pitch = (s16)(*(f32*)&lbl_803E4F20 * trigB);

    ObjAnim_AdvanceCurrentMove((int)obj, *(f32*)&lbl_803E4F24, timeDelta, &animEvents);
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

    obj->yaw = (s16)(obj->yaw + (s16)(((f32)angleDelta * timeDelta) / *(f32*)&lbl_803E4F28));
    distance = Vec_xzDistance(&obj->worldPosX, &((GameObject*)playerObj)->anim.worldPosX);
    if (distance <= *(f32*)&lbl_803E4F2C)
    {
        obj->alpha = (u8)(int)(*(f32*)&lbl_803E4F30 * (distance / *(f32*)&lbl_803E4F2C));
    }
    else
    {
        obj->alpha = 0xFF;
    }
}
#pragma opt_common_subs reset
#pragma dont_inline reset

#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E4F40 = 0.0f;
#pragma explicit_zero_data reset
const f32 lbl_803E4F44 = 72.0f;
const f32 lbl_803E4F48 = 0.0010416667209938169f;
const f32 lbl_803E4F4C = 96.0f;

#pragma dont_inline on
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

    stickAccel = (f32)(s8)padGetStickX(0) / *(f32*)&lbl_803E4F44;
    stickAccel = stickAccel * *(f32*)&lbl_803E4F48;
    runtime->swayVelocity += stickAccel * timeDelta;

    target = runtime->swayTarget;
    if (target < lbl_803E4F40 && runtime->swayAccel > target)
    {
        runtime->swayAccel -= *(f32*)&lbl_803E4F48 * timeDelta;
    }
    else if (target > *(f32*)&lbl_803E4F40)
    {
        if (runtime->swayAccel < target)
        {
            runtime->swayAccel += *(f32*)&lbl_803E4F48 * timeDelta;
        }
    }

    runtime->swayPhase += timeDelta * (runtime->swayVelocity + runtime->swayAccel);
    swayValue = (int)(*(f32*)&lbl_803E4F4C * runtime->swayPhase);
    fearTestMeterSetRange(0x60, 0x39, swayValue);
    if ((swayValue > 0x39) || (swayValue < -0x39))
    {
        return 1;
    }
    return 0;
}
#pragma dont_inline reset

__declspec(section ".sdata2") f32 lbl_803E4F50 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E4F54 = -0.0026041667442768812f;
__declspec(section ".sdata2") f32 lbl_803E4F58 = 0.0026041667442768812f;
__declspec(section ".sdata2") f32 lbl_803E4F5C = 2.0f;
__declspec(section ".sdata2") f32 lbl_803E4F60 = 0.5f;

int MMSH_Shrine_SeqFn(int objArg, u32 unused, MMSHShrineSequenceState* seq)
{
    MMSHShrineRuntime* runtime;
    u8 command;
    int playerObj;
    int i;

    runtime = ((MMSHShrineObject*)objArg)->runtime;
    playerObj = (int)Obj_GetPlayerObject();
    seq->targetObject = -1;
    seq->activeCommand = 0;

    for (i = 0; i < (int)(u32)seq->commandCount; i++)
    {
        command = seq->commands[i];
        if (command != 0)
        {
            switch (command)
            {
            case 7:
                objSetAnimStateFlags((GameObject*)playerObj, 4, 1);
                mainSetBits(MMSH_SHRINE_SEQ_GB_KRYSTAL, 1);
                mainSetBits(MMSH_SHRINE_SEQ_GB_UNKNOWN_FF, 1);
                (*gMapEventInterface)->setMapAct(MMSH_SHRINE_SEQ_MAP_DIR, MMSH_SHRINE_SEQ_MAP_EVENT);
                break;
            case 0xe:
                ((MMSHShrineObject*)objArg)->flags06 |= MMSH_SHRINE_FLAG_LIT;
                if (runtime->light != NULL)
                {
                    modelLightStruct_setEnabled(runtime->light, 0, lbl_803E4F50);
                }
                break;
            case 0xf:
                ((MMSHShrineObject*)objArg)->flags06 &= ~MMSH_SHRINE_FLAG_LIT;
                if (runtime->light != NULL)
                {
                    modelLightStruct_setEnabled(runtime->light, 0, lbl_803E4F50);
                }
                break;
            case 1:
                runtime->latch.activeMask |= MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE;
                break;
            case 2:
                runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE;
                if ((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_SWAY_RESET) != 0)
                {
                    fn_8011F6D4(0);
                    runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_SWAY_RESET;
                }
                break;
            case 3:
                runtime->swayTarget = lbl_803E4F54;
                break;
            case 4:
                runtime->swayTarget = lbl_803E4F58;
                break;
            case 5:
                runtime->swayTarget = -runtime->swayTarget;
                runtime->swayVelocity = -runtime->swayTarget;
                break;
            case 6:
                runtime->swayTarget *= lbl_803E4F5C;
                break;
            case 8:
                runtime->swayTarget *= lbl_803E4F60;
                break;
            }
        }
        seq->commands[i] = 0;
    }

    if (((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE) != 0) && ((u8)fn_801C49B8((void*)objArg) != 0))
    {
        fn_8011F6D4(0);
        runtime->latch.activeMask &= ~(MMSH_SHRINE_LATCH_FLAG_SWAY_ACTIVE | MMSH_SHRINE_LATCH_FLAG_SWAY_RESET);
        runtime->phase = MMSH_SHRINE_PHASE_RESULT;
        mainSetBits(MMSH_SHRINE_SEQ_GB_RESET0, 0);
        mainSetBits(MMSH_SHRINE_SEQ_GB_RESET1, 0);
        mainSetBits(MMSH_SHRINE_SEQ_GB_RESET2, 0);
        mainSetBits(MMSH_SHRINE_SEQ_GB_RESET3, 0);
        return MMSH_SHRINE_SEQ_RESULT_COMPLETE;
    }
    runtime->latch.activeMask |= MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
    return 0;
}

int MMSH_Shrine_getExtraSize(void)
{
    return 0x28;
}

int MMSH_Shrine_getObjectTypeId(void)
{
    return 0;
}

void MMSH_Shrine_free(GameObject* obj)
{
    int state = *(int*)&obj->extra;
    if ((((MMSHShrineRuntime*)state)->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_SWAY_RESET) != 0)
    {
        fn_8011F6D4(0);
        ((MMSHShrineRuntime*)state)->latch.activeMask =
            ((MMSHShrineRuntime*)state)->latch.activeMask & ~MMSH_SHRINE_LATCH_FLAG_SWAY_RESET;
    }
    if (*(void**)state != NULL)
    {
        ModelLightStruct_free(*(void**)state);
        *(int*)state = 0;
    }
    Music_Trigger(MMSH_SHRINE_MUSIC_RUMBLE, 0);
    Music_Trigger(MMSH_SHRINE_MUSIC_RUMBLE_STOP, 0);
    Music_Trigger(MMSH_SHRINE_MUSIC_STOP_8, 0);
    Music_Trigger(MMSH_SHRINE_MUSIC_STOP_A, 0);
    mainSetBits(MMSH_SHRINE_GB_EFA, 0);
    mainSetBits(MMSH_SHRINE_GB_MUSIC_LOCK, 1);
    mainSetBits(MMSH_SHRINE_SEQ_GB_RESET0, 0);
    mainSetBits(MMSH_SHRINE_SEQ_GB_RESET1, 0);
    mainSetBits(MMSH_SHRINE_SEQ_GB_RESET2, 0);
    mainSetBits(MMSH_SHRINE_SEQ_GB_RESET3, 0);
}

void MMSH_Shrine_render(GameObject* obj, u32 a2, u32 a3, u32 a4, u32 a5, char visible)
{
    MMSHShrineObject* shrine = (MMSHShrineObject*)obj;
    MMSHShrineRuntime* runtime = shrine->runtime;

    if (visible == 0)
    {
        if (runtime->light != NULL)
        {
            modelLightStruct_setEnabled(runtime->light, 0, lbl_803E4F50);
        }
    }
    else
    {
        if (runtime->light != NULL)
        {
            modelLightStruct_setEnabled(runtime->light, 1, lbl_803E4F50);
        }
        objRenderModelAndHitVolumes((int)obj, a2, a3, a4, a5, lbl_803E4F50);
        objParticleFn_80099d84((GameObject*)obj, lbl_803E4F50, 7, *(f32*)&lbl_803E4F50,
                               (ModelLightStruct*)runtime->light);
    }
}

void MMSH_Shrine_hitDetect(void)
{
}

void MMSH_Shrine_update(int objArg)
{
    MMSHShrineRuntime* runtime;
    MMSHShrineObject* obj;
    int playerObj;

    obj = (MMSHShrineObject*)objArg;
    runtime = obj->runtime;
    playerObj = (int)Obj_GetPlayerObject();

    if (obj->loadTriggerTimer != 0)
    {
        obj->loadTriggerTimer--;
        if (obj->loadTriggerTimer == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxActInt((int)obj, playerObj, MMSH_SHRINE_ENVFX_A, 0);
            getEnvfxActInt((int)obj, playerObj, MMSH_SHRINE_ENVFX_B, 0);
            getEnvfxActInt((int)obj, playerObj, MMSH_SHRINE_ENVFX_C, 0);
            obj->prevPosX = obj->posX;
            obj->prevPosY = obj->posY;
            obj->prevPosZ = obj->posZ;
        }
    }
    unlockLevel(mapGetDirIdx(MMSH_SHRINE_LOAD_MAP_DIR), 1, 0);
    fn_801C4664((void*)obj);
    SCGameBitLatch_Update(&runtime->latch, MMSH_SHRINE_LATCH_FLAG_AMBIENT_LOCK, -1, -1, MMSH_SHRINE_GB_OPEN, 0xa);
    SCGameBitLatch_UpdateInverted(&runtime->latch, MMSH_SHRINE_LATCH_FLAG_CHECK_COMPLETE, -1, -1,
                                  MMSH_SHRINE_GB_MUSIC_LOCK, 8);
    SCGameBitLatch_Update(&runtime->latch, MMSH_SHRINE_LATCH_FLAG_MUSIC_LOCK, -1, -1, MMSH_SHRINE_GB_MUSIC_LOCK, 0xc4);

    switch (runtime->phase)
    {
    case MMSH_SHRINE_PHASE_IDLE:
    {
        f32 idleSfxTimer = runtime->idleSfxTimer - timeDelta;
        runtime->idleSfxTimer = idleSfxTimer;
        if (idleSfxTimer <= lbl_803E4F40)
        {
            Sfx_PlayFromObject((int)obj, MMSH_SHRINE_SFX_IDLE);
            runtime->idleSfxTimer = (f32)(s32)randomGetRange(500, 1000);
        }
    }
        if ((obj->objectFlags & 1) == 0)
        {
            break;
        }
        runtime->phase = MMSH_SHRINE_PHASE_ACTIVATING;
        (*gObjectTriggerInterface)->setCamVars(MMSH_SHRINE_CAMMODE_CAMDEBUG, 0, 0, 0);
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        Music_Trigger(MMSH_SHRINE_MUSIC_RUMBLE, 1);
        break;
    case MMSH_SHRINE_PHASE_ACTIVATING:
        if ((runtime->latch.activeMask & MMSH_SHRINE_LATCH_FLAG_OPEN_READY) == 0)
        {
            break;
        }
        obj->flags06 |= MMSH_SHRINE_FLAG_LIT;
        obj->yaw = 0;
        runtime->phase = MMSH_SHRINE_PHASE_LIT;
        runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
        mainSetBits(MMSH_SHRINE_GB_OPEN, 1);
        (*gObjectTriggerInterface)->runSequence(2, obj, -1);
        break;
    case MMSH_SHRINE_PHASE_RESULT:
        (*gObjectTriggerInterface)->endSequence(obj->triggerHandle);
        (*gObjectTriggerInterface)->runSequence(3, obj, -1);
        runtime->phase = MMSH_SHRINE_PHASE_COMPLETE;
        mainSetBits(MMSH_SHRINE_GB_OPEN, 0);
        break;
    case MMSH_SHRINE_PHASE_COMPLETE:
        runtime->phase = MMSH_SHRINE_PHASE_RESET;
        mainSetBits(MMSH_SHRINE_GB_OPEN, 0);
        mainSetBits(MMSH_SHRINE_GB_COMPLETE, 1);
        break;
    case MMSH_SHRINE_PHASE_LIT:
        if (objGetAnimStateFlags((GameObject*)playerObj, 4) == 0)
        {
            audioStopByMask(3);
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
        }
        runtime->phase = MMSH_SHRINE_PHASE_RESET;
        mainSetBits(MMSH_SHRINE_GB_OPEN, 0);
        break;
    case MMSH_SHRINE_PHASE_RESET:
        runtime->phase = MMSH_SHRINE_PHASE_IDLE;
        runtime->latch.activeMask &= ~MMSH_SHRINE_LATCH_FLAG_OPEN_READY;
        obj->flags06 &= ~MMSH_SHRINE_FLAG_LIT;
        mainSetBits(MMSH_SHRINE_GB_RESET_A, 0);
        mainSetBits(MMSH_SHRINE_GB_COMPLETE, 0);
        mainSetBits(MMSH_SHRINE_GB_RESET_B, 0);
        mainSetBits(MMSH_SHRINE_GB_OPEN, 0);
        break;
    }
}

void MMSH_Shrine_init(GameObject* obj, int def)
{
    ModelLightStruct* light;
    MMSHShrineRuntime* state;
    MMSHShrinePlacement* p = (MMSHShrinePlacement*)def;

    state = obj->extra;
    ((MMSHShrineObject*)obj)->yaw = 0;
    obj->animEventCallback = MMSH_Shrine_SeqFn;
    state->initCount = 10;
    state->phase = MMSH_SHRINE_PHASE_IDLE;
    if (0 < p->initCountParam)
    {
        state->initCount = p->initCountParam >> 8;
    }
    mainSetBits(MMSH_SHRINE_GB_RESET_A, 0);
    mainSetBits(MMSH_SHRINE_GB_12D, 0);
    ((MMSHShrineObject*)obj)->loadTriggerTimer = 1;
    if (state->light == NULL)
    {
        light = objCreateLight(0, 1);
        state->light = light;
    }
    mainSetBits(MMSH_SHRINE_GB_F07, 1);
    mainSetBits(MMSH_SHRINE_GB_EFA, 1);
}

void MMSH_Shrine_release(void)
{
}

void MMSH_Shrine_initialise(void)
{
}

/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* gMMSH_ScalesObjDescriptor[14] = {(void*)0x00000000,           (void*)0x00000000,       (void*)0x00000000,
                                       (void*)0x00090000,           MMSH_Scales_initialise,  MMSH_Scales_release,
                                       (void*)0x00000000,           MMSH_Scales_init,        MMSH_Scales_update,
                                       MMSH_Scales_hitDetect,       MMSH_Scales_render,      MMSH_Scales_free,
                                       MMSH_Scales_getObjectTypeId, MMSH_Scales_getExtraSize};
void* gMMSH_WaterSpikeObjDescriptor[14] = {(void*)0x00000000,
                                           (void*)0x00000000,
                                           (void*)0x00000000,
                                           (void*)0x00090000,
                                           mmsh_waterspike_initialise,
                                           mmsh_waterspike_release,
                                           (void*)0x00000000,
                                           mmsh_waterspike_init,
                                           mmsh_waterspike_update,
                                           mmsh_waterspike_hitDetect,
                                           mmsh_waterspike_render,
                                           mmsh_waterspike_free,
                                           mmsh_waterspike_getObjectTypeId,
                                           mmsh_waterspike_getExtraSize};
