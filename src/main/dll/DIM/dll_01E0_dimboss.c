/*
 * dimboss (DLL 0x1E0) - the DIM world boss object.
 * Manages the boss's lifecycle: initialise/update/render/free, anim-event dispatch,
 * hit-detection, asset loading for the DIM→DIMTOP transition, and the game-bit-
 * driven sequence-flag word (gDIMbossSequenceFlags).
 */
#include "main/dll/DIM/dll_01E0_dimboss.h"
#include "main/dll/DIM/DIM2icicle.h"
#include "main/dll/DIM/DIM2lift.h"
#include "main/effect_interfaces.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/pi_dolphin.h"
#include "main/sfa_shared_decls.h"

#define DIMBOSS_OBJGROUP 3

u32 gDIMbossAnimController[0x189];
extern void Music_Trigger(int id, int arg);






extern u32 ObjModel_ClearRenderAttachment();
extern void ObjModel_EnableDefaultRenderCallback(DIMbossObject* obj, u32 model, void* mtx,
                                                 int enabled, double scale);
extern int Obj_GetActiveModel();
extern u32 Obj_BuildWorldTransformMatrix();
extern u32 getTrickyObject();
extern u64 ObjGroup_RemoveObject();
extern u64 clearLoadedFileFlags_blocks1();

extern u32 getLoadedFileFlags();





extern void loadDataFiles(void);




extern void skyFn_800895e0(int flags, u8 red, u8 green, u8 blue, u8 m1, u8 m2);

extern u64 dll_2E_func07();
extern u32 dll_2E_func09();
extern u32 dll_2E_func05();
extern void fn_801B9ECC(void);
extern u32 dll_2E_func04();


extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern u32 ModelLightStruct_free();
extern void Obj_FreeObject(u8* obj);
extern u32 Obj_GetPlayerObject();
extern u32 ObjHits_RegisterActiveHitVolumeObject();
extern void objRenderModelAndHitVolumes(DIMbossObject* obj, u32 p2, u32 p3,
                                 u32 p4, u32 p5, f32 scale);

extern void queueGlowRender(void* effect);
extern void dll_2E_func06(DIMbossObject* obj, void* animController, int p3);
extern u32 dll_2E_func03();
extern f32 timeDelta;
extern u8 gDvdErrorPauseActive;
extern u32 gDIMbossSequenceFlags;
extern f32 lbl_803E4C70;
extern u32 gDIMbossRenderMtx[];
extern DIMbossAnimScratch gDIMbossAnimScratchBase;
extern u32 gDIMbossAnimController[];
extern u32 lbl_802C2338[];
extern void (*gDIMbossAnimTable[])(void);
extern void (*gDIMbossHitDetectAnimTable[])(void);
extern int gPlayerInterface;
extern u32* gBaddieControlInterface;
extern void* gDIMbossHitEffectResource;
extern u8 lbl_803DDB84;
extern f32 lbl_803E4BD8;
extern f32 lbl_803E4C28;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C4C;
extern f32 lbl_803E4C50;
extern f32 lbl_803E4C54;
extern f32 lbl_803E4C78;
char sDIMBossFreeingAssetsForDIMBoss[] = "<DIMBoss.c> freeing assets for DIMBoss\n";
char sDIMBossLoadingAssetsForDIMTop[] = "<DIMBoss.c> loading assets for DIMTop\n";

#define DIMBOSS_BONE_PARTICLE_EFFECT_800 0x800
#define DIMBOSS_BONE_PARTICLE_EFFECT_7FF 0x7FF
#define DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES 100
#define DIMBOSS_SPAWN_OBJECT_TIMER 0x3C

typedef void (*DIMbossAnimSetupFn)(DIMbossObject* obj, u32 p2, DIMbossRuntime* runtime,
                                   int p4, int p5, int p6, u8 p7, float scale);
typedef void (*DIMbossPlayerHitReactFn)(DIMbossObject* obj, DIMbossRuntime* runtime, f32 x, f32 y,
                                        void* hitDetectAnimTable, void* animTable);

typedef struct DIMbossInitVec
{
    u32 a;
    u32 b;
    u32 c;
} DIMbossInitVec;

typedef struct DIMbossBaddieControlInterface
{
    u8 pad00[0x28];
    void (*startMove)(DIMbossObject* obj, DIMbossRuntime* runtime, void* moveScratch, int moveId,
                      u8* hitReactMode, int p6, int p7, int p8, int p9);
    void (*applyHitReact)(DIMbossObject* obj, DIMbossRuntime* runtime, f32 amount, int flag);
    int (*updateState)(DIMbossObject* obj, DIMbossRuntime* runtime, int flags);
    int (*updateHitDetect)(DIMbossObject* obj, ObjAnimUpdateState* animUpdate,
                           DIMbossRuntime* runtime, void* hitDetectAnimTable, void* animTable,
                           int flags);
    u8 pad38[0x40 - 0x38];
    void (*releaseState)(DIMbossObject* obj, DIMbossRuntime* runtime, int flags);
    u8 pad44[0x58 - 0x44];
    DIMbossAnimSetupFn setupAnim;
} DIMbossBaddieControlInterface;

typedef struct DIMbossPlayerInterface
{
    u8 pad00[0x08];
    DIMbossPlayerHitReactFn applyHitReact;
    void (*updateHitDetect)(DIMbossObject* obj, DIMbossRuntime* runtime, void* hitDetectAnimTable);
    u8 pad10[0x14 - 0x10];
    void (*init)(DIMbossObject* obj, DIMbossRuntime* runtime, int mode);
} DIMbossPlayerInterface;

typedef struct DIMbossMapEventInterface
{
    u8 pad00[0x40];
    u8 (*getAreaState)(int areaId);
    void (*setAreaState)(int areaId, int state);
    u8 pad48[0x4C - 0x48];
    int (*getAnimEvent)(int mapDir, int areaId);
    void (*triggerArea)(int mapDir, int areaId, int enabled);
} DIMbossMapEventInterface;

typedef struct DIMbossObjectTriggerInterface
{
    u8 pad00[0x48];
    void (*spawnAnimObject)(int objectType, DIMbossObject* parent, int timer);
    u8 pad4C[0x50 - 0x4C];
    void (*spawnObject)(int objectType, int spawnMode, DIMbossObject* parent, int timer);
    u8 pad54[0x58 - 0x54];
    void (*triggerEvent)(ObjAnimUpdateState* animUpdate, int eventId);
} DIMbossObjectTriggerInterface;

extern DIMbossMapEventInterface** gMapEventInterface;

static inline DIMbossBaddieControlInterface* DIMboss_GetBaddieControlInterface(void)
{
    return (DIMbossBaddieControlInterface*)*gBaddieControlInterface;
}

static inline BoneParticleEffectInterface* DIMboss_GetBoneParticleEffectInterface(void)
{
    return *gBoneParticleEffectInterface;
}

static inline DIMbossPlayerInterface* DIMboss_GetPlayerInterface(void)
{
    return (DIMbossPlayerInterface*)*(int*)gPlayerInterface;
}

static inline DIMbossObjectTriggerInterface* DIMboss_GetObjectTriggerInterface(void)
{
    return (DIMbossObjectTriggerInterface*)*gObjectTriggerInterface;
}

int DIMboss_updateState(DIMbossObject* obj, u32 state, ObjAnimUpdateState* animUpdate)
{
    DIMbossRuntime* runtime;
    DIMbossConfig* config;
    DIMbossTopState* topState;
    DIMbossAnimScratch* animScratch;
    int hitReactMode;
    u8 loadWaitStarted;
    int updateResult;
    int model;
    int mapDirIndex;
    u32 statusFlags;
    int eventIndex;
    int baddieResult;

    animScratch = &gDIMbossAnimScratchBase;
    runtime = obj->runtime;
    config = obj->config;
    updateResult = 0;
    Obj_GetPlayerObject();
    topState = runtime->topState;
    runtime->phase = DIMBOSS_PHASE_START;
    (*gMapEventInterface)->triggerArea(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_INTRO_GATE, 0);
    if (obj->renderPause != 0)
    {
        return 0;
    }

    dll_2E_func07(obj, animUpdate, animScratch->animController, 1, 1);
    for (eventIndex = 0; eventIndex < (int)(u32)animUpdate->eventCount; eventIndex = eventIndex + 1)
    {
        switch (animUpdate->eventIds[eventIndex])
        {
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAG_80000:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | (u64)DIMBOSS_SEQUENCE_FLAG_80000;
            break;
        case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_80000:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_80000;
            break;
        case DIMBOSS_EVENT_CLEAR_RENDER_ATTACHMENT:
            DIMboss_GetBoneParticleEffectInterface()->spawnEffect(
                obj,DIMBOSS_BONE_PARTICLE_EFFECT_800, NULL,DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES, NULL);
            DIMboss_GetBoneParticleEffectInterface()->spawnEffect(
                obj,DIMBOSS_BONE_PARTICLE_EFFECT_800, NULL,DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES, NULL);
            DIMboss_GetBoneParticleEffectInterface()->spawnEffect(
                obj,DIMBOSS_BONE_PARTICLE_EFFECT_7FF, NULL,DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES, NULL);
            DIMboss_GetBoneParticleEffectInterface()->spawnEffect(
                obj,DIMBOSS_BONE_PARTICLE_EFFECT_7FF, NULL,DIMBOSS_CLEAR_RENDER_PARTICLE_FRAMES, NULL);
            model = Obj_GetActiveModel((int)obj);
            ObjModel_ClearRenderAttachment(model);
            Music_Trigger(DIMBOSS_MUSIC_LIFT_RUMBLE, 1);
            break;
        case DIMBOSS_EVENT_LAUNCH_LIFT:
            runtime->phase = DIMBOSS_PHASE_LAUNCH_LIFT;
            obj->objectFlags &= ~DIMBOSS_OBJECT_FLAG_HIDDEN;
            obj->objectFlags |= DIMBOSS_OBJECT_FLAG_ACTIVE;
            (*gMapEventInterface)->triggerArea(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_LIFT, 0);
            break;
        case DIMBOSS_EVENT_ENABLE_DIMBOSS_MAP_AREA:
            (*gMapEventInterface)->triggerArea(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_BOSS, 1);
            break;
        case DIMBOSS_EVENT_DISABLE_DIMBOSS_MAP_AREA:
            (*gMapEventInterface)->triggerArea(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_BOSS, 0);
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_40004:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | (u64)DIMBOSS_SEQUENCE_FLAGS_40004;
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0002:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | DIMBOSS_SEQUENCE_FLAG_0002;
            break;
        case DIMBOSS_EVENT_QUEUE_STEAM_SFX:
            topState = runtime->topState;
            topState->steamFlags.bits.sfxPending = 1;
            Music_Trigger(DIMBOSS_MUSIC_STEAM_LOOP, 0);
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0040:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | DIMBOSS_SEQUENCE_FLAG_0040;
            break;
        case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0040:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_0040;
            break;
        case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0080:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_0080;
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAG_0100:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | DIMBOSS_SEQUENCE_FLAG_0100;
            break;
        case DIMBOSS_EVENT_CLEAR_SEQUENCE_FLAG_0100:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags & ~(u64)DIMBOSS_SEQUENCE_FLAG_0100;
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_2001:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | DIMBOSS_SEQUENCE_FLAGS_2001;
            break;
        case DIMBOSS_EVENT_SET_SEQUENCE_FLAGS_8021:
            gDIMbossSequenceFlags = gDIMbossSequenceFlags | (u64)DIMBOSS_SEQUENCE_FLAGS_8021;
            break;
        case DIMBOSS_EVENT_TRIGGER_DEFEAT_FLAGS:
            topState->defeatTimer = DIMBOSS_DEFEAT_TIMER_START;
            GameBit_Set(DIMBOSS_GAMEBIT_DEFEAT_STATE_A, 1);
            GameBit_Set(DIMBOSS_GAMEBIT_DEFEAT_STATE_B, 1);
            Music_Trigger(DIMBOSS_MUSIC_LIFT_RUMBLE, 0);
            Music_Trigger(DIMBOSS_MUSIC_BOSS_THEME, 0);
            Music_Trigger(DIMBOSS_MUSIC_STEAM_LOOP, 0);
            break;
        case DIMBOSS_EVENT_SPAWN_DIMBOSS_OBJECT:
            DIMboss_GetObjectTriggerInterface()->spawnObject(DIMBOSS_OBJECT_TYPE_ID, 4, obj,
                                                             DIMBOSS_SPAWN_OBJECT_TIMER);
            break;
        case DIMBOSS_EVENT_FREE_DIMBOSS_ASSETS:
            OSReport(sDIMBossFreeingAssetsForDIMBoss);
            setLoadedFileFlags_blocks1();
            unlockLevel(0, 0, 1);
            mapDirIndex = mapGetDirIdx(DIMBOSS_MAP_DIR);
            mapUnload(mapDirIndex, DIMBOSS_MAP_UNLOAD_MASK);
            mapDirIndex = mapGetDirIdx(DIMBOSS_GUT_MAP_DIR);
            mapUnload(mapDirIndex, DIMBOSS_GUT_MAP_UNLOAD_MASK);
            defragMemory(0);
            break;
        case DIMBOSS_EVENT_LOAD_DIMTOP_ASSETS:
            OSReport(sDIMBossLoadingAssetsForDIMTop);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            lockLevel(mapDirIndex, 0);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_BOOT_DATA_FILE);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_INTRO_DATA_FILE);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_PLATFORM_DATA_FILE);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_LIFT_DATA_FILE);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_SCENE_DATA_FILE);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_STEAM_DATA_FILE);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_BOSS_DATA_FILE_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_BOSS_DATA_FILE_B);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_EFFECT_DATA_FILE_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_EFFECT_DATA_FILE_B);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_ROOM_DATA_FILE_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_ROOM_DATA_FILE_B);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_AUDIO_DATA_FILE_A);
            mapDirIndex = mapGetDirIdx(DIMTOP_MAP_DIR);
            mapLoadDataFile(mapDirIndex, DIMTOP_AUDIO_DATA_FILE_B);
            loadWaitStarted = false;
            while (statusFlags = getLoadedFileFlags(0), (int)(statusFlags & DIMTOP_LOAD_PENDING_FLAGS_MASK) != 0)
            {
                padUpdate();
                checkReset();
                if (loadWaitStarted)
                {
                    waitNextFrame();
                }
                loadDataFiles();
                dvdCheckError();
                if (loadWaitStarted)
                {
                    mmFreeTick(0);
                    gameTextRun();
                    GXFlush_(1, 0);
                }
                if (gDvdErrorPauseActive != '\0')
                {
                    loadWaitStarted = true;
                }
            }
            clearLoadedFileFlags_blocks1();
            break;
        }
    }
    if (obj->animStateId != -1)
    {
        baddieResult = DIMboss_GetBaddieControlInterface()->updateState(obj, runtime, 1);
        if (baddieResult == 0)
        {
            updateResult = 1;
            goto LAB_801bd7dc;
        }
        if (obj->childObject != NULL)
        {
            ((ObjAnimComponent*)obj->childObject)->parent = obj->anim.parent;
        }
        if ((runtime->eventGameBit != -1) &&
            (statusFlags = GameBit_Get((int)runtime->eventGameBit), statusFlags != 0))
        {
            DIMboss_GetObjectTriggerInterface()->triggerEvent(animUpdate, config->eventId);
            runtime->eventGameBit = -1;
        }
        hitReactMode = runtime->hitReactMode;
        switch (hitReactMode)
        {
        case 0:
            break;
        case 2:
            animUpdate->hitVolumePair = 0;
            DIM2icicle_updateCombatState(obj, animUpdate, runtime, runtime);
            if (runtime->hitReactMode == 1)
            {
                runtime->field270 = 0;
                DIMboss_GetPlayerInterface()->applyHitReact(
                    obj, runtime, lbl_803E4C44, *(f32*)&lbl_803E4C44,
                    animScratch->hitDetectAnimTable, animScratch->animTable);
                animUpdate->sequenceEventActive = 0;
            }
            break;
        case 1:
            baddieResult = DIMboss_GetBaddieControlInterface()->updateHitDetect(
                obj, animUpdate, runtime,
                animScratch->hitDetectAnimTable, animScratch->animTable, 0);
            if (baddieResult != 0)
            {
                DIMboss_GetBaddieControlInterface()->applyHitReact(obj, runtime, lbl_803E4C70, 1);
            }
            break;
        }
    }
    DIM2icicle_updateDarkIceMinesWarpAndEffects(obj, runtime);
    if (obj->animStateId == -1)
    {
        runtime->stateFlags |= DIMBOSS_STATE_FLAG_START_MOVE;
        updateResult = 0;
    }
    else
    {
        updateResult = runtime->hitReactMode != 0;
    }
LAB_801bd7dc:
    return updateResult;
}

void DIMboss_func0B(void)
{
}

int DIMboss_setScale(DIMbossObject* obj)
{
    return obj->runtime->scale;
}

int DIMboss_getExtraSize(void)
{
    return DIMBOSS_RUNTIME_SIZE;
}

int DIMboss_getObjectTypeId(void)
{
    return DIMBOSS_OBJECT_TYPE_ID;
}

void DIMboss_free(DIMbossObject* obj)
{
    DIMbossRuntime* runtime;
    void* childObject;
    void* effect;

    runtime = obj->runtime;
    GameBit_Set(DIMBOSS_GAMEBIT_BOSS_ACTIVE, 0);
    GameBit_Set(0xc1e, 1);
    GameBit_Set(0xc1f, 0);
    GameBit_Set(0xc20, 0);
    GameBit_Set(0xd8f, 0);
    GameBit_Set(0x3e2, 0);
    obj->objectFlags &= ~DIMBOSS_OBJECT_FLAG_ACTIVE;
    Camera_DisableViewYOffset();
    ObjGroup_RemoveObject(obj, DIMBOSS_OBJGROUP);
    childObject = obj->childObject;
    if (childObject != NULL)
    {
        Obj_FreeObject(childObject);
        obj->childObject = NULL;
    }
    DIMboss_GetBaddieControlInterface()->releaseState(obj, runtime, 0x20);
    if (gDIMbossHitEffectResource != 0)
    {
        Resource_Release(gDIMbossHitEffectResource);
    }
    gDIMbossHitEffectResource = 0;
    effect = runtime->topState->effect;
    if (effect != NULL)
    {
        ModelLightStruct_free(effect);
    }
    timeOfDayFn_80055000();
}

void DIMboss_render(DIMbossObject* obj, u32 p2, u32 p3, u32 p4,
                    u32 p5, char shouldRender)
{
    DIMbossRuntime* runtime;
    DIMbossEffect* effect;

    runtime = obj->runtime;
    if (shouldRender == 0 || obj->renderPause != 0 || runtime->phase == DIMBOSS_PHASE_NO_RENDER)
    {
        return;
    }

    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E4C44);
    DIM2icicle_updateBossSequenceEffects(obj, runtime);
    dll_2E_func06(obj, gDIMbossAnimController, 0);

    effect = runtime->topState->effect;
    if (effect != NULL && effect->glowType != 0 && effect->enabled != 0)
    {
        queueGlowRender(effect);
    }
}

void DIMboss_hitDetect(DIMbossObject* obj)
{
    DIMboss_GetPlayerInterface()->updateHitDetect(obj, obj->runtime, gDIMbossHitDetectAnimTable);
}

void DIMboss_update(DIMbossObject* obj)
{
    u32 gameBitCount;
    u32 targetModel;
    DIMbossTopState* topState;
    DIMbossRuntime* runtime;
    DIMbossConfig* config;
    void* childObject;

    runtime = obj->runtime;
    config = obj->config;
    Obj_GetPlayerObject();
    topState = runtime->topState;
    if (obj->renderPause == 0)
    {
        if (topState->introSinkHeight > lbl_803E4BD8)
        {
            gameTextShow(0x432);
            topState->introSinkHeight -= timeDelta;
            if (topState->introSinkHeight < *(f32*)&lbl_803E4BD8)
            {
                topState->introSinkHeight = lbl_803E4BD8;
            }
        }
        ObjHits_RegisterActiveHitVolumeObject(obj);
        if (obj->updateInitialized == 0)
        {
            obj->anim.localPosX = config->spawnX;
            obj->anim.localPosY = config->spawnY;
            obj->anim.localPosZ = config->spawnZ;
            DIMboss_GetObjectTriggerInterface()->spawnAnimObject((int)config->animObjId, obj, -1);
            obj->updateInitialized = 1;
        }
        else
        {
            if ((runtime->stateFlags & DIMBOSS_STATE_FLAG_START_MOVE) != 0)
            {
                DIMboss_GetBaddieControlInterface()->startMove(
                    obj, runtime, runtime->moveScratch, runtime->activeMoveId, &runtime->hitReactMode,
                    0, 0, 0, 1);
                runtime->stateFlags &= ~DIMBOSS_STATE_FLAG_START_MOVE;
                obj->objectFlags &= ~DIMBOSS_OBJECT_FLAG_HIDDEN;
                obj->objectFlags |= DIMBOSS_OBJECT_FLAG_ACTIVE;
                gameBitCount = GameBit_Get(DIMBOSS_GAMEBIT_TONSIL_HIT_COUNT);
                if (gameBitCount >= 3)
                {
                    runtime->phase = DIMBOSS_PHASE_GAMEBIT_COUNT_MET;
                    runtime->animMode = 3;
                    obj->objectFlags &= ~DIMBOSS_OBJECT_FLAG_HIDDEN;
                    GameBit_Set(DIMBOSS_GAMEBIT_LIGHTFOOT_SNOWBALL_GATE, 0);
                }
                else
                {
                    runtime->phase = DIMBOSS_PHASE_LAUNCH_LIFT;
                    runtime->animMode = 3;
                    obj->objectFlags &= ~DIMBOSS_OBJECT_FLAG_HIDDEN;
                    topState->launchLift = lbl_803E4C44;
                    GameBit_Set(DIMBOSS_GAMEBIT_LIGHTFOOT_SNOWBALL_GATE, 1);
                }
            }
            if ((runtime->phase == DIMBOSS_PHASE_START) || (runtime->phase == DIMBOSS_PHASE_NO_RENDER))
            {
                if (topState->stompDustDelay != 0)
                {
                    topState->stompDustDelay--;
                    if (topState->stompDustDelay == 0)
                    {
                        Obj_BuildWorldTransformMatrix(obj, gDIMbossRenderMtx, 0);
                        targetModel = Obj_GetActiveModel(obj);
                        ObjModel_EnableDefaultRenderCallback
                            (obj, targetModel, gDIMbossRenderMtx, 1,
                             (double)(obj->anim.hitboxScale * obj->anim.rootMotionScale));
                    }
                }
                if (topState->steamFlags.bits.sfxPending != 0)
                {
                    getEnvfxAct(0, 0, 0xdb, 0);
                    getEnvfxAct(0, 0, 0xdc, 0);
                    skyFn_80089710(7, 1, 0);
                    skyFn_800894a8(7, lbl_803E4C4C, lbl_803E4C50, lbl_803E4C54);
                    skyFn_800895e0(7, 0xa0, 0xa0, 0xff, 0x7f, 0x28);
                    topState->steamFlags.bits.sfxPending = 0;
                }
            }
            else
            {
                if ((runtime->stateFlags & DIMBOSS_STATE_FLAG_TARGET_TRICKY) != 0)
                {
                    targetModel = getTrickyObject();
                    runtime->targetModel = targetModel;
                }
                else
                {
                    targetModel = Obj_GetPlayerObject();
                    runtime->targetModel = targetModel;
                }
                childObject = obj->childObject;
                if (childObject != NULL)
                {
                    ((ObjAnimComponent*)childObject)->parent = obj->anim.parent;
                }
                DIM2icicle_updateCombatState(obj, NULL, runtime, runtime);
                dll_2E_func04(gDIMbossAnimController, runtime->targetModel);
                dll_2E_func03(obj, gDIMbossAnimController);
                DIM2icicle_updateDarkIceMinesWarpAndEffects(obj, runtime);
            }
        }
    }
}

void DIMboss_init(DIMbossObject* obj, u32 params, int isAltVariant)
{
    DIMbossRuntime* runtime;
    DIMbossTopState* topState;
    u32 localVec[4];
    u8* animFlagsByte;
    u32 mapDir;
    u8 animFlags;
    f32 liftHeight;

    runtime = obj->runtime;
    *(DIMbossInitVec*)localVec = *(DIMbossInitVec*)lbl_802C2338;
    *(u16*)(localVec + 3) = *(u16*)(lbl_802C2338 + 3);
    setDrawCloudsAndLights(0);
    obj->updateMode = 2;
    animFlags = 6;
    if (isAltVariant != 0)
    {
        animFlags |= 1;
    }
    DIMboss_GetBaddieControlInterface()->setupAnim(
        obj, params, runtime, 0xc, 6, 0x102, animFlags, lbl_803E4C28);
    obj->updateState = DIMboss_updateState;
    runtime->phase = DIMBOSS_PHASE_START;
    DIMboss_GetPlayerInterface()->init(obj, runtime, 0);
    runtime->field270 = 0;
    runtime->animMode = 3;
    obj->objectFlags = (u8)(obj->objectFlags |
        (DIMBOSS_OBJECT_FLAG_HIDDEN | DIMBOSS_OBJECT_FLAG_ACTIVE));
    if (GameBit_Get(DIMBOSS_GAMEBIT_RENDER_PAUSE) != 0)
    {
        runtime->phase = DIMBOSS_PHASE_RENDER_PAUSE;
        obj->renderPause = 1;
    }
    if (GameBit_Get(DIMBOSS_GAMEBIT_SPIT_ACTIVE) != 0)
    {
        runtime->phase = DIMBOSS_PHASE_NO_RENDER;
    }
    topState = runtime->topState;
    liftHeight = lbl_803E4BD8;
    topState->idleLift = liftHeight;
    topState->launchLift = liftHeight;
    obj->anim.activeMove = -1;
    topState->effect = NULL;
    lbl_803DDB84 = 0;
    gDIMbossSequenceFlags = 0;
    GameBit_Set(DIMBOSS_GAMEBIT_TRICKY_BOSS_MODE, 1);
    dll_2E_func05(obj, gDIMbossAnimController, 0xffffd8e4, 0x1c71, 6);
    dll_2E_func09(gDIMbossAnimController, &localVec, &localVec, 6);
    animFlagsByte = (u8*)((int)gDIMbossAnimController + DIMBOSS_ANIM_CONTROLLER_FLAGS_OFFSET);
    *animFlagsByte |= 8;
    *animFlagsByte &= ~1;
    topState->steamFlags.bits.sfxPending = 1;
    gDIMbossHitEffectResource =
        Resource_Acquire(DIMBOSS_HIT_EFFECT_ID, DIMBOSS_HIT_EFFECT_RESOURCE_COUNT);
    if (GameBit_Get(DIMBOSS_GAMEBIT_INTRO_SEEN) == 0)
    {
        topState->stompDustDelay = 2;
        topState->introSinkHeight = lbl_803E4C78;
        (*gMapEventInterface)->triggerArea(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_INTRO_GATE, 1);
    }
    else
    {
        (*gMapEventInterface)->triggerArea(DIMBOSS_MAP_DIR, DIMBOSS_MAP_AREA_INTRO_GATE, 0);
    }
    topState->defeatTimer = 0;
    if ((*gMapEventInterface)->getAreaState(7) == 2)
    {
        (*gMapEventInterface)->setAreaState(7, 3);
    }
    GameBit_Set(DIMBOSS_GAMEBIT_BOSS_ACTIVE, 1);
    unlockLevel(0, 0, 1);
    mapDir = mapGetDirIdx(DIMBOSS_MAP_DIR);
    lockLevel(mapDir, 1);
    mapDir = mapGetDirIdx(DIMBOSS_GUT_MAP_DIR);
    lockLevel(mapDir, 0);
    GameBit_Set(DIMBOSS_GAMEBIT_SHRINE_MUSIC_LOCK, 0);
    Music_Trigger(DIMBOSS_MUSIC_BOSS_THEME, 1);
    GameBit_Set(DIMBOSS_GAMEBIT_DIM2_PROJECTILE_DONE, 0);
    Music_Trigger(DIMBOSS_MUSIC_DIM2_PROJECTILE, 0);
    Music_Trigger(DIMBOSS_MUSIC_DIM2_PROJECTILE_ALT, 0);
}

void DIMboss_release(void)
{
}

void DIMboss_initialise(void)
{
    DIMboss_initialiseAnimTables();
}

ObjectDescriptor12 gDIM_BossObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)DIMboss_initialise,
    (ObjectDescriptorCallback)DIMboss_release,
    0,
    (ObjectDescriptorCallback)DIMboss_init,
    (ObjectDescriptorCallback)DIMboss_update,
    (ObjectDescriptorCallback)DIMboss_hitDetect,
    (ObjectDescriptorCallback)DIMboss_render,
    (ObjectDescriptorCallback)DIMboss_free,
    (ObjectDescriptorCallback)DIMboss_getObjectTypeId,
    DIMboss_getExtraSize,
    (ObjectDescriptorCallback)DIMboss_setScale,
    (ObjectDescriptorCallback)DIMboss_func0B,
};

void DIMboss_initialiseAnimTables(void)
{
    typedef void (*DIMbossRawAnimCallback)(void);
    DIMbossRawAnimCallback *table;

    table = gDIMbossHitDetectAnimTable;
    table[0] = (DIMbossRawAnimCallback)DIMbossHitDetect_resetIdleMove;
    table[1] = (DIMbossRawAnimCallback)DIMbossHitDetect_applyForwardMove;
    table[2] = (DIMbossRawAnimCallback)DIMbossHitDetect_trackTargetMove;
    table[3] = (DIMbossRawAnimCallback)DIMbossHitDetect_randomSwipe;
    table[4] = (DIMbossRawAnimCallback)DIMbossHitDetect_blueWhiteEventCapture;
    table[5] = (DIMbossRawAnimCallback)DIMbossHitDetect_blueWhiteCapture;
    table[6] = (DIMbossRawAnimCallback)DIMbossHitDetect_breathBurst;
    table[7] = (DIMbossRawAnimCallback)DIMbossHitDetect_lungeAttack;
    table[8] = (DIMbossRawAnimCallback)DIMbossHitDetect_chooseIdleTaunt;
    table[9] = (DIMbossRawAnimCallback)DIMbossHitDetect_liftImpact;
    table[10] = (DIMbossRawAnimCallback)DIMbossHitDetect_liftSlam;
    table[11] = (DIMbossRawAnimCallback)DIMbossHitDetect_tonsilSlam;

    table = gDIMbossAnimTable;
    table[0] = (DIMbossRawAnimCallback)DIMbossAnim_selectTargetControlMode;
    table[1] = (DIMbossRawAnimCallback)DIMbossAnim_returnToIdleWhenDone;
    table[2] = (DIMbossRawAnimCallback)DIMbossAnim_hasMoveDone;
    table[3] = (DIMbossRawAnimCallback)DIMbossAnim_finishDefeat;
    table[4] = (DIMbossRawAnimCallback)DIMbossAnim_updatePlayerHitReaction;
    table[5] = fn_801B9ECC;
}
