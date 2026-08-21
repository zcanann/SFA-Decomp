/*
 * FirePipe (DLL 627) - a cyclic flame/jet emitter placed in the world.
 *
 * Each tick the object emits a particle effect sub-object (a fresh
 * spawn-def is allocated, positioned at the emitter and handed to a
 * pooled effect slot) and drives an optional point-light glow that
 * follows the flame. Emission runs on a duty cycle (cycleTimer /
 * emitTimer, seeded from the placement's cycleTime/timer fields) and is
 * gated by a placement game bit: setting the bit toggles the jet on or
 * off, and player hits / freeze state can also start or stop it.
 *
 * The object-id variants select the effect flavour spawned by
 * firepipe_init / firepipe_updateState:
 *   0x6f9 -> effect type 10 (blue glow)   0x730 -> type 0xC
 *   0x731 -> type 0xD                     0x732 -> type 0xE
 *   0x4a4 / 0x70a / default -> type 9 (orange flame, clear-volume pair)
 *
 * Per-object boolean state lives in FirePipeExtra.flags, accessed as a
 * FirePipeBitFlags overlay (emitting, glowEnabled, renderEnabled, ...).
 *
 * Live-verified (Dolphin) against the nearest emitter in the loaded save:
 * the object spawns pooled `FlameThrowerspe` (DLL 0x0E4) flame-stream
 * effects (FirePipeExtra.effectObjs); clearing `emitting` stops the jet and
 * freezing `cycleTimer` keeps it off; FirePipeMapData.rotX/rotY aim the jet
 * (changing them swings the model and the flame); `glowLight` is the
 * point-light that tracks the emitter.
 */
#include "main/audio/sfx_limited_object_api.h"
#include "main/maketex_timer_api.h"
#include "main/vecmath.h"
#include "main/audio/sfx_trigger_ids.h"
#include "game/objects/object.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "main/object_update_list.h"
#include "main/objfx.h"
#include "string.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/object_render.h"
#include "main/dll/dll_0273_firepipe.h"
#include "game/objects/object_setup.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/model_light.h"

f32 gFirePipeEffectScale = -0.01f;
f32 gFirePipeEffectVelocityY = 0.3f;
s16 gFirePipeCycleTimerThreshold = 0x3C;
f32 gFirePipeGlowScale = 60.0f;
int gFirePipeEmitTimerReset = 0x0A;

#define FIREPIPE_OBJGROUP 0x4a

#define FIREPIPE_OBJFLAG_ACTIVE 0x200

/* objectId variants handled by this DLL (select the emitted effect); retail
 * OBJECTS.bin names: IceHole, SteamHoleNo/SteamHoleFi/SteamHoleDe (11-char
 * truncated), FirePipe, BossDrakorF. */
#define FIREPIPE_OBJ_ICE_HOLE        0x6f9
#define FIREPIPE_OBJ_STEAM_HOLE_NO   0x730
#define FIREPIPE_OBJ_STEAM_HOLE_FI   0x731
#define FIREPIPE_OBJ_STEAM_HOLE_DE   0x732
#define FIREPIPE_OBJ_FIRE_PIPE       0x4a4
#define FIREPIPE_OBJ_BOSSDRAKOR_FIRE 0x70a
/* FlameThrowerspe child (DLL 0xE4) spawned as the emitted effect. */
#define FIREPIPE_CHILD_OBJ_FLAMETHROWER 0x1b5

/* emitted effect-type (flavour) per objectId variant (docblock: "0x6f9 -> type
 * 10 (blue glow), 0x730 -> 0xC, 0x731 -> 0xD, 0x732 -> 0xE, flame/default ->
 * type 9 (orange flame)"). */
#define FIREPIPE_EFFECT_TYPE_ICE_HOLE      10
#define FIREPIPE_EFFECT_TYPE_STEAM_HOLE_NO 0xc
#define FIREPIPE_EFFECT_TYPE_STEAM_HOLE_FI 0xd
#define FIREPIPE_EFFECT_TYPE_STEAM_HOLE_DE 0xe
#define FIREPIPE_EFFECT_TYPE_FLAME         9

typedef void (*FirePipeEffectInitFn)(int obj, void* spawnDef, int p3);

/* Spawn-setup buffer seeded by firepipe_updateState for the emitted flame
 * effect (defNo 0x1b5). Reuses ObjPlacement's color/pos head and adds the
 * class-specific effectMode/scale fields; store widths per target asm. */
typedef struct FirePipeEffectSetup
{
    ObjPlacement head; /* 0x00: color at +4, pos at +8/+c/+10 */
    u8 pad18;          /* 0x18 */
    s8 effectMode;     /* 0x19 */
    s16 scale;         /* 0x1a */
} FirePipeEffectSetup;

int firepipe_spawnEffectObject(FirePipeExtra* extra, GameObject* obj, ObjPlacement* spawnDef)
{
    int i;
    GameObject* effectObj;
    int freeDelay;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0)
    {
        return 0;
    }
    for (i = 0; i < extra->effectCount; i++)
    {
        effectObj = extra->effectObjs[i];
        if ((effectObj->objectFlags & FIREPIPE_OBJFLAG_ACTIVE) == 0)
        {
            effectObj->objectFlags |= FIREPIPE_OBJFLAG_ACTIVE;
            memcpy(effectObj->anim.placement, spawnDef, spawnDef->size);
            effectObj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            effectObj->anim.localPosX = spawnDef->posX;
            effectObj->anim.localPosY = spawnDef->posY;
            effectObj->anim.localPosZ = spawnDef->posZ;
            (*(FirePipeEffectInitFn*)(*(int*)effectObj->anim.dll + 4))((int)effectObj, spawnDef, 0);
            freeDelay = mmSetFreeDelay(0);
            mm_free(spawnDef);
            mmSetFreeDelay(freeDelay);
            Obj_InsertIntoUpdateList(effectObj);
            effectObj->objectFlags &= ~OBJECT_OBJFLAG_UPDATE_DISABLED;
            return (int)effectObj;
        }
    }
    effectObj = loadObjectAtObject(obj, spawnDef);
    if (extra->effectCount != 8)
    {
        effectObj->objectFlags |= FIREPIPE_OBJFLAG_ACTIVE;
        i = extra->effectCount++;
        extra->effectObjs[i] = effectObj;
    }
    return (int)effectObj;
}

void firepipe_releaseEffectObject(GameObject* obj)
{
    if ((obj->objectFlags & FIREPIPE_OBJFLAG_ACTIVE) != 0)
    {
        ObjHits_DisableObject(obj);
        obj->objectFlags &= ~FIREPIPE_OBJFLAG_ACTIVE;
        Obj_RemoveFromUpdateList(obj);
        obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED;
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        Obj_FreeObject(obj);
    }
}

int firepipe_clearLinkedUpdateFlag(GameObject* obj)
{
    FirePipeExtra* extra = obj->extra;
    extra->flags.childEmitEnabled = 0;
    return 1;
}

int firepipe_setLinkedUpdateFlag(GameObject* obj)
{
    FirePipeExtra* extra = obj->extra;
    extra->flags.childEmitEnabled = 1;
    return 1;
}

void firepipe_updateState(GameObject* obj)
{
    FirePipeExtra* extra;
    FirePipeMapData* mapData;
    FirePipeBitFlags* flags;
    int priorityHit;
    FirePipeEffectSetup* spawnDef;
    GameObject* effectObj;
    f32 radius;
    f32 nearAtten;
    f32 farAtten;

    extra = obj->extra;
    mapData = (FirePipeMapData*)obj->anim.placementData;
    flags = &extra->flags;
    Obj_GetPlayerObject();

    if (obj->ownerObj != NULL)
    {
        ObjHits_DisableObject(obj);
        if (flags->childEmitEnabled == 0)
        {
            return;
        }
        flags->extTriggered = 1;
    }
    else
    {
        priorityHit = ObjHits_GetPriorityHit(obj, 0, 0, 0);
        switch (obj->anim.romDefNo)
        {
        case FIREPIPE_OBJ_BOSSDRAKOR_FIRE:
            if ((priorityHit == 0xf) || (priorityHit == 0xe))
            {
                flags->emitting = 0;
                storeZeroToFloatParam(&extra->cycleTimer);
                s16toFloat(&extra->cycleTimer, 0x12c);
            }
            break;
        case FIREPIPE_OBJ_ICE_HOLE:
            break;
        case FIREPIPE_OBJ_FIRE_PIPE:
        case FIREPIPE_OBJ_STEAM_HOLE_NO:
        case FIREPIPE_OBJ_STEAM_HOLE_FI:
        case FIREPIPE_OBJ_STEAM_HOLE_DE:
        default:
            if (priorityHit == 0x10)
            {
                FirePipeMapData* md0 = (FirePipeMapData*)obj->anim.placementData;
                Obj_StartModelFadeIn(obj, 0x12c);
                mainSetBits(md0->gameBit, 1);
                flags->restartPending = 1;
            }
            break;
        }
    }

    if ((flags->restartPending == 0) && (mapData->gameBit != -1))
    {
        if (flags->lastGameBitState != mainGetBit(mapData->gameBit))
        {
            if ((flags->emitting = !mainGetBit(mapData->gameBit)) != 0)
            {
                FirePipeExtra* ex2;
                FirePipeMapData* md2;
                s16 cycleTime;
                md2 = (FirePipeMapData*)obj->anim.placementData;
                ex2 = obj->extra;
                storeZeroToFloatParam(&ex2->cycleTimer);
                cycleTime = md2->cycleTime;
                if (cycleTime != 0)
                {
                    if (md2->startOffset != 0)
                    {
                        if (md2->startOffset < 0)
                        {
                            s16toFloat(&ex2->cycleTimer, randomGetRange(1, cycleTime * 0x3c));
                        }
                        else
                        {
                            s16toFloat(&ex2->cycleTimer, (md2->startOffset * 0x3c));
                            if (md2->startOffset >= md2->cycleTime)
                            {
                                ex2->flags.emitting = 0;
                            }
                        }
                    }
                    else
                    {
                        s16toFloat(&ex2->cycleTimer, (cycleTime * 0x3c));
                    }
                }
            }
            else
            {
                storeZeroToFloatParam(&extra->cycleTimer);
            }
        }
        flags->lastGameBitState = mainGetBit(mapData->gameBit);
    }

    if (flags->emitting != 0)
    {
        if (((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) || (obj->ownerObj != NULL))
        {
            objfx_spawnPulseBurst(obj, 0.2f * mapData->scale, (u8)extra->effectType, 0, 0, NULL);
        }
    }

    if (objIsFrozen(obj) != 0)
    {
        flags->emitting = 0;
        flags->restartPending = 1;
    }
    else
    {
        if (flags->restartPending != 0)
        {
            flags->emitting = 1;
            flags->restartPending = 0;
            mainSetBits(mapData->gameBit, flags->lastGameBitState);
        }

        if ((timerIsActive(&extra->cycleTimer) != 0) && (flags->emitting == 0))
        {
            if (extra->cycleTimer < gFirePipeCycleTimerThreshold)
            {
                if ((extra->glowLight == 0) && (flags->glowEnabled != 0))
                {
                    extra->glowLight = modelLightStruct_createPointLight(obj, 0xff, 0x80, 0, 0);
                    if (extra->glowLight != 0)
                    {
                        modelLightStruct_setEnabled(extra->glowLight, 0, 0.0f);
                        modelLightStruct_setEnabled(extra->glowLight, 1, 1.0f);
                        if (obj->anim.romDefNo == FIREPIPE_OBJ_ICE_HOLE)
                        {
                            modelLightStruct_setupGlow(extra->glowLight, 0, 0, 0xb4, 0xff, 0x64,
                                                       gFirePipeGlowScale * obj->anim.rootMotionScale);
                        }
                        else
                        {
                            modelLightStruct_setupGlow(extra->glowLight, 0, 0xff, 0x80, 0, 0x64,
                                                       gFirePipeGlowScale * obj->anim.rootMotionScale);
                        }
                        modelLightStruct_setPosition(extra->glowLight, 0.0f, 0.0f, 3.0f);
                        radius = 240.0f * obj->anim.rootMotionScale;
                        nearAtten = (radius < 50.0f)
                                        ? 50.0f
                                        : ((radius > 70.0f) ? 70.0f : radius);
                        farAtten = 30.0f + radius;
                        { /* separate local to reproduce reg assignment */
                            ModelLightStruct* light = (ModelLightStruct*)extra->glowLight;
                            modelLightStruct_setDistanceAttenuation(
                                light, nearAtten,
                                (farAtten < 80.0f)
                                    ? 80.0f
                                    : ((farAtten > 100.0f) ? 100.0f : farAtten));
                        }
                    }
                }
            }
            else if (extra->glowLight != 0)
            {
                modelLightStruct_setEnabled(extra->glowLight, 0, 0.25f);
                if (modelLightStruct_getActiveState((ModelLightStruct*)extra->glowLight) == 0)
                {
                    modelLightStruct_freeSlot(&extra->glowLight);
                }
            }
        }

        if (timerCountDown(&extra->cycleTimer) != 0)
        {
            if (mapData->cycleTime != 0)
            {
                s16toFloat(&extra->cycleTimer, (mapData->cycleTime * 0x3c));
            }
            flags->emitting = (flags->emitting == 0);
        }
    }

    if ((flags->emitting != 0) && (timerCountDown(&extra->emitTimer) != 0))
    {
        FirePipeExtra* ex3;
        FirePipeMapData* md3;
        md3 = (FirePipeMapData*)obj->anim.placementData;
        ex3 = obj->extra;
        spawnDef = (FirePipeEffectSetup*)Obj_AllocObjectSetup(0x24, FIREPIPE_CHILD_OBJ_FLAMETHROWER);
        spawnDef->head.color[0] = 2;
        spawnDef->effectMode = ex3->effectMode;
        spawnDef->scale = md3->scale;
        spawnDef->head.posX = obj->anim.localPosX;
        spawnDef->head.posY = obj->anim.localPosY;
        spawnDef->head.posZ = obj->anim.localPosZ;
        if (spawnDef == 0)
        {
            effectObj = 0;
        }
        else
        {
            effectObj = (GameObject*)firepipe_spawnEffectObject(extra, obj, &spawnDef->head);
        }
        if (effectObj != 0)
        {
            effectObj->anim.localPosX = obj->anim.localPosX;
            effectObj->anim.localPosY = obj->anim.localPosY;
            effectObj->anim.localPosZ = obj->anim.localPosZ;
            effectObj->anim.rotX = obj->anim.rotX;
            effectObj->anim.rotY = obj->anim.rotY;
            effectObj->anim.velocityY = gFirePipeEffectVelocityY;
        }
        storeZeroToFloatParam(&extra->emitTimer);
        s16toFloat(&extra->emitTimer, gFirePipeEmitTimerReset);
    }

    if (flags->emitting != 0)
    {
        if (flags->wasEmitting == 0)
        {
            Sfx_PlayFromObjectLimited(obj, SFXTRIG_en_cvdrip1c_32c, 3);
        }
        Sfx_KeepAliveLoopedObjectSoundLimited(obj, SFXTRIG_en_trpopn_c_32d, 2);
    }
    flags->wasEmitting = flags->emitting;

    if (extra->glowLight != 0)
    {
        modelLightStruct_updateGlowAlpha(extra->glowLight);
    }
}

int firepipe_getExtraSize(void)
{
    return sizeof(FirePipeExtra);
}

u32 firepipe_stateCallback(GameObject* obj)
{
    firepipe_updateState(obj);
    return 0;
}

int firepipe_getObjectTypeId(void)
{
    return 1;
}

void firepipe_free(GameObject* obj)
{
    int i;
    GameObject** iter;
    FirePipeExtra* extra;

    extra = obj->extra;
    objFreeObjectType(obj, FIREPIPE_OBJGROUP);
    i = 0;
    iter = extra->effectObjs;
    while (i < (int)(u32)extra->effectCount)
    {
        Obj_FreeObject(*iter);
        iter++;
        i++;
    }
    if (extra->glowLight != NULL)
    {
        modelLightStruct_freeSlot(&extra->glowLight);
    }
}

void firepipe_render(GameObject* obj, int p1, int p2, int p3, int p4, char visible)
{
    FirePipeExtra* extra;
    ModelLightStruct* glowLight;

    extra = obj->extra;
    glowLight = extra->glowLight;
    if (glowLight != NULL && glowLight->glowType != 0 && glowLight->enabled != 0)
    {
        queueGlowRender(glowLight);
    }
    if (visible != 0 && extra->flags.renderEnabled != 0)
    {
        objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, 1.0f);
    }
}

void firepipe_update(GameObject* obj)
{
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
    firepipe_updateState(obj);
}

void firepipe_init(GameObject* obj, FirePipeMapData* mapData)
{
    FirePipeExtra* extra;
    FirePipeExtra* extra2;
    FirePipeMapData* def;
    short startTime;
    short cycleTime;
    u32 bitVal;
    u32 flagValue;

    extra = obj->extra;
    if ((int)mapData->scale != 0)
    {
        f32 scale = 0.1f * (f32)(s32)mapData->scale;
        obj->anim.rootMotionScale = scale * obj->anim.modelInstance->rootMotionScaleBase;
    }
    if (mapData->gameBit != -1)
    {
        bitVal = mainGetBit((int)mapData->gameBit);
        extra->flags.emitting = bitVal;
    }
    else
    {
        extra->flags.emitting = 1;
    }
    obj->animEventCallback = firepipe_stateCallback;
    {
        def = (FirePipeMapData*)obj->anim.placementData;
        extra2 = obj->extra;
        storeZeroToFloatParam(&extra2->cycleTimer);
        cycleTime = def->cycleTime;
        if (cycleTime != 0)
        {
            startTime = def->startOffset;
            if (startTime != 0)
            {
                if (startTime < 0)
                {
                    cycleTime = randomGetRange(1, cycleTime * 0x3c);
                    s16toFloat(&extra2->cycleTimer, cycleTime);
                }
                else
                {
                    s16toFloat(&extra2->cycleTimer, (int)(short)(startTime * 0x3c));
                    if (def->startOffset >= def->cycleTime)
                    {
                        extra2->flags.emitting = 0;
                    }
                }
            }
            else
            {
                s16toFloat(&extra2->cycleTimer, (int)(short)(cycleTime * 0x3c));
            }
        }
        extra->clearVolumeA = 0;
        extra->clearVolumeB = 0;
        switch (obj->anim.romDefNo)
        {
        case FIREPIPE_OBJ_ICE_HOLE:
            extra->effectType = FIREPIPE_EFFECT_TYPE_ICE_HOLE;
            extra->effectMode = 1;
            extra->effectScale = gFirePipeEffectScale;
            break;
        case FIREPIPE_OBJ_STEAM_HOLE_FI:
            extra->effectType = FIREPIPE_EFFECT_TYPE_STEAM_HOLE_FI;
            extra->effectMode = 2;
            extra->effectScale = 0.0f;
            break;
        case FIREPIPE_OBJ_STEAM_HOLE_NO:
            extra->effectType = FIREPIPE_EFFECT_TYPE_STEAM_HOLE_NO;
            extra->effectMode = 2;
            extra->effectScale = 0.0f;
            break;
        case FIREPIPE_OBJ_STEAM_HOLE_DE:
            extra->effectType = FIREPIPE_EFFECT_TYPE_STEAM_HOLE_DE;
            extra->effectMode = 2;
            extra->effectScale = 0.0f;
            break;
        case FIREPIPE_OBJ_FIRE_PIPE:
        case FIREPIPE_OBJ_BOSSDRAKOR_FIRE:
        default:
            extra->effectType = FIREPIPE_EFFECT_TYPE_FLAME;
            extra->effectMode = 0;
            extra->effectScale = -gFirePipeEffectScale;
            extra->clearVolumeA = 0x32c;
            extra->clearVolumeB = 0x32e;
            break;
        }
        extra->effectObjs[0] = 0;
        extra->effectObjs[1] = 0;
        extra->effectObjs[2] = 0;
        extra->effectObjs[3] = 0;
        extra->effectObjs[4] = 0;
        extra->effectObjs[5] = 0;
        extra->effectObjs[6] = 0;
        extra->effectObjs[7] = 0;
        extra->effectCount = 0;
        obj->anim.rotZ = 0;
        obj->anim.rotX = (short)((int)mapData->rotX << 8);
        obj->anim.rotY = mapData->rotY << 8;
        ObjHits_EnableObject(obj);
        extra->flags.restartPending = 0;
        extra->activeSpawn = 0;
        bitVal = mainGetBit((int)mapData->gameBit);
        {
            u32 clz = __cntlzw(bitVal);
            extra->flags.lastGameBitState = (u8)(clz >> 5);
        }
        if ((mapData->flags & 1) != 0)
        {
            flagValue = 0;
        }
        else
        {
            flagValue = 1;
        }
        extra->flags.renderEnabled = flagValue;
        if ((mapData->flags & 2) != 0)
        {
            flagValue = 0;
        }
        else
        {
            flagValue = 1;
        }
        extra->flags.glowEnabled = flagValue;
        storeZeroToFloatParam(&extra->emitTimer);
        s16toFloat(&extra->emitTimer, 0x14);
        objAddObjectType(obj, FIREPIPE_OBJGROUP);
        extra->flags.childEmitEnabled = 0;
        extra->glowLight = NULL;
    }
}

ObjectDescriptor gFirePipeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)firepipe_init,
    (ObjectDescriptorCallback)firepipe_update,
    0,
    (ObjectDescriptorCallback)firepipe_render,
    (ObjectDescriptorCallback)firepipe_free,
    (ObjectDescriptorCallback)firepipe_getObjectTypeId,
    firepipe_getExtraSize,
};
