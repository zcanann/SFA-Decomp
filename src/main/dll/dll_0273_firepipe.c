/*
 * firepipe (DLL 0x273) - a cyclic flame/jet emitter placed in the world.
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
 * the object spawns pooled `flamethrowerspe` (DLL 0x0E4) flame-stream
 * effects (FirePipeExtra.effectObjs); clearing `emitting` stops the jet and
 * freezing `cycleTimer` keeps it off; FirePipeMapData.rotX/rotY aim the jet
 * (changing them swings the model and the flame); `glowLight` is the
 * point-light that tracks the emitter.
 */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/obj_placement.h"
#include "string.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/sfa_shared_decls.h"

#define FIREPIPE_OBJGROUP 0x4a

#define FIREPIPE_OBJFLAG_ACTIVE 0x200
#define FIREPIPE_OBJFLAG_RENDERED 0x800
#define FIREPIPE_OBJFLAG_UPDATE_DISABLED 0x8000
extern void modelLightStruct_freeSlot(int p);
extern int randomGetRange(int lo, int hi);
extern void* Obj_GetPlayerObject(void);
extern u8 Obj_IsLoadingLocked(void);
extern void Obj_FreeObject(int obj);
extern int loadObjectAtObject(FirePipeObject* obj, void* spawnDef);
extern void Obj_InsertIntoUpdateList(int obj);
extern void Obj_RemoveFromUpdateList(FirePipeObject * obj);


extern void ObjHits_EnableObject(FirePipeObject * obj);
extern void ObjHits_DisableObject(FirePipeObject * obj);
extern int ObjHits_GetPriorityHit(FirePipeObject* obj, int a, int b, int c);
extern void Obj_StartModelFadeIn(FirePipeObject* obj, int timer);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void ObjGroup_RemoveObject();
extern void ObjGroup_AddObject();
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, double scale);
extern void queueGlowRender(void);
extern void storeZeroToFloatParam(f32* p);
extern void s16toFloat(f32* p, s16 val);
extern void fn_80098B18(void* obj, f32 scale, int type, int count, int mode, f32* vec);
extern int objIsFrozen(FirePipeObject * obj);
extern int fn_80080150(int timer);
extern int timerCountDown(int timer);
extern int modelLightStruct_createPointLight(FirePipeObject* obj, int r, int g, int b, int a);
extern void modelLightStruct_setEnabled(int light, int mode, f32 value);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern int modelLightStruct_getActiveState(int light);
extern void modelLightStruct_updateGlowAlpha(int light);
extern void Sfx_PlayFromObjectLimited(FirePipeObject* obj, int sfxId, int limit);
extern void Sfx_KeepAliveLoopedObjectSoundLimited(FirePipeObject* obj, int sfxId, int limit);
extern f32 lbl_803DC340;
extern f32 lbl_803DC344;
extern s16 lbl_803DC348;
extern f32 lbl_803DC34C;
extern int lbl_803DC350;
extern f32 lbl_803E6B70;
extern f32 lbl_803E6B74;
extern f32 lbl_803E6B78;
extern f32 lbl_803E6B7C;
extern f32 lbl_803E6B80;
extern f32 gFirePipeNearAttenMin;
extern f32 gFirePipeNearAttenMax;
extern f32 lbl_803E6B8C;
extern f32 gFirePipeFarAttenMin;
extern f32 gFirePipeFarAttenMax;
extern f32 lbl_803E6B98;
extern f32 lbl_803E6BA8;

/* objectId variants handled by this DLL (select the emitted effect). */
#define FIREPIPE_OBJ_BLUE 0x6f9
#define FIREPIPE_OBJ_C 0x730
#define FIREPIPE_OBJ_D 0x731
#define FIREPIPE_OBJ_E 0x732
#define FIREPIPE_OBJ_FLAME_A 0x4a4
#define FIREPIPE_OBJ_FLAME_B 0x70a

typedef struct
{
    u8 lastGameBitState : 1; /* bit7: snapshot of gameBit, for change detection */
    u8 emitting : 1;         /* bit6: jet is actively firing (live-verified) */
    u8 wasEmitting : 1;      /* bit5: previous-frame `emitting`, for sound edge */
    u8 restartPending : 1;   /* bit4: hit/freeze interrupted; re-enable emit when able */
    u8 extTriggered : 1;     /* bit3: set when externally driven; not read in this DLL */
    u8 childEmitEnabled : 1; /* bit2: emit enable when linked as a child (firecrawler) */
    u8 renderEnabled : 1;    /* bit1: draw the emitter model (from placement flag 0x1) */
    u8 glowEnabled : 1;      /* bit0: spawn the point-light glow (from placement flag 0x2) */
} FirePipeBitFlags;

typedef void (*FirePipeEffectInitFn)(int obj, void* spawnDef, int p3);

/* Spawn-setup buffer seeded by firepipe_updateState for the emitted flame
 * effect (defNo 0x1b5). Reuses ObjPlacement's color/pos head and adds the
 * class-specific effectMode/scale fields; store widths per target asm. */
typedef struct FirePipeEffectSetup
{
    ObjPlacement head;  /* 0x00: color at +4, pos at +8/+c/+10 */
    u8 pad18;           /* 0x18 */
    s8 effectMode;      /* 0x19 */
    s16 scale;          /* 0x1a */
} FirePipeEffectSetup;

#pragma dont_inline on
int firepipe_spawnEffectObject(FirePipeExtra* extra, FirePipeObject* obj, void* spawnDef)
{
    int i;
    int effectObj;
    int freeDelay;

    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    for (i = 0; i < extra->effectCount; i++)
    {
        effectObj = extra->effectObjs[i];
        if ((((GameObject*)effectObj)->objectFlags & FIREPIPE_OBJFLAG_ACTIVE) == 0)
        {
            ((GameObject*)effectObj)->objectFlags |= FIREPIPE_OBJFLAG_ACTIVE;
            memcpy(((GameObject*)effectObj)->anim.placement, spawnDef, *(u8*)((int)spawnDef + 2));
            ((GameObject*)effectObj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((GameObject*)effectObj)->anim.localPosX = *(float*)((int)spawnDef + 8);
            ((GameObject*)effectObj)->anim.localPosY = *(float*)((int)spawnDef + 0xc);
            ((GameObject*)effectObj)->anim.localPosZ = *(float*)((int)spawnDef + 0x10);
            (*(FirePipeEffectInitFn*)(**(int**)(effectObj + 0x68) + 4))(effectObj, spawnDef, 0);
            freeDelay = mmSetFreeDelay(0);
            mm_free(spawnDef);
            mmSetFreeDelay(freeDelay);
            Obj_InsertIntoUpdateList(effectObj);
            ((GameObject*)effectObj)->objectFlags &= ~FIREPIPE_OBJFLAG_UPDATE_DISABLED;
            return effectObj;
        }
    }
    effectObj = loadObjectAtObject(obj, spawnDef);
    if (extra->effectCount != 8)
    {
        ((GameObject*)effectObj)->objectFlags |= FIREPIPE_OBJFLAG_ACTIVE;
        i = extra->effectCount++;
        extra->effectObjs[i] = effectObj;
    }
    return effectObj;
}
#pragma dont_inline reset

void firepipe_releaseEffectObject(FirePipeObject* obj)
{
    if ((((GameObject*)obj)->objectFlags & FIREPIPE_OBJFLAG_ACTIVE) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->objectFlags &= ~FIREPIPE_OBJFLAG_ACTIVE;
        Obj_RemoveFromUpdateList(obj);
        ((GameObject*)obj)->objectFlags |= FIREPIPE_OBJFLAG_UPDATE_DISABLED;
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        Obj_FreeObject((int)obj);
    }
}

int firepipe_clearLinkedUpdateFlag(FirePipeObject* obj)
{
    ((FirePipeBitFlags*)&obj->extra->flags)->childEmitEnabled = 0;
    return 1;
}

int firepipe_setLinkedUpdateFlag(FirePipeObject* obj)
{
    ((FirePipeBitFlags*)&obj->extra->flags)->childEmitEnabled = 1;
    return 1;
}

void firepipe_updateState(FirePipeObject* obj)
{
    FirePipeExtra* extra;
    FirePipeMapData* mapData;
    FirePipeBitFlags* flags;
    int priorityHit;
    u8* spawnDef;
    u8* effectObj;
    f32 radius;
    f32 nearAtten;
    f32 farAtten;

    extra = obj->extra;
    mapData = (FirePipeMapData*)obj->objectDef;
    flags = (FirePipeBitFlags*)&extra->flags;
    Obj_GetPlayerObject();

    if (obj->callback != NULL)
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
        switch (obj->objectId)
        {
        case FIREPIPE_OBJ_FLAME_B:
            if ((priorityHit == 0xf) || (priorityHit == 0xe))
            {
                flags->emitting = 0;
                storeZeroToFloatParam(&extra->cycleTimer);
                s16toFloat(&extra->cycleTimer, 0x12c);
            }
            break;
        case FIREPIPE_OBJ_BLUE:
            break;
        case FIREPIPE_OBJ_FLAME_A:
        case FIREPIPE_OBJ_C:
        case FIREPIPE_OBJ_D:
        case FIREPIPE_OBJ_E:
        default:
            if (priorityHit == 0x10)
            {
                FirePipeMapData* md0 = (FirePipeMapData*)obj->objectDef;
                Obj_StartModelFadeIn(obj, 0x12c);
                GameBit_Set(md0->gameBit, 1);
                flags->restartPending = 1;
            }
            break;
        }
    }

    if ((flags->restartPending == 0) && (mapData->gameBit != -1))
    {
        if (flags->lastGameBitState != GameBit_Get(mapData->gameBit))
        {
            if ((flags->emitting = !GameBit_Get(mapData->gameBit)) != 0)
            {
                FirePipeExtra* ex2;
                FirePipeMapData* md2;
                s16 cycleTime;
                md2 = (FirePipeMapData*)obj->objectDef;
                ex2 = obj->extra;
                storeZeroToFloatParam(&ex2->cycleTimer);
                cycleTime = md2->cycleTime;
                if (cycleTime != 0)
                {
                    if (md2->startOffset != 0)
                    {
                        if (md2->startOffset < 0)
                        {
                            s16toFloat(&ex2->cycleTimer,
                                       randomGetRange(1, cycleTime * 0x3c));
                        }
                        else
                        {
                            s16toFloat(&ex2->cycleTimer, (s16)(md2->startOffset * 0x3c));
                            if (md2->startOffset >= md2->cycleTime)
                            {
                                ((FirePipeBitFlags*)&ex2->flags)->emitting = 0;
                            }
                        }
                    }
                    else
                    {
                        s16toFloat(&ex2->cycleTimer, (s16)(cycleTime * 0x3c));
                    }
                }
            }
            else
            {
                storeZeroToFloatParam(&extra->cycleTimer);
            }
        }
        flags->lastGameBitState = GameBit_Get(mapData->gameBit);
    }

    if (flags->emitting != 0)
    {
        if (((((GameObject*)obj)->objectFlags & FIREPIPE_OBJFLAG_RENDERED) != 0) || (obj->callback != NULL))
        {
            fn_80098B18(obj, lbl_803E6B70 * mapData->scale, (u8)extra->effectType, 0, 0, 0);
        }
    }

    if (objIsFrozen(obj) != 0)
    {
        flags->emitting = 0;
        flags->restartPending = 1;
        goto sound_update;
    }

    if (flags->restartPending != 0)
    {
        flags->emitting = 1;
        flags->restartPending = 0;
        GameBit_Set(mapData->gameBit, flags->lastGameBitState);
    }

    if ((fn_80080150((int)&extra->cycleTimer) != 0) && (flags->emitting == 0))
    {
        if (extra->cycleTimer < lbl_803DC348)
        {
            if ((extra->glowLight == 0) && (flags->glowEnabled != 0))
            {
                extra->glowLight = modelLightStruct_createPointLight(obj, 0xff, 0x80, 0, 0);
                if (extra->glowLight != 0)
                {
                    modelLightStruct_setEnabled(extra->glowLight, 0, lbl_803E6B74);
                    modelLightStruct_setEnabled(extra->glowLight, 1, lbl_803E6B78);
                    if (obj->objectId == FIREPIPE_OBJ_BLUE)
                    {
                        modelLightStruct_setupGlow(extra->glowLight, 0, 0, 0xb4, 0xff, 0x64,
                                                   lbl_803DC34C * obj->scale);
                    }
                    else
                    {
                        modelLightStruct_setupGlow(extra->glowLight, 0, 0xff, 0x80, 0, 0x64,
                                                   lbl_803DC34C * obj->scale);
                    }
                    modelLightStruct_setPosition(extra->glowLight, lbl_803E6B74, *(f32*)&lbl_803E6B74, lbl_803E6B7C);
                    radius = lbl_803E6B80 * obj->scale;
                    nearAtten = (radius < gFirePipeNearAttenMin)
                                    ? gFirePipeNearAttenMin
                                    : ((radius > gFirePipeNearAttenMax) ? gFirePipeNearAttenMax : radius);
                    farAtten = lbl_803E6B8C + radius;
                    { /* separate local to reproduce reg assignment */
                        int light = extra->glowLight;
                        modelLightStruct_setDistanceAttenuation(light, nearAtten,
                                                                (farAtten < gFirePipeFarAttenMin)
                                                                    ? gFirePipeFarAttenMin
                                                                    : ((farAtten > gFirePipeFarAttenMax)
                                                                           ? gFirePipeFarAttenMax
                                                                           : farAtten));
                    }
                }
            }
        }
        else if (extra->glowLight != 0)
        {
            modelLightStruct_setEnabled(extra->glowLight, 0, lbl_803E6B98);
            if (modelLightStruct_getActiveState(extra->glowLight) == 0)
            {
                modelLightStruct_freeSlot((int)&extra->glowLight);
            }
        }
    }

    if (timerCountDown((int)extra + 0x24) != 0)
    {
        if (mapData->cycleTime != 0)
        {
            s16toFloat(&extra->cycleTimer, (s16)(mapData->cycleTime * 0x3c));
        }
        flags->emitting = (flags->emitting == 0);
    }

sound_update:
    if ((flags->emitting != 0) && (timerCountDown((int)&extra->emitTimer) != 0))
    {
        FirePipeExtra* ex3;
        FirePipeMapData* md3;
        md3 = (FirePipeMapData*)obj->objectDef;
        ex3 = obj->extra;
        spawnDef = (u8*)Obj_AllocObjectSetup(0x24, 0x1b5);
        ((FirePipeEffectSetup*)spawnDef)->head.color[0] = 2;
        ((FirePipeEffectSetup*)spawnDef)->effectMode = ex3->effectMode;
        ((FirePipeEffectSetup*)spawnDef)->scale = md3->scale;
        ((FirePipeEffectSetup*)spawnDef)->head.posX = ((GameObject*)obj)->anim.localPosX;
        ((FirePipeEffectSetup*)spawnDef)->head.posY = ((GameObject*)obj)->anim.localPosY;
        ((FirePipeEffectSetup*)spawnDef)->head.posZ = ((GameObject*)obj)->anim.localPosZ;
        if (spawnDef == 0)
        {
            effectObj = 0;
        }
        else
        {
            effectObj = (u8*)firepipe_spawnEffectObject(extra, obj, spawnDef);
        }
        if (effectObj != 0)
        {
            ((GameObject*)effectObj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)effectObj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)effectObj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ;
            ((GameObject*)effectObj)->anim.rotX = ((GameObject*)obj)->anim.rotX;
            ((GameObject*)effectObj)->anim.rotY = ((GameObject*)obj)->anim.rotY;
            ((GameObject*)effectObj)->anim.velocityY = lbl_803DC344;
        }
        storeZeroToFloatParam(&extra->emitTimer);
        s16toFloat(&extra->emitTimer, lbl_803DC350);
    }

    if (flags->emitting != 0)
    {
        if (flags->wasEmitting == 0)
        {
            Sfx_PlayFromObjectLimited(obj, SFXand_missilelaunch, 3);
        }
        Sfx_KeepAliveLoopedObjectSoundLimited(obj, SFXand_suck_lp, 2);
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

u32 firepipe_stateCallback(FirePipeObject* obj)
{
    firepipe_updateState(obj);
    return 0;
}

int firepipe_getObjectTypeId(void)
{
    return 1;
}

void firepipe_free(FirePipeObject* obj)
{
    int i;
    int* iter;
    FirePipeExtra* extra;

    extra = obj->extra;
    ObjGroup_RemoveObject(obj, FIREPIPE_OBJGROUP);
    i = 0;
    iter = (int*)extra;
    while (i < (int)(u32)extra->effectCount)
    {
        Obj_FreeObject(*iter);
        iter++;
        i++;
    }
    if ((u32)extra->glowLight != 0)
    {
        modelLightStruct_freeSlot((int)&extra->glowLight);
    }
}

void firepipe_render(FirePipeObject* obj, int p1, int p2, int p3, int p4, char visible)
{
    FirePipeExtra* extra;
    int glowLight;

    extra = obj->extra;
    glowLight = extra->glowLight;
    if ((u32)glowLight != 0 && *(u8*)(glowLight + 0x2f8) != 0 && *(u8*)(glowLight + 0x4c) != 0)
    {
        queueGlowRender();
    }
    if (visible != 0 && (u32)((extra->flags >> 1) & 1) != 0)
    {
        objRenderModelAndHitVolumes((int)obj, p1, p2, p3, p4, (double)lbl_803E6B78);
    }
}

void firepipe_update(FirePipeObject* obj)
{
    obj->statusFlags = (u8)(obj->statusFlags | 8);
    firepipe_updateState(obj);
}

void firepipe_init(FirePipeObject* obj, FirePipeMapData* mapData)
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
        f32 scale = lbl_803E6BA8 * (f32)(s32)
        mapData->scale;
        obj->scale = scale * obj->anim.modelInstance->rootMotionScaleBase;
    }
    if (mapData->gameBit != -1)
    {
        bitVal = GameBit_Get((int)mapData->gameBit);
        ((FirePipeBitFlags*)&extra->flags)->emitting = bitVal;
    }
    else
    {
        ((FirePipeBitFlags*)&extra->flags)->emitting = 1;
    }
    obj->sequenceCallback = firepipe_stateCallback;
    {
        def = (FirePipeMapData*)obj->objectDef;
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
                        ((FirePipeBitFlags*)&extra2->flags)->emitting = 0;
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
        switch (obj->objectId)
        {
        case FIREPIPE_OBJ_BLUE:
            extra->effectType = 10;
            extra->effectMode = 1;
            extra->effectScale = lbl_803DC340;
            break;
        case FIREPIPE_OBJ_D:
            extra->effectType = 0xd;
            extra->effectMode = 2;
            extra->effectScale = lbl_803E6B74;
            break;
        case FIREPIPE_OBJ_C:
            extra->effectType = 0xc;
            extra->effectMode = 2;
            extra->effectScale = lbl_803E6B74;
            break;
        case FIREPIPE_OBJ_E:
            extra->effectType = 0xe;
            extra->effectMode = 2;
            extra->effectScale = lbl_803E6B74;
            break;
        case FIREPIPE_OBJ_FLAME_A:
        case FIREPIPE_OBJ_FLAME_B:
        default:
            extra->effectType = 9;
            extra->effectMode = 0;
            extra->effectScale = -lbl_803DC340;
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
        obj->resetTimer = 0;
        obj->rotX = (short)((int)mapData->rotX << 8);
        obj->rotY = mapData->rotY << 8;
        ObjHits_EnableObject(obj);
        ((FirePipeBitFlags*)&extra->flags)->restartPending = 0;
        extra->activeSpawn = 0;
        bitVal = GameBit_Get((int)mapData->gameBit);
        {
            u32 clz = __cntlzw(bitVal);
            ((FirePipeBitFlags*)&extra->flags)->lastGameBitState = (u8)(clz >> 5);
        }
        if ((mapData->flags & 1) != 0)
        {
            flagValue = 0;
        }
        else
        {
            flagValue = 1;
        }
        ((FirePipeBitFlags*)&extra->flags)->renderEnabled = flagValue;
        if ((mapData->flags & 2) != 0)
        {
            flagValue = 0;
        }
        else
        {
            flagValue = 1;
        }
        ((FirePipeBitFlags*)&extra->flags)->glowEnabled = flagValue;
        storeZeroToFloatParam(&extra->emitTimer);
        s16toFloat(&extra->emitTimer, 0x14);
        ObjGroup_AddObject(obj, FIREPIPE_OBJGROUP);
        ((FirePipeBitFlags*)&extra->flags)->childEmitEnabled = 0;
        extra->glowLight = 0;
    }
}

ObjectDescriptor gFirePipeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0, 0, 0,
    (ObjectDescriptorCallback)firepipe_init,
    (ObjectDescriptorCallback)firepipe_update,
    0,
    (ObjectDescriptorCallback)firepipe_render,
    (ObjectDescriptorCallback)firepipe_free,
    (ObjectDescriptorCallback)firepipe_getObjectTypeId,
    firepipe_getExtraSize,
};
