#include "ghidra_import.h"
#include "main/audio/sfx_ids.h"
#include "global.h"
#include "main/dll/firepipe.h"
#include "string.h"

extern undefined4 modelLightStruct_freeSlot(int param_1);
extern undefined4 GameBit_Get(int eventId);
extern undefined4 randomGetRange(int param_1, int param_2);
extern int Obj_GetPlayerObject(void);
extern u8 Obj_IsLoadingLocked(void);
extern undefined4 Obj_FreeObject(int param_1);
extern int loadObjectAtObject(FirePipeObject *obj, void *spawnDef);
extern void fn_8002CE14(int obj);
extern void objRemoveFromListFn_8002ce88(FirePipeObject *obj);
extern int mmSetFreeDelay(int delay);
extern void mm_free(void *ptr);
extern undefined4 ObjHits_EnableObject(FirePipeObject *obj);
extern void ObjHits_DisableObject(FirePipeObject *obj);
extern int ObjHits_GetPriorityHit(FirePipeObject *obj, int a, int b, int c);
extern void Obj_StartModelFadeIn(FirePipeObject *obj, int timer);
extern int Obj_AllocObjectSetup(int size, int objectId);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 objRenderFn_8003b8f4(int param_1, int param_2, int param_3, int param_4, int param_5, double scale);
extern undefined4 queueGlowRender(void);
extern void storeZeroToFloatParam(f32 *param_1);
extern void s16toFloat(f32 *param_1, s16 param_2);
extern void fn_80098B18(FirePipeObject *obj, int type, int a, int b, int c, f32 scale);
extern int objIsFrozen(FirePipeObject *obj);
extern int fn_80080150(int timer);
extern int timerCountDown(int timer);
extern int modelLightStruct_createPointLight(FirePipeObject *obj, int r, int g, int b, int a);
extern void modelLightStruct_setEnabled(int light, int mode, f32 value);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern int modelLightStruct_getActiveState(int light);
extern void modelLightStruct_updateGlowAlpha(int light);
extern void Sfx_PlayFromObjectLimited(FirePipeObject *obj, int sfxId, int limit);
extern void Sfx_KeepAliveLoopedObjectSoundLimited(FirePipeObject *obj, int sfxId, int limit);

extern f32 lbl_803DC340;
extern f32 lbl_803DC344;
extern s16 lbl_803DC348;
extern f32 lbl_803DC34C;
extern s16 lbl_803DC350;
extern f32 lbl_803E6B70;
extern f32 lbl_803E6B74;
extern f32 lbl_803E6B78;
extern f32 lbl_803E6B7C;
extern f32 lbl_803E6B80;
extern f32 lbl_803E6B84;
extern f32 lbl_803E6B88;
extern f32 lbl_803E6B8C;
extern f32 lbl_803E6B90;
extern f32 lbl_803E6B94;
extern f32 lbl_803E6B98;
extern f64 lbl_803E6BA0;
extern f32 lbl_803E6BA8;

typedef struct {
    u8 bit7 : 1;
    u8 bit6 : 1;
    u8 bit5 : 1;
    u8 bit4 : 1;
    u8 bit3 : 1;
    u8 bit2 : 1;
    u8 bit1 : 1;
    u8 bit0 : 1;
} FirePipeBitFlags;

typedef void (*FirePipeEffectInitFn)(int obj, void *spawnDef, int param_3);

#pragma scheduling off
#pragma peephole off
int firepipe_spawnEffectObject(FirePipeExtra *extra, FirePipeObject *obj, void *spawnDef)
{
    int i;
    int effectObj;
    int freeDelay;

    if (Obj_IsLoadingLocked() == 0) {
        return 0;
    }
    for (i = 0; i < extra->effectCount; i++) {
        effectObj = extra->effectObjs[i];
        if ((*(u16 *)(effectObj + 0xb0) & 0x200) == 0) {
            *(u16 *)(effectObj + 0xb0) |= 0x200;
            memcpy(*(void **)(effectObj + 0x4c), spawnDef, *(u8 *)((int)spawnDef + 2));
            *(s16 *)(effectObj + 6) &= ~0x4000;
            *(float *)(effectObj + 0xc) = *(float *)((int)spawnDef + 8);
            *(float *)(effectObj + 0x10) = *(float *)((int)spawnDef + 0xc);
            *(float *)(effectObj + 0x14) = *(float *)((int)spawnDef + 0x10);
            (*(FirePipeEffectInitFn *)(**(int **)(effectObj + 0x68) + 4))(effectObj, spawnDef, 0);
            freeDelay = mmSetFreeDelay(0);
            mm_free(spawnDef);
            mmSetFreeDelay(freeDelay);
            fn_8002CE14(effectObj);
            *(u16 *)(effectObj + 0xb0) &= ~0x8000;
            return effectObj;
        }
    }
    effectObj = loadObjectAtObject(obj, spawnDef);
    if (extra->effectCount != 8) {
        *(u16 *)(effectObj + 0xb0) |= 0x200;
        i = extra->effectCount++;
        extra->effectObjs[i] = effectObj;
    }
    return effectObj;
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void firepipe_releaseEffectObject(FirePipeObject *obj)
{
    if ((*(u16 *)((int)obj + 0xb0) & 0x200) != 0) {
        ObjHits_DisableObject(obj);
        *(u16 *)((int)obj + 0xb0) &= ~0x200;
        objRemoveFromListFn_8002ce88(obj);
        *(u16 *)((int)obj + 0xb0) |= 0x8000;
        *(s16 *)((int)obj + 6) |= 0x4000;
    } else {
        Obj_FreeObject((int)obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
int firepipe_clearLinkedUpdateFlag(FirePipeObject *obj)
{
    ((FirePipeBitFlags *)&obj->extra->flags)->bit2 = 0;
    return 1;
}

int firepipe_setLinkedUpdateFlag(FirePipeObject *obj)
{
    ((FirePipeBitFlags *)&obj->extra->flags)->bit2 = 1;
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void firepipe_updateState(FirePipeObject *obj)
{
    FirePipeExtra *extra;
    FirePipeMapData *mapData;
    FirePipeBitFlags *flags;
    int priorityHit;
    int spawnDef;
    int effectObj;
    f32 radius;
    f32 nearAtten;
    f32 farAtten;

    extra = obj->extra;
    mapData = (FirePipeMapData *)obj->objectDef;
    flags = (FirePipeBitFlags *)&extra->flags;
    Obj_GetPlayerObject();

    if (obj->callback != NULL) {
        ObjHits_DisableObject(obj);
        if (flags->bit2 == 0) {
            goto update_light;
        }
        flags->bit3 = 1;
    } else {
        priorityHit = ObjHits_GetPriorityHit(obj,0,0,0);
        switch (obj->objectId) {
        case 0x70a:
            if ((priorityHit == 0xf) || (priorityHit == 0xe)) {
                flags->bit6 = 0;
                storeZeroToFloatParam(&extra->cycleTimer);
                s16toFloat(&extra->cycleTimer, 0x12c);
            }
            break;
        case 0x6f9:
            break;
        case 0x4a4:
        case 0x730:
        case 0x731:
        case 0x732:
        default:
            if (priorityHit == 0x10) {
                Obj_StartModelFadeIn(obj,0x12c);
                GameBit_Set(mapData->gameBit,1);
                flags->bit4 = 1;
            }
            break;
        }
    }

    if ((flags->bit4 == 0) && (mapData->gameBit != -1)) {
        if ((u8)flags->bit7 != (u8)GameBit_Get(mapData->gameBit)) {
            flags->bit6 = (GameBit_Get(mapData->gameBit) != 0);
            if (flags->bit6 != 0) {
                storeZeroToFloatParam(&extra->cycleTimer);
                if (mapData->timer != 0) {
                    if (mapData->flags != 0) {
                        if ((s8)mapData->flags < 0) {
                            s16toFloat(&extra->cycleTimer,
                                       (s16)randomGetRange(1,mapData->timer * 0x3c));
                        } else {
                            s16toFloat(&extra->cycleTimer, (s16)(mapData->flags * 0x3c));
                            if (mapData->flags >= mapData->timer) {
                                flags->bit6 = 0;
                            }
                        }
                    } else {
                        s16toFloat(&extra->cycleTimer, (s16)(mapData->timer * 0x3c));
                    }
                }
            } else {
                storeZeroToFloatParam(&extra->cycleTimer);
            }
        }
        flags->bit7 = (u8)GameBit_Get(mapData->gameBit);
    }

    if (flags->bit6 != 0) {
        if (((*(u16 *)((u8 *)obj + 0xb0) & 0x800) != 0) || (obj->callback != NULL)) {
            fn_80098B18(obj,(u8)extra->effectType,0,0,0,lbl_803E6B70 * (f32)mapData->scale);
        }
    }

    if (objIsFrozen(obj) != 0) {
        flags->bit6 = 0;
        flags->bit4 = 1;
        goto sound_update;
    }

    if (flags->bit4 != 0) {
        flags->bit6 = 1;
        flags->bit4 = 0;
        GameBit_Set(mapData->gameBit,(u8)flags->bit7);
    }

    if ((fn_80080150((int)extra + 0x24) != 0) && (flags->bit6 == 0)) {
        if (*(u8 *)&extra->cycleTimer < lbl_803DC348) {
            if ((extra->subObj == 0) && (flags->bit0 != 0)) {
                extra->subObj = modelLightStruct_createPointLight(obj,0xff,0x80,0,0);
                if (extra->subObj != 0) {
                    modelLightStruct_setEnabled(extra->subObj,0,lbl_803E6B74);
                    modelLightStruct_setEnabled(extra->subObj,1,lbl_803E6B78);
                    if (obj->objectId == 0x6f9) {
                        modelLightStruct_setupGlow(extra->subObj,0,0,0xb4,0xff,0x64,
                                    lbl_803DC34C * obj->scale);
                    } else {
                        modelLightStruct_setupGlow(extra->subObj,0,0xff,0x80,0,0x64,
                                    lbl_803DC34C * obj->scale);
                    }
                    modelLightStruct_setPosition(extra->subObj,lbl_803E6B74,lbl_803E6B74,lbl_803E6B7C);
                    radius = lbl_803E6B80 * obj->scale;
                    nearAtten = radius;
                    if (radius >= lbl_803E6B84) {
                        if (radius > lbl_803E6B88) {
                            nearAtten = lbl_803E6B88;
                        }
                    } else {
                        nearAtten = lbl_803E6B84;
                    }
                    farAtten = lbl_803E6B8C + radius;
                    if (farAtten >= lbl_803E6B90) {
                        if (farAtten > lbl_803E6B94) {
                            farAtten = lbl_803E6B94;
                        }
                    } else {
                        farAtten = lbl_803E6B90;
                    }
                    modelLightStruct_setDistanceAttenuation(extra->subObj,nearAtten,farAtten);
                }
            }
        } else if (extra->subObj != 0) {
            modelLightStruct_setEnabled(extra->subObj,0,lbl_803E6B98);
            if (modelLightStruct_getActiveState(extra->subObj) == 0) {
                modelLightStruct_freeSlot((int)&extra->subObj);
            }
        }
    }

    if (timerCountDown((int)extra + 0x24) != 0) {
        if (mapData->timer != 0) {
            s16toFloat(&extra->cycleTimer, (s16)(mapData->timer * 0x3c));
        }
        flags->bit6 = (flags->bit6 == 0);
    }

sound_update:
    if ((flags->bit6 != 0) && (timerCountDown((int)extra + 0x28) != 0)) {
        spawnDef = Obj_AllocObjectSetup(0x24,0x1b5);
        *(u8 *)(spawnDef + 4) = 2;
        *(u8 *)(spawnDef + 0x19) = (s8)extra->effectMode;
        *(s16 *)(spawnDef + 0x1a) = mapData->scale;
        *(f32 *)(spawnDef + 8) = *(f32 *)((u8 *)obj + 0xc);
        *(f32 *)(spawnDef + 0xc) = *(f32 *)((u8 *)obj + 0x10);
        *(f32 *)(spawnDef + 0x10) = *(f32 *)((u8 *)obj + 0x14);
        if (spawnDef != 0) {
            effectObj = firepipe_spawnEffectObject(extra,obj,(void *)spawnDef);
        } else {
            effectObj = 0;
        }
        if (effectObj != 0) {
            *(f32 *)(effectObj + 0xc) = *(f32 *)((u8 *)obj + 0xc);
            *(f32 *)(effectObj + 0x10) = *(f32 *)((u8 *)obj + 0x10);
            *(f32 *)(effectObj + 0x14) = *(f32 *)((u8 *)obj + 0x14);
            *(s16 *)(effectObj + 0) = *(s16 *)((u8 *)obj + 0);
            *(s16 *)(effectObj + 2) = *(s16 *)((u8 *)obj + 2);
            *(f32 *)(effectObj + 0x28) = lbl_803DC344;
        }
        storeZeroToFloatParam(&extra->emitTimer);
        s16toFloat(&extra->emitTimer, lbl_803DC350);
    }

    if (flags->bit6 != 0) {
        if (flags->bit5 == 0) {
            Sfx_PlayFromObjectLimited(obj,SFXand_missilelaunch,3);
        }
        Sfx_KeepAliveLoopedObjectSoundLimited(obj,SFXand_suck_lp,2);
    }
    flags->bit5 = flags->bit6;

update_light:
    if (extra->subObj != 0) {
        modelLightStruct_updateGlowAlpha(extra->subObj);
    }
}
#pragma scheduling reset
#pragma peephole reset

int firepipe_getExtraSize(void)
{
    return 0x44;
}

#pragma peephole off
#pragma scheduling off
#pragma peephole off
undefined4 firepipe_stateCallback(FirePipeObject *obj)
{
    firepipe_updateState(obj);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

int firepipe_getObjectTypeId(void)
{
    return 1;
}

#pragma peephole off
#pragma scheduling off
#pragma peephole off
void firepipe_free(FirePipeObject *obj)
{
    int i;
    undefined4 *iter;
    FirePipeExtra *extra;

    extra = obj->extra;
    ObjGroup_RemoveObject(obj, 0x4a);
    i = 0;
    iter = (undefined4 *)extra;
    while (i < (int)(uint)extra->effectCount) {
        Obj_FreeObject(*iter);
        iter = iter + 1;
        i++;
    }
    if ((uint)extra->subObj != 0) {
        modelLightStruct_freeSlot((int)&extra->subObj);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
#pragma peephole off
void firepipe_render(FirePipeObject *obj, int param_2, int param_3, int param_4, int param_5, char param_6)
{
    FirePipeExtra *extra;
    int subObj;

    extra = obj->extra;
    subObj = extra->subObj;
    if ((uint)subObj != 0 && *(byte *)(subObj + 0x2f8) != 0 && *(byte *)(subObj + 0x4c) != 0) {
        queueGlowRender();
    }
    if (param_6 != '\0' && (uint)((extra->flags >> 1) & 1) != 0) {
        objRenderFn_8003b8f4((int)obj, param_2, param_3, param_4, param_5, (double)lbl_803E6B78);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
#pragma peephole off
void firepipe_update(FirePipeObject *obj)
{
    obj->statusFlags = (u8)(obj->statusFlags | 8);
    firepipe_updateState(obj);
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

static inline f64 firepipe_u32AsDouble(u32 value)
{
    u64 bits = CONCAT44(0x43300000, value);
    return *(f64 *)&bits;
}

#pragma peephole off
#pragma scheduling off
void firepipe_init(FirePipeObject *obj, FirePipeMapData *mapData)
{
    FirePipeExtra *extra;
    FirePipeExtra *extra2;
    int iVar7;
    short sVar1;
    short sVar5;
    undefined4 uVar3;
    uint uVar4;

    extra = obj->extra;
    if ((int)mapData->scale != 0) {
        f32 scale = lbl_803E6BA8 * (f32)(s32)mapData->scale;
        obj->scale = scale * *(float *)(*(int *)((int)obj + 0x50) + 4);
    }
    if (mapData->gameBit != -1) {
        uVar3 = GameBit_Get((int)mapData->gameBit);
        ((FirePipeBitFlags *)&extra->flags)->bit6 = (u8)uVar3;
    }
    else {
        ((FirePipeBitFlags *)&extra->flags)->bit6 = 1;
    }
    obj->sequenceCallback = firepipe_stateCallback;
    {
        iVar7 = (int)obj->objectDef;
        extra2 = obj->extra;
        storeZeroToFloatParam(&extra2->cycleTimer);
        sVar5 = *(short *)(iVar7 + 0x1a);
        if (sVar5 != 0) {
            sVar1 = *(short *)(iVar7 + 0x20);
            if (sVar1 != 0) {
                if (sVar1 < 0) {
                    sVar5 = randomGetRange(1, sVar5 * 0x3c);
                    s16toFloat(&extra2->cycleTimer, (int)sVar5);
                }
                else {
                    s16toFloat(&extra2->cycleTimer, (int)(short)(sVar1 * 0x3c));
                    if (*(short *)(iVar7 + 0x20) >= *(short *)(iVar7 + 0x1a)) {
                        ((FirePipeBitFlags *)&extra2->flags)->bit6 = 0;
                    }
                }
            }
            else {
                s16toFloat(&extra2->cycleTimer, (int)(short)(sVar5 * 0x3c));
            }
        }
        extra->clearVolumeA = 0;
        extra->clearVolumeB = 0;
        sVar5 = obj->objectId;
        switch (sVar5) {
        case 0x6f9:
            extra->effectType = 10;
            extra->effectMode = 1;
            extra->effectScale = lbl_803DC340;
            break;
        case 0x731:
            extra->effectType = 0xd;
            extra->effectMode = 2;
            extra->effectScale = lbl_803E6B74;
            break;
        case 0x730:
            extra->effectType = 0xc;
            extra->effectMode = 2;
            extra->effectScale = lbl_803E6B74;
            break;
        case 0x732:
            extra->effectType = 0xe;
            extra->effectMode = 2;
            extra->effectScale = lbl_803E6B74;
            break;
        case 0x4a4:
        case 0x70a:
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
        obj->modeX = (short)((int)mapData->modeX << 8);
        obj->modeY = (ushort)mapData->modeY << 8;
        ObjHits_EnableObject(obj);
        ((FirePipeBitFlags *)&extra->flags)->bit4 = 0;
        extra->activeSpawn = 0;
        uVar3 = GameBit_Get((int)mapData->gameBit);
        {
            uint clz = __cntlzw(uVar3);
            ((FirePipeBitFlags *)&extra->flags)->bit7 = (u8)(clz >> 5);
        }
        if ((mapData->flags & 1) != 0) {
            uVar4 = 0;
        }
        else {
            uVar4 = 1;
        }
        ((FirePipeBitFlags *)&extra->flags)->bit1 = uVar4;
        if ((mapData->flags & 2) != 0) {
            uVar4 = 0;
        }
        else {
            uVar4 = 1;
        }
        ((FirePipeBitFlags *)&extra->flags)->bit0 = uVar4;
        storeZeroToFloatParam(&extra->emitTimer);
        s16toFloat(&extra->emitTimer, 0x14);
        ObjGroup_AddObject(obj, 0x4a);
        ((FirePipeBitFlags *)&extra->flags)->bit2 = 0;
        extra->subObj = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

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
