#include "ghidra_import.h"
#include "main/dll/firepipe.h"
#include "string.h"

extern undefined4 fn_8001CB3C(int param_1);
extern undefined4 GameBit_Get(int eventId);
extern undefined4 randomGetRange(int param_1, int param_2);
extern u8 Obj_IsLoadingLocked(void);
extern undefined4 Obj_FreeObject(int param_1);
extern int fn_8002B5A0(FirePipeObject *obj, void *spawnDef);
extern void fn_8002CE14(int obj);
extern void objRemoveFromListFn_8002ce88(FirePipeObject *obj);
extern int mmSetFreeDelay(int delay);
extern void mm_free(void *ptr);
extern undefined4 ObjHits_EnableObject(FirePipeObject *obj);
extern void ObjHits_DisableObject(FirePipeObject *obj);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 objRenderFn_8003b8f4(int param_1, int param_2, int param_3, int param_4, int param_5, double scale);
extern undefined4 queueGlowRender(void);
extern undefined4 storeZeroToFloatParam(int param_1);
extern undefined4 s16toFloat(int param_1, int param_2);

extern f32 lbl_803DC340;
extern f32 lbl_803E6B74;
extern f32 lbl_803E6B78;
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
    effectObj = fn_8002B5A0(obj, spawnDef);
    if (extra->effectCount != 8) {
        *(u16 *)(effectObj + 0xb0) |= 0x200;
        extra->effectObjs[extra->effectCount] = effectObj;
        extra->effectCount++;
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

int firepipe_func08(void)
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
        fn_8001CB3C((int)&extra->subObj);
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
    int iVar8;
    int iVar7;
    short sVar1;
    short sVar5;
    undefined4 uVar3;

    extra = obj->extra;
    if ((int)mapData->scale != 0) {
        obj->scale =
            lbl_803E6BA8 *
            (f32)(s32)mapData->scale * *(float *)(*(int *)((int)obj + 0x50) + 4);
    }
    if (mapData->gameBit != -1) {
        uVar3 = GameBit_Get((int)mapData->gameBit);
        ((FirePipeBitFlags *)&extra->flags)->bit6 = (u8)uVar3;
    }
    else {
        ((FirePipeBitFlags *)&extra->flags)->bit6 = 1;
    }
    obj->callback = firepipe_stateCallback;
    {
        iVar7 = (int)obj->objectDef;
        iVar8 = (int)obj->extra;
        storeZeroToFloatParam(iVar8 + 0x24);
        sVar5 = *(short *)(iVar7 + 0x1a);
        if (sVar5 != 0) {
            sVar1 = *(short *)(iVar7 + 0x20);
            if (sVar1 == 0) {
                s16toFloat(iVar8 + 0x24, (int)(short)(sVar5 * 0x3c));
            }
            else if (sVar1 < 0) {
                sVar5 = randomGetRange(1, sVar5 * 0x3c);
                s16toFloat(iVar8 + 0x24, (int)sVar5);
            }
            else {
                s16toFloat(iVar8 + 0x24, (int)(short)(sVar1 * 0x3c));
                if (*(short *)(iVar7 + 0x1a) <= *(short *)(iVar7 + 0x20)) {
                    ((FirePipeBitFlags *)(iVar8 + 0x41))->bit6 = 0;
                }
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
        case 0x730:
            extra->effectType = 0xc;
            extra->effectMode = 2;
            extra->effectScale = lbl_803E6B74;
            break;
        case 0x731:
            extra->effectType = 0xd;
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
            uint clz = countLeadingZeros(uVar3);
            ((FirePipeBitFlags *)&extra->flags)->bit7 = (u8)(clz >> 5);
        }
        ((FirePipeBitFlags *)&extra->flags)->bit1 = (mapData->flags & 1) == 0;
        ((FirePipeBitFlags *)&extra->flags)->bit0 = (mapData->flags & 2) == 0;
        storeZeroToFloatParam((int)&extra->cycleTimer);
        s16toFloat((int)&extra->cycleTimer, 0x14);
        ObjGroup_AddObject(obj, 0x4a);
        ((FirePipeBitFlags *)&extra->flags)->bit2 = 0;
        extra->subObj = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset
