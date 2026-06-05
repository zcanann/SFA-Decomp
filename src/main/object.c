#include "ghidra_import.h"
#include "main/model_light.h"
#include "main/engine_8001746C_phantoms.h"

extern undefined4 ObjHits_TickPriorityHitCooldowns();
extern undefined4 ObjHits_Update();
extern uint ObjHitbox_AllocRotatedBounds();
extern uint ObjHitReact_InitState();
extern uint ObjHits_AllocObjectState();
extern undefined8 ObjHitReact_UpdateResetObjects();
extern undefined4 ObjHits_ResetWorkBuffers();
extern undefined4 ObjHits_InitWorkBuffers();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjGroup_GetObjectGroup();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjGroup_ClearAll();
extern undefined4 ObjContact_RemoveObjectCallbacks();
extern void mm_free(void *ptr);

/*
 * --INFO--
 *
 * Function: gameTextFn_80017434
 * EN v1.0 Address: 0x80017434
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001746C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* moved below GameTextSlot/global declarations */

/*
 * --INFO--
 *
 * Function: FUN_80017460
 * EN v1.0 Address: 0x80017460
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800191FC
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 *
FUN_80017460(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017468
 * EN v1.0 Address: 0x80017468
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001947C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 *
FUN_80017468(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: textRenderStr
 * EN v1.0 Address: 0x800174D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001AE18
 * EN v1.1 Size: 1760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern f32 timeDelta;

#pragma push
#pragma scheduling off

#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

/*
 * --INFO--
 *
 * Function: FUN_80017500
 * EN v1.0 Address: 0x80017500
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001BD8C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80017500(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001786c
 * EN v1.0 Address: 0x8001786C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80024F40
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8001786c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017998
 * EN v1.0 Address: 0x80017998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80029260
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined *
FUN_80017998(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            )
{
    return 0;
}

/* Pattern wrappers. */
#pragma dont_inline on
#pragma dont_inline reset
void doNothing_afterRenderObject(void) {}
void doNothing_beforeRenderObject(void) {}
void fn_8002B85C(void) {}

/* ObjModel/model-file accessors. */
typedef struct ObjModelRenderOpLite {
    u8 pad00[0x43];
    s8 alpha;
} ObjModelRenderOpLite;

typedef struct ObjModelFileHeaderLite {
    u8 pad00[0x38];
    ObjModelRenderOpLite *renderOps;
    u8 pad3c[0xf3 - 0x3c];
    u8 jointCount;
    u8 extraJointCount;
    u8 padf5[0xf8 - 0xf5];
    u8 renderOpCount;
} ObjModelFileHeaderLite;

typedef struct ObjModelInstanceLite {
    ObjModelFileHeaderLite *file;
    u8 pad04[0x0c - 0x04];
    u8 *jointMatrices[2];
    u8 pad14[0x18 - 0x14];
    u16 bufferFlags;
} ObjModelInstanceLite;

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
void *ObjModel_GetRenderOp(u8 *model, int renderOpIndex);
#pragma dont_inline reset

u16 modelFileHeaderGetCullDistance(u8 *modelFile);

#pragma dont_inline on
void ObjModel_ClearRenderAttachment(u8 *model);
#pragma dont_inline reset

#pragma dont_inline on
void ObjModel_EnableDefaultRenderCallback(void *obj, u8 *model, f32 *mtx, int enabled, f32 scale);
#pragma dont_inline reset

void ObjModel_SetRenderCallback(u8 *model, void *callback);

void Obj_SetModelRenderOpAlpha(u8 *obj, int alpha) {
    int renderOpAlpha;
    int renderOpIndex;
    ObjModelFileHeaderLite *modelFile;
    ObjModelInstanceLite *model;

    renderOpAlpha = alpha;
    model = *(ObjModelInstanceLite **)(*(u8 **)(obj + 0x7c) + (s8)obj[0xad] * 4);
    if (model != NULL) {
        modelFile = model->file;
        if (modelFile != NULL) {
            for (renderOpIndex = 0; renderOpIndex < modelFile->renderOpCount; renderOpIndex++) {
                ((ObjModelRenderOpLite *)ObjModel_GetRenderOp((u8 *)modelFile, renderOpIndex))
                    ->alpha = renderOpAlpha;
            }
        }
    }
}

void Obj_SetModelSlotIndex(u8 *obj, int slotIndex) {
    *(s8 *)(obj + 0xac) = slotIndex;
}

void Obj_ClearModelSlotIndex(u8 *obj) {
    *(s8 *)(obj + 0xac) = -1;
}

void *Obj_GetActiveModel(u8 *obj) {
    return *(void **)(*(u8 **)(obj + 0x7c) + (s8)obj[0xad] * 4);
}

extern int *lbl_803DCAB4;
extern u8 framesThisStep;
extern f32 lbl_803DE88C;
extern f32 lbl_803DE89C;
extern f32 lbl_803DE8A0;
extern void Obj_BuildWorldTransformMatrix(u8 *obj, f32 *mtx, int flags);

void Obj_ClearModelColorFadeRecursive(u8 *obj) {
    int i;
    u8 *childScan;

    *(s16 *)(obj + 0xe6) = 0;
    obj[0xe5] &= ~0x6;
    i = 0;
    childScan = obj;
    while (i < obj[0xeb]) {
        Obj_ClearModelColorFadeRecursive(*(u8 **)(childScan + 0xc8));
        childScan += 4;
        i++;
    }
}

void Obj_TickModelColorFadeRecursive(u8 *obj) {
    f32 alpha;
    int i;
    u8 *childScan;

    if ((obj[0xe5] & 4) != 0) {
        alpha = (f32)obj[0xef] + lbl_803DE89C * timeDelta;
    } else {
        alpha = (f32)obj[0xef] - lbl_803DE89C * timeDelta;
    }

    if (alpha < lbl_803DE88C) {
        alpha = -alpha;
        obj[0xe5] ^= 4;
    } else if (alpha > lbl_803DE8A0) {
        alpha = lbl_803DE8A0 - (alpha - lbl_803DE8A0);
        obj[0xe5] ^= 4;
    }

    *(s8 *)(obj + 0xef) = (int)alpha;
    if ((obj[0xe5] & 8) == 0) {
        *(s16 *)(obj + 0xe6) -= framesThisStep;
        if (*(s16 *)(obj + 0xe6) <= 0 && *(void **)(obj + 0xc4) == NULL) {
            Obj_ClearModelColorFadeRecursive(obj);
        }
    }

    i = 0;
    childScan = obj;
    while (i < obj[0xeb]) {
        Obj_TickModelColorFadeRecursive(*(u8 **)(childScan + 0xc8));
        childScan += 4;
        i++;
    }
}

#pragma dont_inline on
void Obj_SetModelColorFadeRecursive(u8 *obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf) {
    int i;
    u8 *childScan;

    *(s16 *)(obj + 0xe6) = (s16)frames;
    obj[0xe5] &= ~4;
    obj[0xe5] |= 2;
    obj[0xec] = red;
    obj[0xed] = green;
    obj[0xee] = blue;
    if (frames == 10000) {
        obj[0xe5] |= 8;
    } else {
        obj[0xe5] &= ~8;
    }
    if (startAtHalf != 0) {
        obj[0xef] = 0x7f;
    } else {
        obj[0xef] = 0;
    }

    i = 0;
    childScan = obj;
    while (i < obj[0xeb]) {
        Obj_SetModelColorFadeRecursive(*(u8 **)(childScan + 0xc8), frames, red, green, blue, startAtHalf);
        childScan += 4;
        i++;
    }
}
#pragma dont_inline reset

void Obj_SetModelColorOverrideRecursive(u8 *obj, u8 red, u8 green, u8 blue, u8 alpha, u8 enabled) {
    int i;
    u8 *childScan;

    if (enabled != 0) {
        obj[0xe5] |= 0x10;
        obj[0xec] = red;
        obj[0xed] = green;
        obj[0xee] = blue;
        obj[0xef] = alpha;
    } else {
        obj[0xe5] &= ~0x10;
    }

    i = 0;
    childScan = obj;
    while (i < obj[0xeb]) {
        Obj_SetModelColorOverrideRecursive(*(u8 **)(childScan + 0xc8), red, green, blue, alpha, enabled);
        childScan += 4;
        i++;
    }
}

void Obj_ResetModelColorState(u8 *obj) {
    *(s16 *)(obj + 0xe6) = 0;
    obj[0xe5] &= ~1;
    obj[0xf0] = 0;
    ObjModel_ClearRenderAttachment((u8 *)Obj_GetActiveModel(obj));
    (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))((int)obj, 0x7fb, 0, 0x50, 0);
    (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))((int)obj, 0x7fc, 0, 0x32, 0);
}

#pragma peephole off
void Obj_StartModelFadeIn(u8 *obj, int frames) {
    f32 mtx[16];
    int fadeLimit;
    s16 objType;

    fadeLimit = 10;
    objType = *(s16 *)(obj + 0x44);
    if (objType == 0x1c || objType == 0x6d || objType == 0x2a) {
        fadeLimit = 40;
    }
    if ((*(u8 *)(*(u8 **)(obj + 0x50) + 0x76) & 1) != 0) {
        if (obj[0xf0] < fadeLimit) {
            obj[0xf0]++;
            Obj_SetModelColorFadeRecursive(obj, 0x1e, 0xa0, 0xff, 0xff, 0);
        }
        if (obj[0xf0] == fadeLimit) {
            if ((obj[0xe5] & 2) != 0) {
                Obj_ClearModelColorFadeRecursive(obj);
            }
            *(s16 *)(obj + 0xe6) = (s16)frames;
            obj[0xe5] = (u8)(obj[0xe5] | 1);
            Obj_BuildWorldTransformMatrix(obj, mtx, 0);
            ((void (*)(u8 *, u8 *, f32 *, int, f32))ObjModel_EnableDefaultRenderCallback)(
                obj, *(u8 **)(*(u8 **)(obj + 0x7c) + (s8)obj[0xad] * 4), mtx, 1,
                *(f32 *)(obj + 0xa8) * *(f32 *)(obj + 8));
            (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))((int)obj, 0x7fc, 0, 0x64, 0);
        }
    }
}
#pragma peephole reset

#pragma pop

/* Global game-state / text accessors. */

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole off

#pragma peephole reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

int objIsFrozen(u8 *obj) {
    return obj[0xe5] & 1;
}

int objGetFlagsE5_2(u8 *obj) {
    return obj[0xe5] & 2;
}

#pragma peephole off
int roundUpTo4(int x);

#pragma dont_inline on
int roundUpTo8(int x);

int roundUpTo32(int x);
#pragma dont_inline reset
#pragma peephole reset

/* Simple field/global accessors. */

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

extern void *mmAlloc(int size, int type, int flag);
extern void *memset(void *dst, int val, int n);
extern void PSMTXMultVec(f32 *mtx, f32 *in, f32 *out);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);
extern void Obj_TransformLocalPointByWorldMatrix(u8 *obj, f32 *src, f32 *dst, u8 flag);
extern void Obj_TransformLocalVectorByWorldMatrix(void *obj, f32 *src, f32 *dst);
extern void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern void textureFree(void *tex);

#pragma peephole off
#pragma scheduling off
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma dont_inline on
#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop
#pragma dont_inline reset

#pragma peephole off
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole on
#pragma peephole reset

#pragma dont_inline on

#pragma dont_inline reset

void objSetHintTextIdx(u8 *obj, u16 idx) {
    if (idx > 4) {
        idx = 0;
    }
    obj[0xe8] = (u8)idx;
}
#pragma pop

extern int getLoadedFileFlags(int);
extern s8 lbl_803DCB74;
extern int lbl_803408A8[];

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

int Obj_IsLoadingLocked(void) {
    return !(getLoadedFileFlags(0) & 0x100000);
}

void objSetSlot(u8 *obj, s8 slot) {
    if (slot == 0x5a) {
        if ((*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 0x40) == 0) {
            return;
        }
    }
    *(s8 *)(obj + 0xae) = slot;
}

#pragma peephole on
void fn_8002B758(void *v) {
    int i;
    int count;

    count = lbl_803DCB74;
    for (i = 0; i < count; i++) {
        if ((void *)lbl_803408A8[i] == v) {
            break;
        }
    }
    if (i == count) {
        return;
    }
    for (; i < count - 1; i++) {
        lbl_803408A8[i] = lbl_803408A8[i + 1];
    }
    lbl_803DCB74--;
}

void fn_8002B860(void *v) {
    s8 i = lbl_803DCB74;
    lbl_803DCB74 = i + 1;
    lbl_803408A8[i] = (int)v;
}
#pragma peephole reset
#pragma pop

extern void objList_remove(void *list, void *item);
extern int lbl_803DCBAC;
extern int *lbl_803DCBB0;
extern u8 *lbl_803DCBB4;
extern int lbl_803DCB7C;
extern f32 timeDelta;

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
void mm_free(void *p);
#pragma dont_inline reset

void *getTablesBinEntry(int i) {
    if (i < 0 || i >= lbl_803DCBAC) {
        return lbl_803DCBB4;
    }
    return lbl_803DCBB4 + lbl_803DCBB0[i] * 4;
}

void fn_8002CE14(u8 *obj) {
    if (*(u16 *)(obj + 0xb0) & 0x10) {
        int *list = &lbl_803DCB7C;
        int prev = 0;
        int cur = list[1];
        s16 linkOff = *(s16 *)((u8 *)list + 2);
        while (cur != 0 && (s8)obj[0xae] < (s8)((u8 *)cur)[0xae]) {
            prev = cur;
            cur = *(int *)((u8 *)cur + linkOff);
        }
        objListAdd(&lbl_803DCB7C, prev, (int)obj);
    }
}

void objRemoveFromListFn_8002ce88(u8 *obj) {
    if (*(u16 *)(obj + 0xb0) & 0x10) {
        objList_remove(&lbl_803DCB7C, obj);
    }
}

void *Obj_GetPlayerObject(void) {
    int count;
    void **objs = ObjGroup_GetObjects(0, &count);
    if (count != 0) {
        return objs[0];
    }
    return NULL;
}

#pragma peephole off
#pragma peephole reset
#pragma pop

extern f32 sqrtf(f32 x);
extern int lbl_803DCB84;
extern void *lbl_803DCB88;

extern void fileLoadToBufferOffset(int id, void *buf, int offset, int size);
extern void *Resource_Acquire(u32 id, u32 arg);
extern void *loadCharacter(s16 *data, int flags, int arg2, int arg3, void *parent, int unused);

#pragma push
#pragma scheduling off
#pragma peephole off

void *ObjList_GetObjects(int *outA, int *outB) {
    if (outA != NULL) {
        *outA = 0;
    }
    if (outB != NULL) {
        *outB = lbl_803DCB84;
    }
    return lbl_803DCB88;
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
void *loadAssetFileById(int id, int arg);

#pragma dont_inline reset

void Obj_SetActiveModelIndex(u8 *obj, int idx) {
    if (idx == (s8)obj[0xad]) {
        return;
    }
    if (idx < 0) {
        idx = 0;
    } else {
        int max = *(s8 *)(*(u8 **)(obj + 0x50) + 0x55);
        if (idx >= max) {
            idx = max - 1;
        }
    }
    *(s8 *)(obj + 0xad) = idx;
}
#pragma pop

typedef struct ObjListObjectDef {
    u8 pad00[0x14];
    u32 objectId;
} ObjListObjectDef;

typedef struct ObjListObject {
    u8 pad00[0x4c];
    ObjListObjectDef *def;
} ObjListObject;

#pragma push
#pragma scheduling off
#pragma peephole off

void *getTrickyObject(void) {
    int count;
    void **objs = ObjGroup_GetObjects(1, &count);
    if (count != 0) {
        return objs[0];
    }
    return NULL;
}

ObjListObject *ObjList_FindObjectById(u32 objectId) {
    int i;
    int count = lbl_803DCB84;
    ObjListObject **arr = lbl_803DCB88;
    for (i = 0; i < count; i++) {
        ObjListObject *obj = arr[i];
        ObjListObjectDef *def = obj->def;
        if (def != NULL && def->objectId == objectId) {
            return obj;
        }
    }
    return NULL;
}

#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline on
void *getTabEntry(int id, int arg, int e, int d);
#pragma dont_inline reset

#pragma pop

typedef f32 Mtx[3][4];
extern void Obj_BuildWorldTransformMatrix(u8 *obj, f32 *mtx, int flags);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma dont_inline on
void Obj_TransformLocalVectorByWorldMatrix(void *obj, f32 *src, f32 *dst) {
    f32 mtx[16];
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    PSMTXMultVecSR(mtx, src, dst);
}
#pragma dont_inline reset

extern void PSMTXMultVec(f32 *mtx, f32 *in, f32 *out);
extern f32 lbl_803DE890;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

#pragma dont_inline on
void Obj_TransformLocalPointByWorldMatrix(u8 *obj, f32 *src, f32 *dst, u8 flag) {
    f32 savedZ;
    f32 mtx[16];
    if (flag) {
        savedZ = *(f32 *)(obj + 8);
        *(f32 *)(obj + 8) = lbl_803DE890;
    }
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    PSMTXMultVec(mtx, src, dst);
    if (flag) {
        *(f32 *)(obj + 8) = savedZ;
    }
    dst[0] += playerMapOffsetX;
    dst[2] += playerMapOffsetZ;
}
#pragma dont_inline reset

extern void mtxRotateByVec3s(f32 *mtx, void *transform);
extern void mtx44Transpose(f32 *src, f32 *dst);

void objWorldToLocalPos(f32 *out, u8 *transform, f32 *in) {
    f32 rotated[3];
    struct {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        s16 pad;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } inverse;
    f32 rotMtx[16];
    f32 transposed[16];

    inverse.x = -*(f32 *)(transform + 0xc);
    inverse.y = -*(f32 *)(transform + 0x10);
    inverse.z = -*(f32 *)(transform + 0x14);
    inverse.rotX = -*(s16 *)(transform + 0);
    inverse.rotY = -*(s16 *)(transform + 2);
    inverse.rotZ = -*(s16 *)(transform + 4);
    inverse.scale = lbl_803DE890;
    mtxRotateByVec3s(rotMtx, &inverse);
    mtx44Transpose(rotMtx, transposed);
    PSMTXMultVec(transposed, in, rotated);
    *(u32 *)(out + 0) = *(u32 *)(rotated + 0);
    *(u32 *)(out + 1) = *(u32 *)(rotated + 1);
    *(u32 *)(out + 2) = *(u32 *)(rotated + 2);
}

extern void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *ab);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern void fileLoadToBufferOffset(int id, void *buf, int offset, int size);

#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma peephole reset

extern void *mmAlloc(int size, int type, int flag);
extern void *memset(void *dst, int val, int n);

void *Obj_AllocObjectSetup(int size, int b) {
    u8 *p = mmAlloc(size, 0xe, 0);
    memset(p, 0, size);
    *(int *)(p + 0x14) = -1;
    p[6] = 0x64;
    p[7] = 0x96;
    p[4] = 8;
    p[5] = 4;
    *(s16 *)p = b;
    p[2] = size;
    return p;
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

void ObjModel_LoadRenderOpTextures(u8 *model, int arg);

#pragma dont_inline on
#pragma dont_inline reset

extern void OSReport(char *fmt, ...);

#pragma peephole on
#pragma peephole reset

#pragma pop

extern void *memcpy(void *dst, const void *src, int n);

#pragma push
#pragma scheduling off
#pragma peephole off
int objMove(u8 *obj, f32 dx, f32 dy, f32 dz) {
    int n;
    *(f32 *)(obj + 0xc) += dx;
    *(f32 *)(obj + 0x10) += dy;
    *(f32 *)(obj + 0x14) += dz;
    ObjGroup_GetObjects(0, &n);
    return 0;
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

extern void *memset(void *dst, int val, int n);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void mtx44Transpose(f32 *src, f32 *dst);
#pragma dont_inline reset

extern void PSMTXConcat(f32 *a, f32 *b, f32 *ab);

#pragma dont_inline on
void setMatrixFromObjectTransposed(void *obj, f32 *out);
#pragma dont_inline reset

void objFn_8002b67c(u8 *obj) {
    u8 *dst;
    u8 *src;
    int idx;

    if (obj == NULL) {
        return;
    }
    dst = *(u8 **)(obj + 0x78);
    if (dst == NULL) {
        return;
    }
    src = *(u8 **)(*(u8 **)(obj + 0x50) + 0x40);
    idx = obj[0xe4];
    src += idx * 0x18;
    dst += idx * 5;
    dst[0] = src[0xc];
    dst[1] = src[0xd];
    dst[2] = src[0xe];
    dst[3] = src[0xf];
    dst[4] = src[0x10];
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma pop

extern void textureFree(void *tex);
extern f32 lbl_803DE8B8;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma dont_inline on

#pragma dont_inline reset

int objApplyVelocity(u8 *obj) {
    *(f32 *)(obj + 0xc) += timeDelta * (lbl_803DE8B8 * (*(f32 *)(obj + 0xfc) + *(f32 *)(obj + 0x24)));
    *(f32 *)(obj + 0x10) += timeDelta * (lbl_803DE8B8 * (*(f32 *)(obj + 0x100) + *(f32 *)(obj + 0x28)));
    *(f32 *)(obj + 0x14) += timeDelta * (lbl_803DE8B8 * (*(f32 *)(obj + 0x104) + *(f32 *)(obj + 0x2c)));
    return 1;
}

void Obj_ApplyPendingParentLinks(void) {
    int i;
    for (i = 0; i < lbl_803DCB84; i++) {
        u8 *obj = ((u8 **)lbl_803DCB88)[i];
        obj[0xaf] &= ~7;
        {
            u8 *parent = *(u8 **)(obj + 0xc0);
            if (parent != NULL && *(void **)(obj + 0x30) == NULL &&
                *(void **)(parent + 0x30) != NULL) {
                *(void **)(obj + 0x30) = *(void **)(parent + 0x30);
                *(void **)(obj + 0xc0) = NULL;
            }
        }
    }
}
#pragma pop

extern void objFreeObjDef(void *def, int flags);
extern int lbl_803DCB94;
extern void **lbl_803DCB98;

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

extern void OSReport(char *fmt, ...);

#pragma dont_inline on
#pragma dont_inline reset

void Obj_FlushDeferredFreeList(void) {
    int i;
    for (i = 0; i < lbl_803DCB94; i++) {
        void *p = lbl_803DCB98[i];
        if (p != NULL) {
            objFreeObjDef(p, 0);
            lbl_803DCB98[i] = NULL;
        }
    }
    lbl_803DCB94 = 0;
}

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void fn_8002B6D8(u8 *obj, int a, int b, int c, u8 d, u8 e) {
    u8 *p;
    if (obj == NULL) {
        return;
    }
    p = *(u8 **)(obj + 0x78);
    if (p == NULL) {
        return;
    }
    p += obj[0xe4] * 5;
    if (a != 0) {
        p[0] = a >> 2;
    }
    if (c != 0) {
        p[1] = c >> 2;
    }
    if (b != 0) {
        p[2] = b >> 2;
    }
    if (d != 0) {
        p[3] = d;
    }
    if (e != 0) {
        p[4] = e;
    }
}

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma scheduling off
#pragma peephole off
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma peephole off
void ObjModel_AdvanceBlendChannels(u8 *model, f32 dt);
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
void *ObjModel_LoadAnimData(u8 *p, int b, int c);
#pragma pop

void *ObjModel_Load(int id, int arg2, int *outSize);

extern void OSReport(char *fmt, ...);
extern void *loadCharacter(s16 *data, int flags, int arg2, int arg3, void *parent, int unused);
extern void Obj_RegisterObject(u8 *obj, int b);
extern char sObjSetupObjectLoadingLockedWarning[];
extern char lbl_802CAC54[];

#pragma peephole off
#pragma scheduling off
void *Obj_SetupObject(int a, int b, int c, int d, int e) {
    void *obj;
    if (getLoadedFileFlags(0) & 0x100000) {
        OSReport(sObjSetupObjectLoadingLockedWarning, d);
        return NULL;
    }
    obj = loadCharacter((s16 *)a, b, c, d, (void *)e, 0);
    if (obj != NULL) {
        Obj_RegisterObject(obj, b);
        OSReport(lbl_802CAC54, *(int *)((u8 *)obj + 0x50) + 0x91);
    }
    return obj;
}
#pragma scheduling reset

#pragma scheduling off
void *loadObjectAtObject(u8 *src, int arg1) {
    int type = *(s8 *)(src + 0xac);
    int objF30 = *(int *)(src + 0x30);
    void *obj;
    if (getLoadedFileFlags(0) & 0x100000) {
        OSReport(sObjSetupObjectLoadingLockedWarning, -1);
        obj = NULL;
    } else {
        obj = loadCharacter((s16 *)arg1, 5, type, -1, (void *)objF30, 0);
        if (obj != NULL) {
            Obj_RegisterObject(obj, 5);
            OSReport(lbl_802CAC54, *(int *)((u8 *)obj + 0x50) + 0x91);
        }
    }
    return obj;
}
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjModel_Release(u8 *model);
#pragma pop

extern void *memset(void *dst, int val, int n);

#pragma push
#pragma scheduling off
#pragma peephole off

extern void objLoadPlayerFromSave(u8 *obj);
extern f32 lbl_803DE88C;

void Obj_RunInitCallback(u8 *obj, int cb, int unused) {
    s16 mode = *(s16 *)(obj + 0x46);
    if (mode == 0x1f || mode == 0) {
        objLoadPlayerFromSave(obj);
    } else {
        int *p = *(int **)(obj + 0x68);
        if (p != NULL) {
            int fn = ((int *)*p)[1];
            if (fn != -1 && (void *)fn != NULL) {
                ((void (*)(u8 *))fn)(obj);
            }
        }
    }
    {
        int *q = *(int **)(obj + 0x64);
        if (q != NULL) {
            q[0xc] |= 8;
        }
    }
    {
        f32 v;
        *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
        *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x14);
        v = lbl_803DE88C;
        *(f32 *)(obj + 0xfc) = v;
        *(f32 *)(obj + 0x100) = v;
        *(f32 *)(obj + 0x104) = v;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void objGetWeaponDa(u8 *obj, int dummy, int *out, int key, u8 load) {
    int i;
    s16 *tbl;
    s16 da2;

    tbl = (s16 *)*(int *)(*(u8 **)(obj + 0x50) + 0x28);
    *out = 0;
    if (tbl == NULL) {
        return;
    }
    i = 0;
    while (tbl[i] != -1) {
        if (tbl[i] == key) {
            da2 = tbl[i + 1];
            *out = tbl[i + 2];
            if (*out > 0x800) {
                *out = 0x800;
            }
            if (load) {
                getTabEntry(out[1], 0x34, da2, *out);
            } else {
                fileLoadToBufferOffset(0x34, (void *)out[1], da2, *out);
            }
            return;
        }
        i += 3;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjAnim_LoadMoveEvents(u8 *obj, int dummy, int *out, int key, u8 load) {
    int i;
    s16 *tbl;
    s16 da2;

    tbl = (s16 *)*(int *)(*(u8 **)(obj + 0x50) + 0x20);
    *out = 0;
    if (tbl == NULL) {
        return;
    }
    i = 0;
    while (tbl[i] != -1) {
        if (tbl[i] == key) {
            da2 = tbl[i + 1];
            *out = tbl[i + 2];
            if (*out > 0x50) {
                *out = 0x50;
            }
            if (load == 0) {
                getTabEntry(out[1], 0x40, da2, *out);
            } else {
                fileLoadToBufferOffset(0x40, (void *)out[1], da2, *out);
            }
            return;
        }
        i += 3;
    }
}
#pragma pop

typedef struct ObjPathTransform {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u8 pad06[2];
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjPathTransform;

extern void mtxRotateByVec3s(f32 *mtx, void *transform);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out) {
    ObjPathTransform transform;
    f32 rotMtx[16];

    if (*(void **)(obj + 0x30) == NULL) {
        *(f32 *)(obj + 0xc) -= playerMapOffsetX;
        *(f32 *)(obj + 0x14) -= playerMapOffsetZ;
    }
    transform.x = -*(f32 *)(obj + 0xc);
    transform.y = -*(f32 *)(obj + 0x10);
    transform.z = -*(f32 *)(obj + 0x14);
    transform.rotX = -*(s16 *)(obj + 0x0);
    transform.rotY = -*(s16 *)(obj + 0x2);
    transform.rotZ = -*(s16 *)(obj + 0x4);
    transform.scale = lbl_803DE890;
    mtxRotateByVec3s(rotMtx, &transform);
    mtx44Transpose(rotMtx, out);
    if (*(void **)(obj + 0x30) == NULL) {
        *(f32 *)(obj + 0xc) += playerMapOffsetX;
        *(f32 *)(obj + 0x14) += playerMapOffsetZ;
    }
}
#pragma pop

extern s16 lbl_803DCBC4;

#pragma push
#pragma scheduling off
#pragma peephole off
void ObjList_PartitionForRender(int *out) {
    void **arr;
    void *tmp;
    int stop;
    int i;
    int j;
    int hi;

    *out = lbl_803DCB84;
    if (lbl_803DCBC4 != 0) {
        return;
    }
    i = 0;
    j = lbl_803DCB84 - 1;
    hi = j;
    while (i <= j) {
        arr = (void **)lbl_803DCB88;
        stop = 0;
        while (i <= hi && stop == 0) {
            if (*(int *)(*(u8 **)((u8 *)arr[i] + 0x50) + 0x44) & 1) {
                i++;
            } else {
                stop = -1;
            }
        }
        stop = 0;
        while (j >= 0 && stop == 0) {
            if (*(int *)(*(u8 **)((u8 *)arr[j] + 0x50) + 0x44) & 1) {
                stop = -1;
            } else {
                j--;
            }
        }
        if (i < j) {
            tmp = arr[i];
            arr[i] = arr[j];
            ((void **)lbl_803DCB88)[j] = tmp;
            i++;
            j--;
        }
    }
    lbl_803DCBC4 = i;
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_BuildWorldTransformMatrix(u8 *obj, f32 *mtx, int flags) {
    f32 savedZ;
    f32 parentMtx[16];
    void *parent;

    if (*(void **)(obj + 0x30) == NULL) {
        *(f32 *)(obj + 0xc) -= playerMapOffsetX;
        *(f32 *)(obj + 0x14) -= playerMapOffsetZ;
    }
    if ((u8)flags != 0) {
        savedZ = *(f32 *)(obj + 0x8);
        if ((*(u16 *)(obj + 0xb0) & 0x8) == 0) {
            *(f32 *)(obj + 0x8) = lbl_803DE890;
        }
    }
    setMatrixFromObjectTransposed(obj, mtx);
    if ((u8)flags != 0) {
        *(f32 *)(obj + 0x8) = savedZ;
    }
    parent = *(void **)(obj + 0x30);
    if (parent == NULL) {
        *(f32 *)(obj + 0xc) += playerMapOffsetX;
        *(f32 *)(obj + 0x14) += playerMapOffsetZ;
    } else {
        Obj_BuildWorldTransformMatrix(parent, (f32 *)parentMtx, 1);
        PSMTXConcat((f32 *)parentMtx, mtx, mtx);
    }
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma fp_contract off
void mtxRotateByVec3s(f32 *mtx, void *transform);
#pragma pop

extern int lbl_803DCB9C;
extern s16 *lbl_803DCBA0;
extern char sObjUnknownTypeUsingDummyObjectWarning[];
extern f32 lbl_803DE8CC;
extern f32 lbl_803DE8D0;
extern u8 *loadObjectFile(int id);
extern int objGetTotalDataSize(void *tmpl, u8 *def, s16 *data, int flags);
extern void modelInitBones(f32 scale, void *model);
extern int shadowInit(void *obj, int cursor, int arg);
extern void debugPrintf(char *fmt, ...);
extern int objCallback_80074d04();
extern int modelCb_80073d04();
extern int modelCb_80074518();

typedef struct LoadedObj {
    u8 pad00[0x06];
    s16 flags06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0x18];
    void *parent;
    u8 pad34[0x2];
    u8 f36;
    u8 pad37[0x5];
    f32 f3c;
    f32 f40;
    s16 f44;
    s16 seqId;
    s16 typeId;
    u8 pad4a[0x2];
    s16 *data;
    u8 *def;
    void *f54;
    u8 pad58[0x4];
    int f5c;
    int f60;
    u8 pad64[0x4];
    int **dll;
    int f6c;
    int f70;
    int f74;
    int f78;
    u8 **models;
    u8 pad80[0x22];
    s16 fa2;
    u8 pada4[0x4];
    f32 cullDist;
    s8 fac;
    u8 padad[0x3];
    u16 fb0;
    s16 fb2;
    s16 fb4;
    u8 padb6[0x2];
    int fb8;
    u8 padbc[0x20];
    int fdc;
    u8 pade0[0x11];
    u8 ff1;
    s8 ff2;
    u8 padf3[0x15];
    int f108;
} LoadedObj;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *loadCharacter(s16 *data, int flags, int arg2, int arg3, void *parent, int unused) {
    int size;
    int offsets[20];
    void *models[20];
    LoadedObj tmpl;
    LoadedObj *tp;
    s16 seq;
    int id;
    u8 *def;
    int fnFlags;
    int (*fp)(void *);
    int (*fp2)(void *, int);
    int flags29;
    int total;
    int i;
    int count;
    int idx;
    LoadedObj *obj;
    int base;
    int cursor;
    u8 n;
    u16 h;
    u8 cb;
    f32 max;
    int m;
    u32 v;
    s16 seq2;
    int sz;
    int tmp;
    int j;
    int k;

    seq = *data;
    if (flags & 2) {
        id = seq;
    } else {
        if (seq > lbl_803DCB9C) {
            return NULL;
        }
        id = lbl_803DCBA0[seq];
    }
    memset(&tmpl, 0, 0x10c);
    tp = &tmpl;
    def = loadObjectFile(id);
    tmpl.def = def;
    if (def == NULL || (int)def == -1) {
        debugPrintf(sObjUnknownTypeUsingDummyObjectWarning, id, *data, tmpl.seqId);
        return NULL;
    }
    tmpl.f44 = *(s16 *)(def + 0x52);
    tmpl.scale = *(f32 *)(def + 4);
    tmpl.flags06 = 2;
    if (*(u32 *)(def + 0x44) & 0x80) {
        tmpl.flags06 = tmpl.flags06 | 0x80;
    }
    if (*(u32 *)(def + 0x44) & 0x40000) {
        tmpl.fb0 = tmpl.fb0 | 0x80;
    }
    if (flags & 4) {
        tmpl.flags06 = tmpl.flags06 | 0x2000;
    }
    tmpl.x = *(f32 *)(data + 4);
    tmpl.y = *(f32 *)(data + 6);
    tmpl.z = *(f32 *)(data + 8);
    tmpl.typeId = (s16)id;
    tmpl.data = data;
    tmpl.seqId = seq;
    tmpl.fb2 = (s16)arg3;
    tmpl.fac = (s8)arg2;
    tmpl.fa2 = -1;
    tmpl.fb4 = -1;
    tmpl.f36 = 0xff;
    tmpl.fdc = 0;
    tmpl.ff1 = 0xff;
    tmpl.f3c = (f32)(int)(((u8 *)data)[6] << 3);
    tmpl.f40 = (f32)(int)(((u8 *)data)[7] << 3);
    n = (((u8 *)data)[5] & 0x18) >> 3;
    tmpl.ff2 = n;
    if (n == 0) {
        tmpl.ff2 = *(s8 *)(tmpl.def + 0x8e);
    } else {
        tmpl.ff2 = n - 1;
    }
    tmpl.dll = NULL;
    if ((int)*(s16 *)(def + 0x50) != -1) {
        tmpl.dll = Resource_Acquire(*(s16 *)(def + 0x50) & 0xffff, 6);
    }
    switch (tmpl.seqId) {
    case 0:
    case 0x1f:
        fnFlags = 0x1cb;
        break;
    default:
        if (tmpl.dll != NULL && (int)(fp = (int (*)(void *))*(int *)(*(int *)tmpl.dll + 0x18)) != -1 && fp != NULL) {
            fnFlags = fp(tp);
        } else {
            fnFlags = 0;
        }
        break;
    }
    if (*(u32 *)(def + 0x44) & 0x20) {
        flags29 = fnFlags & ~1;
    } else {
        flags29 = fnFlags | 1;
    }
    if (*(s16 *)(def + 0x48) != 0) {
        flags29 |= 2;
    } else {
        flags29 &= ~2;
    }
    if (*(s16 *)(def + 0x48) == 3) {
        flags29 |= 0x8000;
    }
    if (*(u32 *)(def + 0x44) & 1) {
        flags29 |= 0x200;
    }
    total = 0;
    i = 0;
    count = *(s8 *)(def + 0x55);
    if (flags29 & 0x400) {
        idx = (flags29 >> 0xb) & 0xf;
        if (idx < count) {
            models[idx] = ObjModel_Load(-(*(int **)(def + 8))[idx], flags29, &size);
            offsets[idx] = 0;
            total = size;
        }
    } else if (!(flags29 & 0x200)) {
        for (; i < count; i++) {
            models[i] = ObjModel_Load(-(*(int **)(def + 8))[i], flags29, &size);
            offsets[i] = total;
            total += size;
        }
    }
    base = objGetTotalDataSize(tp, def, data, flags29);
    obj = mmAlloc(base + total, 0xe, 0);
    memcpy(obj, &tmpl, 0x10c);
    memset((u8 *)obj + 0x10c, 0, base + total - 0x10c);
    obj->models = (u8 **)(obj + 1);
    *(u32 *)(obj->def + 0x44) |= 0x800000;
    i = 0;
    obj->f108 = 0;
    if (flags29 & 0x400) {
        idx = (flags29 >> 0xb) & 0xf;
        if (idx < count) {
            obj->models[idx] = (u8 *)obj + base + offsets[idx];
            ObjModel_LoadAnimData(models[idx], flags29, (int)obj->models[idx]);
            if (!(*(u16 *)(*(u8 **)obj->models[idx] + 2) & 0x8000)) {
                *(u32 *)(obj->def + 0x44) &= 0xff7fffff;
            }
            ObjModel_LoadRenderOpTextures(obj->models[idx], (int)obj);
            modelInitBones(obj->scale, obj->models[idx]);
            if (*(u32 *)(obj->def + 0x44) & 0x800) {
                ObjModel_SetRenderCallback(obj->models[idx], objCallback_80074d04);
            } else {
                cb = *(u8 *)(obj->def + 0x5f);
                if (cb & 1) {
                    ObjModel_SetRenderCallback(obj->models[idx], modelCb_80073d04);
                } else if (cb & 0x80) {
                    ObjModel_SetRenderCallback(obj->models[idx], modelCb_80074518);
                }
            }
        }
    } else if (!(flags29 & 0x200)) {
        for (; i < count; i++) {
            obj->models[i] = (u8 *)obj + base + offsets[i];
            ObjModel_LoadAnimData(models[i], flags29, (int)obj->models[i]);
            h = *(u16 *)(*(u8 **)obj->models[i] + 2);
            if (!(h & 0x8000) && !(h & 0x4000)) {
                *(u32 *)(obj->def + 0x44) &= 0xff7fffff;
            }
            ObjModel_LoadRenderOpTextures(obj->models[i], (int)obj);
            modelInitBones(obj->scale, obj->models[i]);
            if (*(u32 *)(obj->def + 0x44) & 0x800) {
                ObjModel_SetRenderCallback(obj->models[i], objCallback_80074d04);
            } else {
                cb = *(u8 *)(obj->def + 0x5f);
                if (cb & 1) {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80073d04);
                } else if (cb & 0x80) {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80074518);
                }
            }
        }
    }
    cursor = roundUpTo4((int)obj->models + *(s8 *)(def + 0x55) * 4);
    switch (obj->seqId) {
    case 0:
    case 0x1f:
        sz = 0x8e0;
        break;
    default:
        if (obj->dll != NULL && (fp2 = (int (*)(void *, int))*(int *)(*(int *)obj->dll + 0x1c)) != NULL) {
            sz = fp2(obj, cursor);
        } else {
            sz = 0;
        }
        break;
    }
    if (sz != 0) {
        obj->fb8 = cursor;
        cursor += sz;
    } else {
        obj->fb8 = 0;
    }
    if ((flags29 & 0x40) || (*(u32 *)(obj->def + 0x44) & 0x400000)) {
        seq2 = obj->seqId;
        tmp = roundUpTo4(cursor);
        obj->f60 = tmp;
        cursor = roundUpTo8(tmp + 8);
        *(int *)(obj->f60 + 4) = cursor;
        ObjAnim_LoadMoveEvents((u8 *)obj, seq2, (int *)obj->f60, 0, 1);
        cursor += 0x50;
    }
    if ((flags29 & 0x100) && *(void **)obj->models != NULL) {
        tmp = roundUpTo4(cursor);
        obj->f5c = tmp;
        cursor = roundUpTo8(tmp + 8);
        *(int *)(obj->f5c + 4) = cursor;
        cursor += 0x800;
    }
    if ((flags29 & 2) && *(s16 *)(def + 0x48) != 0) {
        cursor = shadowInit(obj, cursor, 0);
    }
    max = lbl_803DE8CC;
    i = 0;
    for (; i < *(s8 *)(obj->def + 0x55); i++) {
        m = *(int *)((u8 *)obj->models + i * 4);
        if (m != 0) {
            if ((f32)modelFileHeaderGetCullDistance(*(u8 **)m) > max) {
                max = (f32)modelFileHeaderGetCullDistance(*(u8 **)m);
            }
        }
    }
    v = *(u8 *)(obj->def + 0x73);
    if (v != 0) {
        max = max * ((lbl_803DE8CC * (f32)v) / lbl_803DE8D0);
    }
    obj->cullDist = max;
    if (*(u8 *)(def + 0x61) != 0) {
        cursor = ObjHits_AllocObjectState(obj, cursor);
        if (*(s8 *)(def + 0x65) & 8) {
            cursor = ObjHitbox_AllocRotatedBounds(obj, cursor);
        }
    }
    if (*(u8 *)(def + 0x5a) != 0) {
        tmp = roundUpTo4(cursor);
        obj->f6c = tmp;
        cursor = tmp + *(u8 *)(def + 0x5a) * 0x12;
    }
    if (*(u8 *)(def + 0x59) != 0) {
        tmp = roundUpTo4(cursor);
        obj->f70 = tmp;
        cursor = tmp + *(u8 *)(def + 0x59) * 0x10;
    }
    if (*(u8 *)(def + 0x72) != 0) {
        tmp = roundUpTo4(cursor);
        obj->f74 = tmp;
        cursor = tmp + *(u8 *)(def + 0x72) * 0x18;
    }
    if (*(u8 *)(def + 0x61) != 0 && *(u8 *)(def + 0x66) != 0) {
        tmp = roundUpTo4(cursor);
        cursor = ObjHitReact_InitState(obj->seqId, (int)*(u8 **)obj->models, obj->f54, tmp, obj);
    }
    if (*(u8 *)(def + 0x72) != 0) {
        obj->f78 = roundUpTo4(cursor);
        i = 0;
        k = 0;
        j = 0;
        for (; i < *(u8 *)(def + 0x72); i++) {
            ((u8 *)obj->f78)[j + 4] = ((u8 *)*(int *)(def + 0x40))[k + 0x10];
            ((u8 *)obj->f78)[j] = ((u8 *)*(int *)(def + 0x40))[k + 0xc];
            ((u8 *)obj->f78)[j + 3] = ((u8 *)*(int *)(def + 0x40))[k + 0xf];
            ((u8 *)obj->f78)[j + 1] = ((u8 *)*(int *)(def + 0x40))[k + 0xd];
            ((u8 *)obj->f78)[j + 2] = ((u8 *)*(int *)(def + 0x40))[k + 0xe];
            k += 0x18;
            j += 5;
        }
    }
    obj->parent = parent;
    return obj;
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

extern void Obj_InitObjectSystem(void);
extern int getDataFileSize(int id);
extern void *gCameraInterface;
extern void *gObjectTriggerInterface;
extern void *gTitleMenuControlInterface;
extern void *gExpgfxInterface;
extern void *gModgfxInterface;
extern void *gWaterfxInterface;
extern int *gMapEventInterface;

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

extern void fn_802B4DE0(u8 *obj, int flag);
extern void Resource_Release(void *res);
extern void Obj_FreeObject(u8 *obj);
extern void fn_80059A50(int arg);
extern void setShadowFlag_803db658(int v);
extern void *textureFn_8006c5c4(void);
extern u8 *lbl_803DCBA4;
extern u8 *lbl_803DCBA8;
extern char sObjFreeObjdefError[];

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void objFreeObjDef(void *objp, int flag) {
    u8 *obj = (u8 *)objp;
    int defs[46];
    void (*fp)(u8 *, int);
    void (*cb)(u8 *);
    void (*cb2)(u8 *, int, int, int, int);
    void (*cb3)(void);
    int i;
    int count;
    int n;
    u8 *o;
    int *bp;
    void *curTex;
    u8 *tex;
    int t2;
    s8 modelCount;
    int group;
    int type;

    if (*(s8 *)(obj + 0xe9) != 0) {
        ObjContact_RemoveObjectCallbacks(obj);
    }
    switch (*(s16 *)(obj + 0x46)) {
    case 0:
    case 0x1f:
        fn_802B4DE0(obj, flag);
        break;
    default:
        if (*(int **)(obj + 0x68) != NULL) {
            fp = (void (*)(u8 *, int))*(int *)(*(int *)(obj + 0x68) + 0x14);
            if (fp != NULL) {
                fp(obj, flag);
            }
            Resource_Release(*(void **)(obj + 0x68));
            *(int *)(obj + 0x68) = 0;
        }
        break;
    }
    (*(void (**)(u8 *))(*(int *)gTitleMenuControlInterface + 0x48))(obj);
    (*(void (**)(u8 *))(*(int *)gExpgfxInterface + 0x28))(obj);
    if (*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 0x40) {
        ObjGroup_RemoveObject(obj, 6);
        if (flag == 0) {
            count = 0;
            for (i = 0; i < lbl_803DCB84; i++) {
                o = ((u8 **)lbl_803DCB88)[i];
                if (*(u8 **)(o + 0x30) == obj) {
                    *(int *)(o + 0x30) = 0;
                    if (*(int *)(o + 0x4c) != 0) {
                        defs[count] = (int)o;
                        count++;
                    }
                }
            }
            for (i = 0; i < count; i++) {
                Obj_FreeObject((void *)defs[i]);
            }
            fn_80059A50(*(u8 *)(obj + 0x34));
        }
    }
    if (flag == 0 && *(s16 *)(obj + 0x44) == 0x10) {
        for (i = 0; i < lbl_803DCB84; i++) {
            if (*(u8 **)(((u8 **)lbl_803DCB88)[i] + 0xc0) == obj) {
                *(int *)(((u8 **)lbl_803DCB88)[i] + 0xc0) = 0;
            }
        }
    }
    for (i = 0; i < lbl_803DCB84; i++) {
        if (*(s16 *)(((u8 **)lbl_803DCB88)[i] + 0x44) == 0x10) {
            bp = *(int **)(((u8 **)lbl_803DCB88)[i] + 0xb8);
            if (*(u8 **)bp == obj) {
                *bp = 0;
                *((u8 *)bp + 0x8f) = 1;
            }
        }
    }
    if (*(s8 *)(*(u8 **)(obj + 0x50) + 0x56) > 0) {
        ObjGroup_RemoveObject(obj, 8);
    }
    if (*(int *)(obj + 0x64) != 0) {
        if (*(s16 *)(*(u8 **)(obj + 0x50) + 0x48) == 1) {
            setShadowFlag_803db658(1);
        }
        if (*(int *)(*(u8 **)(obj + 0x64) + 4) != 0) {
            curTex = textureFn_8006c5c4();
            tex = *(u8 **)(*(u8 **)(obj + 0x64) + 4);
            if (tex != curTex) {
                if ((*(u8 *)(*(u8 **)(obj + 0x50) + 0x5f) & 4) == 0) {
                    textureFree(tex);
                } else {
                    mm_free(tex);
                }
            }
        }
        if (*(int *)(*(u8 **)(obj + 0x64) + 8) != 0) {
            mm_free(*(void **)(*(u8 **)(obj + 0x64) + 8));
        }
        t2 = *(int *)(*(u8 **)(obj + 0x64) + 0x10);
        if (t2 != 0 && t2 != -1) {
            mm_free((void *)t2);
        }
    }
    if (*(int *)(obj + 0xdc) != 0) {
        mm_free(*(void **)(obj + 0xdc));
        *(int *)(obj + 0xdc) = 0;
    }
    modelCount = *(s8 *)(*(u8 **)(obj + 0x50) + 0x55);
    for (i = 0; i < modelCount; i++) {
        if (*(int *)(*(u8 **)(obj + 0x7c) + i * 4) != 0) {
            ObjModel_Release(*(u8 **)(*(u8 **)(obj + 0x7c) + i * 4));
        }
    }
    if (*(u8 *)(obj + 0xe5) & 1) {
        *(u16 *)(obj + 0xe6) = 0;
        *(u8 *)(obj + 0xe5) = *(u8 *)(obj + 0xe5) & ~1;
        *(u8 *)(obj + 0xf0) = 0;
        ObjModel_ClearRenderAttachment(*(u8 **)(*(u8 **)(obj + 0x7c) + *(s8 *)(obj + 0xad) * 4));
        cb2 = (void (*)(u8 *, int, int, int, int))*(int *)(*(int *)lbl_803DCAB4 + 0xc);
        cb2(obj, 0x7fb, 0, 0x50, 0);
        cb2 = (void (*)(u8 *, int, int, int, int))*(int *)(*(int *)lbl_803DCAB4 + 0xc);
        cb2(obj, 0x7fc, 0, 0x32, 0);
    }
    if (*(u8 *)(obj + 0xe5) & 2) {
        Obj_ClearModelColorFadeRecursive(obj);
    }
    group = ObjGroup_GetObjectGroup(obj);
    if (group != 0) {
        ObjGroup_RemoveObject(obj, group - 1);
    }
    type = *(s16 *)(obj + 0x48);
    if (*(s8 *)(lbl_803DCBA4 + type) == 0) {
        debugPrintf(sObjFreeObjdefError);
    } else {
        *(s8 *)(lbl_803DCBA4 + type) -= 1;
        if (*(s8 *)(lbl_803DCBA4 + type) == 0) {
            o = ((u8 **)lbl_803DCBA8)[type];
            if (*(int *)(o + 0x30) != 0) {
                mm_free(*(void **)(o + 0x30));
            }
            if (*(int *)(o + 0x34) != 0) {
                mm_free(*(void **)(o + 0x34));
            }
            mm_free(o);
        }
    }
    if (*(s16 *)(obj + 0xb4) >= 0) {
        if (flag == 0) {
            cb3 = (void (*)(void))*(int *)(*(int *)gObjectTriggerInterface + 0x4c);
            cb3();
        }
        *(s16 *)(obj + 0xb4) = 0xffff;
    }
    if ((*(u16 *)(obj + 6) & 0x2000) && *(int *)(obj + 0x4c) != 0) {
        mm_free(*(void **)(obj + 0x4c));
    }
    mm_free(obj);
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on

#pragma peephole off
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma opt_loop_invariants off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

extern void playerUpdateWhileTimeStopped(u8 *obj);
extern void playerRenderQuakeSpell(void);
extern void playerUpdate(u8 *obj);
extern void Sfx_PlayFromObject(u8 *obj, int sfx);
extern void Obj_GetWorldPosition(u8 *obj, void *x, void *y, void *z);
extern u32 lbl_803DCB78;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_UpdateObject(u8 *obj)
{
    u8 *t;
    void (*cb)(u8 *, int, int, int, int);
    void (*cb2)(u8 *);

    if (*(u16 *)(obj + 0xb0) & 0x40) {
        return;
    }
    if (lbl_803DCB78 & 1) {
        switch (*(s16 *)(obj + 0x46)) {
        case 0:
        case 0x1f:
            playerUpdateWhileTimeStopped(obj);
            break;
        case 0x69:
            playerRenderQuakeSpell();
            break;
        case 0x4f3:
        case 0x882:
        case 0x887:
            cb2 = (void (*)(u8 *))*(int *)(**(int **)(obj + 0x68) + 8);
            cb2(obj);
            break;
        }
        return;
    }
    if (*(u8 *)(obj + 0xe5) != 0 && *(int *)(obj + 0xc4) == 0 && (*(u8 *)(obj + 0xe5) & 2)) {
        Obj_TickModelColorFadeRecursive(obj);
    }
    if (*(int *)(obj + 0xc0) != 0) {
        if (*(int *)(obj + 0xc8) != 0) {
            t = *(u8 **)(*(u8 **)(obj + 0xc8) + 0x54);
            if (t != 0) {
                *(int *)(t + 0x50) = 0;
                *(u8 *)(*(u8 **)(*(u8 **)(obj + 0xc8) + 0x54) + 0x71) = 0;
            }
        }
        if (*(int *)(obj + 0x54) == 0) {
            return;
        }
        *(int *)(*(u8 **)(obj + 0x54) + 0x50) = 0;
        *(u8 *)(*(u8 **)(obj + 0x54) + 0x71) = 0;
        return;
    }
    if ((*(s16 *)(obj + 6) & 8) == 0) {
        *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
        *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0x18);
        *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x1c);
        *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x20);
    }
    *(f32 *)(obj + 0xfc) = *(f32 *)(obj + 0x24);
    *(f32 *)(obj + 0x100) = *(f32 *)(obj + 0x28);
    *(f32 *)(obj + 0x104) = *(f32 *)(obj + 0x2c);
    if (*(u8 *)(obj + 0xe5) != 0 && *(int *)(obj + 0xc4) == 0 && (*(u8 *)(obj + 0xe5) & 1)) {
        *(s16 *)(obj + 0xe6) = (s16)(int)((f32)*(s16 *)(obj + 0xe6) - timeDelta);
        if (*(s16 *)(obj + 0xe6) <= 0) {
            *(s16 *)(obj + 0xe6) = 0;
            *(u8 *)(obj + 0xe5) &= ~1;
            *(u8 *)(obj + 0xf0) = 0;
            ObjModel_ClearRenderAttachment(*(u8 **)(*(u8 **)(obj + 0x7c) + *(s8 *)(obj + 0xad) * 4));
            cb = (void (*)(u8 *, int, int, int, int))*(int *)(*lbl_803DCAB4 + 0xc);
            cb(obj, 0x7fb, 0, 0x50, 0);
            cb = (void (*)(u8 *, int, int, int, int))*(int *)(*lbl_803DCAB4 + 0xc);
            cb(obj, 0x7fc, 0, 0x32, 0);
            Sfx_PlayFromObject(obj, 0x47b);
        }
    }
    if ((*(u16 *)(obj + 0xb0) & 0x8000) == 0) {
        switch (*(s16 *)(obj + 0x46)) {
        case 0:
        case 0x1f:
            playerUpdate(obj);
            break;
        default:
            if (*(int **)(obj + 0x68) == 0) {
                goto skip;
            }
            cb2 = (void (*)(u8 *))*(int *)(**(int **)(obj + 0x68) + 8);
            if (cb2 != 0) {
                cb2(obj);
            }
            break;
        }
        Obj_GetWorldPosition(obj, obj + 0x18, obj + 0x1c, obj + 0x20);
    }
skip:
    if (*(int *)(obj + 0x54) != 0) {
        if (*(int *)(obj + 0xc8) != 0) {
            t = *(u8 **)(*(u8 **)(obj + 0xc8) + 0x54);
            if (t != 0) {
                *(int *)(t + 0x50) = 0;
                *(u8 *)(*(u8 **)(*(u8 **)(obj + 0xc8) + 0x54) + 0x71) = 0;
            }
        }
        *(int *)(*(u8 **)(obj + 0x54) + 0x50) = 0;
        *(u8 *)(*(u8 **)(obj + 0x54) + 0x71) = 0;
    }
    if (*(int *)(obj + 0x58) != 0) {
        *(u8 *)(*(u8 **)(obj + 0x58) + 0x10f) = 0;
    }
}
#pragma dont_inline reset
#pragma pop

extern void objFn_80065604(void);
extern void Obj_UpdateModelBlendStates(void);
extern void ObjHitReact_ResetActiveObjects(int);
extern int Obj_BuildTransformMatrixSlot(int obj);
extern void playerDoHitDetection(int obj);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_UpdateAllObjects(u8 flags)
{
    int f;
    int off;
    int timeStop;
    u8 *obj2;
    int child;
    int obj;
    int count1;
    int count2;
    u8 *t;
    void (*cb)(int);

    f = flags;
    lbl_803DCB78 = f;
    off = *(s16 *)((u8 *)&lbl_803DCB7C + 2);
    timeStop = f & 1;
    if (timeStop == 0) {
        objFn_80065604();
    }
    Obj_UpdateModelBlendStates();
    ObjHitReact_ResetActiveObjects(lbl_803DCB84);
    obj = *(int *)((u8 *)&lbl_803DCB7C + 4);
    while (obj != 0 && *(s8 *)(obj + 0xae) == 0x64) {
        Obj_UpdateObject((u8 *)obj);
        obj = *(int *)(obj + off);
    }
    while (obj != 0 && (*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 0x40)) {
        Obj_UpdateObject((u8 *)obj);
        *(s8 *)(obj + 0x35) = (s8)Obj_BuildTransformMatrixSlot(obj);
        obj = *(int *)(obj + off);
    }
    if (timeStop == 0) {
        ObjHitReact_UpdateResetObjects();
    }
    for (; obj != 0; obj = *(int *)(obj + off)) {
        t = *(u8 **)(obj + 0x54);
        if (t != 0) {
            if ((*(u8 *)(t + 0x62) & 8) == 0 || (*(s16 *)(t + 0x60) & 1) == 0) {
                Obj_UpdateObject((u8 *)obj);
            }
        } else {
            Obj_UpdateObject((u8 *)obj);
        }
    }
    obj2 = (u8 *)ObjGroup_GetObjects(0, &count1);
    if (count1 != 0) {
        obj2 = *(u8 **)obj2;
    } else {
        obj2 = 0;
    }
    if (obj2 != 0 && *(u8 **)(obj2 + 0xc8) != 0) {
        *(int *)(*(u8 **)(obj2 + 0xc8) + 0x30) = *(int *)(obj2 + 0x30);
        Obj_UpdateObject(*(u8 **)(obj2 + 0xc8));
    }
    if (timeStop == 0) {
        ObjHits_Update(lbl_803DCB84);
        obj = *(int *)((u8 *)&lbl_803DCB7C + 4);
        for (; obj != 0; obj = *(int *)(obj + off)) {
            if ((*(u16 *)(obj + 0xb0) & 0x2000) == 0) {
                switch (*(s16 *)(obj + 0x46)) {
                case 0:
                case 0x1f:
                    playerDoHitDetection(obj);
                    break;
                default:
                    if (*(int **)(obj + 0x68) == 0) {
                        goto next;
                    }
                    cb = (void (*)(int))*(int *)(**(int **)(obj + 0x68) + 0xc);
                    if (cb == 0) {
                        goto next;
                    }
                    cb(obj);
                    break;
                }
                Obj_GetWorldPosition((u8 *)obj, (u8 *)(obj + 0x18), (u8 *)(obj + 0x1c), (u8 *)(obj + 0x20));
            }
        next:;
        }
        obj2 = (u8 *)ObjGroup_GetObjects(0, &count2);
        if (count2 != 0) {
            obj2 = *(u8 **)obj2;
        } else {
            obj2 = 0;
        }
        if (obj2 != 0 && *(u8 **)(obj2 + 0xc8) != 0) {
            *(int *)(*(u8 **)(obj2 + 0xc8) + 0x30) = *(int *)(obj2 + 0x30);
            child = *(int *)(obj2 + 0xc8);
            if ((*(u16 *)(child + 0xb0) & 0x2000) == 0) {
                switch (*(s16 *)(child + 0x46)) {
                case 0:
                case 0x1f:
                    playerDoHitDetection(child);
                    break;
                default:
                    if (*(int **)(child + 0x68) == 0) {
                        goto done;
                    }
                    cb = (void (*)(int))*(int *)(**(int **)(child + 0x68) + 0xc);
                    if (cb == 0) {
                        goto done;
                    }
                    cb(child);
                    break;
                }
                Obj_GetWorldPosition((u8 *)child, (u8 *)(child + 0x18), (u8 *)(child + 0x1c), (u8 *)(child + 0x20));
            }
        }
    done:
        (*(void (**)(u8))(*(int *)gWaterfxInterface + 4))(framesThisStep);
    }
    if ((f & 2) == 0) {
        (*(void (**)(int, int, int))(*(int *)gModgfxInterface + 0xc))(0, 0, 0);
        (*(void (**)(int, u8, int, int))(*(int *)gExpgfxInterface + 0xc))(0, framesThisStep, 0, 0);
    }
    if (timeStop == 0) {
        ObjHits_TickPriorityHitCooldowns();
        (*(void (**)(void))(*(int *)gObjectTriggerInterface + 0x28))();
        (*(void (**)(void))(*(int *)gObjectTriggerInterface + 0x18))();
        (*(void (**)(u8))(*(int *)gCameraInterface + 8))(framesThisStep);
    }
}
#pragma dont_inline reset
#pragma pop

extern int getCurMapType(void);
extern void Obj_ResetObjectSystem(void);
extern u8 lbl_802CABF8[];
extern s16 lbl_803DB44C[2];
extern f32 lbl_803DE8BC;
extern f32 lbl_803DE8C0;
extern f32 lbl_803DE8C4;
extern f32 lbl_803DE8C8;
extern f32 fn_80293E80(f32);
extern f32 sin(f32);
extern int getCurUiDll(void);
extern u8 *Camera_GetCurrentViewSlot(void);
extern int lbl_803DCB70;
extern void playerUpdateFn_8005649c(void);

typedef struct CharSpawn {
    s16 id;
    u8 unk2;
    u8 unk3;
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 x;
    f32 y;
    f32 z;
    int unk14;
} CharSpawn;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void mapSetupPlayer(void)
{
    u8 *base;
    int playerNo;
    int mapType;
    u8 *obj;
    f32 *pos;
    f32 x, y, z;
    int uiDll;
    u8 *view;
    u8 *vp;
    CharSpawn spawn;

    base = (u8 *)&lbl_802CABF8;
    mapType = getCurMapType();
    if (mapType == 2 || mapType == 3) {
        OSReport((char *)(base + 0x70));
        Obj_ResetObjectSystem();
    } else {
        playerNo = (*(u8 (**)(void))(*gMapEventInterface + 0x74))();
        pos = (*(f32 *(**)(void))(*gMapEventInterface + 0x90))();
        x = pos[0];
        y = pos[1];
        z = pos[2];
        obj = 0;
        if (playerNo > -1 && mapType != 4) {
            OSReport((char *)(base + 0x88), mapType, playerNo);
            memset(&spawn, 0, 0x18);
            spawn.unk14 = -1;
            spawn.unk3 = 0;
            spawn.unk4 = 1;
            spawn.unk5 = 4;
            spawn.unk6 = 0xff;
            spawn.unk7 = 0xff;
            spawn.id = lbl_803DB44C[playerNo];
            spawn.unk2 = 0x18;
            spawn.x = x;
            spawn.y = y;
            spawn.z = z;
            if (getLoadedFileFlags(0) & 0x100000) {
                OSReport((char *)(base + 0x20), -1);
                obj = 0;
            } else {
                obj = loadCharacter((s16 *)&spawn, 1, -1, -1, 0, 0);
                if (obj != 0) {
                    Obj_RegisterObject(obj, 1);
                    OSReport((char *)(base + 0x5c), *(int *)(obj + 0x50) + 0x91);
                }
            }
        }
        *(f32 *)(base + 8) = lbl_803DE8BC * fn_80293E80((lbl_803DE8C0 * (f32)(*(s8 *)((u8 *)pos + 0xc) << 8)) / lbl_803DE8C4) + x;
        *(f32 *)(base + 0xc) = lbl_803DE8C8 + y;
        *(f32 *)(base + 0x10) = lbl_803DE8BC * sin((lbl_803DE8C0 * (f32)(*(s8 *)((u8 *)pos + 0xc) << 8)) / lbl_803DE8C4) + z;
        uiDll = getCurUiDll();
        if ((u32)(uiDll - 2) <= 4 || uiDll == 7) {
            (*(void (**)(u8 *, f32, f32, f32))(*(int *)gCameraInterface + 4))(obj, *(f32 *)(base + 8), *(f32 *)(base + 0xc), *(f32 *)(base + 0x10));
            (*(void (**)(int, int, int, int, int, int, int))(*(int *)gCameraInterface + 0x1c))(0x57, 0, 3, 0, 0, 0, 0);
            (*(void (**)(u8 *, int))(*(int *)gCameraInterface + 0x28))(obj, 0);
            (*(void (**)(int))(*(int *)gCameraInterface + 8))(1);
        } else {
            (*(void (**)(u8 *, f32, f32, f32))(*(int *)gCameraInterface + 4))(obj, *(f32 *)(base + 8), *(f32 *)(base + 0xc), *(f32 *)(base + 0x10));
            (*(void (**)(int, int, int, int, u8 *, int, int))(*(int *)gCameraInterface + 0x1c))(0x42, 0, 0, 0x20, base, 0, 0xff);
            (*(void (**)(int))(*(int *)gCameraInterface + 8))(1);
        }
        vp = Camera_GetCurrentViewSlot();
        view = (*(u8 *(**)(void))(*(int *)gCameraInterface + 0xc))();
        *(f32 *)(vp + 0xc) = *(f32 *)(view + 0x18);
        *(f32 *)(vp + 0x10) = *(f32 *)(view + 0x1c);
        *(f32 *)(vp + 0x14) = *(f32 *)(view + 0x20);
        (*(void (**)(u8 *))(*(int *)gTitleMenuControlInterface + 0x10))(obj);
        lbl_803DCB70 = 0;
        playerUpdateFn_8005649c();
    }
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

extern void fn_80013B6C(int *p, int n);
extern void AudioStream_StopAll(void);
extern int lbl_803DB448;
extern int lbl_803DCB8C;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_ResetObjectSystem(void)
{
    int off;
    int i;
    int zero;

    i = 0;
    off = i;
    zero = i;
    for (; i < lbl_803DCB94; i++) {
        if (*(void **)((int)lbl_803DCB98 + off) != 0) {
            objFreeObjDef(*(void **)((int)lbl_803DCB98 + off), 0);
            *(int *)((int)lbl_803DCB98 + off) = zero;
        }
        off += 4;
    }
    lbl_803DCB94 = 0;
    lbl_803DB448 = 0;
    i = lbl_803DCB84 - 1;
    off = i << 2;
    for (; i >= 0; i--) {
        Obj_FreeObject(*(void **)((int)lbl_803DCB88 + off));
        off -= 4;
    }
    i = 0;
    off = i;
    zero = i;
    for (; i < lbl_803DCB94; i++) {
        if (*(void **)((int)lbl_803DCB98 + off) != 0) {
            objFreeObjDef(*(void **)((int)lbl_803DCB98 + off), 0);
            *(int *)((int)lbl_803DCB98 + off) = zero;
        }
        off += 4;
    }
    lbl_803DB448 = 2;
    lbl_803DCB94 = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB84 = 0;
    fn_80013B6C(&lbl_803DCB7C, 0x38);
    lbl_803DCB94 = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB70 = 0;
    lbl_803DCB84 = 0;
    fn_80013B6C(&lbl_803DCB7C, 0x38);
    lbl_803DCBC4 = 0;
    ObjGroup_ClearAll();
    ObjHits_ResetWorkBuffers();
    (*(void (**)(int, int))(*(int *)gCameraInterface + 0x28))(0, 0);
    AudioStream_StopAll();
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_UpdateModelBlendStates(void)
{
    int joff;
    u8 *obj;
    int j;
    int i;
    int k;
    int ioff;
    u8 *walker;
    int koff;
    u8 *child;
    u8 *m;
    u8 *c0;
    u8 *bp;

    i = 0;
    ioff = 0;
    for (; i < lbl_803DCB84; i++) {
        obj = *(u8 **)((int)lbl_803DCB88 + ioff);
        if (obj != 0 && *(void **)(obj + 0x50) != 0) {
            m = *(u8 **)(obj + 0x64);
            if (m != 0) {
                *(int *)(m + 0xc) = 0;
            }
            j = 0;
            joff = 0;
            for (; j < *(s8 *)(*(u8 **)(obj + 0x50) + 0x55); j++) {
                m = *(u8 **)(*(u8 **)(obj + 0x7c) + joff);
                if (m != 0) {
                    *(u16 *)(m + 0x18) &= ~8;
                    if (*(u8 *)(*(u8 **)m + 0xf9) != 0) {
                        ObjModel_AdvanceBlendChannels(m, timeDelta);
                    }
                }
                joff += 4;
            }
            j = 0;
            walker = obj;
            for (; j < *(u8 *)(obj + 0xeb); j++) {
                child = *(u8 **)(walker + 0xc8);
                if (child != 0 && *(void **)(child + 0x50) != 0) {
                    k = 0;
                    koff = k;
                    for (; k < *(s8 *)(*(u8 **)(child + 0x50) + 0x55); k++) {
                        m = *(u8 **)(*(u8 **)(child + 0x7c) + koff);
                        if (m != 0) {
                            *(u16 *)(m + 0x18) &= ~8;
                            if (*(u8 *)(*(u8 **)m + 0xf9) != 0) {
                                c0 = *(u8 **)(child + 0xc0);
                                if (c0 != 0) {
                                    bp = *(u8 **)(c0 + 0xb8);
                                } else {
                                    bp = 0;
                                }
                                if (c0 == 0 || (bp != 0 && *(s8 *)(bp + 0x56) == 0)) {
                                    ObjModel_AdvanceBlendChannels(m, timeDelta);
                                }
                            }
                        }
                        koff += 4;
                    }
                }
                walker += 4;
            }
        }
        ioff += 4;
    }
}
#pragma dont_inline reset
#pragma pop

extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, void *ox, void *oy, void *oz);
extern void mapLoadForObject(int id, void *obj);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_RegisterObject(u8 *obj, int flags)
{
    int id;
    int prev;
    int cur;
    int off;

    if (*(void **)(obj + 0x30) != 0) {
        Obj_TransformLocalPointToWorld(*(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14), obj + 0x18, obj + 0x1c, obj + 0x20);
    } else {
        *(f32 *)(obj + 0x18) = *(f32 *)(obj + 0xc);
        *(f32 *)(obj + 0x1c) = *(f32 *)(obj + 0x10);
        *(f32 *)(obj + 0x20) = *(f32 *)(obj + 0x14);
    }
    *(f32 *)(obj + 0x8c) = *(f32 *)(obj + 0x18);
    *(f32 *)(obj + 0x90) = *(f32 *)(obj + 0x1c);
    *(f32 *)(obj + 0x94) = *(f32 *)(obj + 0x20);
    *(f32 *)(obj + 0x80) = *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x84) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x88) = *(f32 *)(obj + 0x14);
    Obj_RunInitCallback(obj, *(int *)(obj + 0x4c), 0);
    if (*(u8 **)(obj + 0x54) != 0) {
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x10) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x14) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x18) = *(f32 *)(obj + 0x14);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x1c) = *(f32 *)(obj + 0xc);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x20) = *(f32 *)(obj + 0x10);
        *(f32 *)(*(u8 **)(obj + 0x54) + 0x24) = *(f32 *)(obj + 0x14);
    }
    id = *(s16 *)(*(u8 **)(obj + 0x50) + 0x78);
    if (id > -1) {
        mapLoadForObject(id, obj);
    }
    if (*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 0x40) {
        ObjGroup_AddObject(obj, 6);
        if (*(s8 *)(obj + 0xae) != 0x5a && (*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 0x40)) {
            *(u8 *)(obj + 0xae) = 0x5a;
        }
    } else {
        if (*(s8 *)(obj + 0xae) == 0) {
            *(u8 *)(obj + 0xae) = 0x50;
        }
    }
    if (flags & 1) {
        *(u16 *)(obj + 0xb0) |= 0x10;
        ((u8 **)lbl_803DCB88)[lbl_803DCB84++] = obj;
        if (*(u16 *)(obj + 0xb0) & 0x10) {
            prev = 0;
            cur = *(int *)((u8 *)&lbl_803DCB7C + 4);
            off = *(s16 *)((u8 *)&lbl_803DCB7C + 2);
            while (cur != 0 && *(s8 *)(obj + 0xae) < *(s8 *)(cur + 0xae)) {
                prev = cur;
                cur = *(int *)(cur + off);
            }
            objListAdd(&lbl_803DCB7C, prev, (int)obj);
        }
    }
    if (*(s8 *)(*(u8 **)(obj + 0x50) + 0x56) > 0) {
        ObjGroup_AddObject(obj, 8);
    }
    if (*(u32 *)(*(u8 **)(obj + 0x50) + 0x44) & 1) {
        lbl_803DCBC4 = 0;
    }
}
#pragma dont_inline reset
#pragma pop

extern void Sfx_RemoveLoopedObjectSoundForObject(u8 *obj);
extern void Sfx_StopObjectChannel(u8 *obj, int ch);
extern char sObjFreeNonExistentObjectWarning[];
extern void *lbl_803DCB90;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_FreeObject(u8 *obj)
{
    u8 **p;
    int n;
    int i;
    u8 **base;
    int off;
    u8 *q;

    if (*(u16 *)(obj + 0xb0) & 0x40) {
        return;
    }
    Sfx_RemoveLoopedObjectSoundForObject(obj);
    Sfx_StopObjectChannel(obj, 0x7f);
    if (*(u16 *)(obj + 0xb0) & 0x10) {
        i = 0;
        p = (u8 **)lbl_803DCB88;
        for (n = lbl_803DCB84; n > 0; n--) {
            if (*p == obj) {
                break;
            }
            p++;
            i++;
        }
        if (i < lbl_803DCB84) {
            lbl_803DCB84--;
            off = i << 2;
            for (; i < lbl_803DCB84; i++) {
                q = (u8 *)lbl_803DCB88 + off;
                *(int *)q = *(int *)(q + 4);
                off += 4;
            }
        } else {
            OSReport(sObjFreeNonExistentObjectWarning);
        }
        if (*(u16 *)(obj + 0xb0) & 0x10) {
            objList_remove(&lbl_803DCB7C, obj);
        }
        lbl_803DCBC4 = 0;
    }
    for (i = 0; i < lbl_803DCB94; i++) {
    }
    *(u16 *)(obj + 0xb0) |= 0x40;
    if (*(u8 *)(obj + 0xea) != 0) {
        i = 0;
        base = (u8 **)lbl_803DCB90;
        p = base;
        for (n = lbl_803DCB8C; n > 0; n--) {
            if (*p == obj) {
                break;
            }
            p++;
            i++;
        }
        if (i != lbl_803DCB8C) {
            return;
        }
        if (lbl_803DCB8C < 0x18) {
            base[lbl_803DCB8C] = obj;
            lbl_803DCB8C++;
            return;
        }
    }
    if (lbl_803DB448 == 2) {
        i = lbl_803DCB94;
        if (lbl_803DCB94 != 0) {
            i = 0;
            p = (u8 **)lbl_803DCB98;
            for (n = lbl_803DCB94; n > 0; n--) {
                if (*p == obj) {
                    break;
                }
                p++;
                i++;
            }
        }
        if (i == lbl_803DCB94) {
            ((u8 **)lbl_803DCB98)[lbl_803DCB94] = obj;
            lbl_803DCB94++;
            if (lbl_803DCB94 == 400) {
                lbl_803DCB94--;
            }
        }
    } else {
        objFreeObjDef(obj, !lbl_803DB448);
    }
}
#pragma dont_inline reset
#pragma pop

extern void *lbl_803DCBC0;
extern int *lbl_803DCBBC;
extern int lbl_803DCBB8;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void Obj_InitObjectSystem(void)
{
    s16 *p;
    int *q;
    int i;

    lbl_803DCB98 = (void **)mmAlloc(0x640, 0xe, 0);
    lbl_803DCB90 = mmAlloc(0x60, 0xe, 0);
    lbl_803DCBC0 = mmAlloc(0x10, 0xe, 0);
    loadAssetFileById((int)&lbl_803DCBA0, 0x3f);
    lbl_803DCB9C = (getDataFileSize(0x3f) >> 1) - 1;
    for (p = lbl_803DCBA0 + lbl_803DCB9C; *p == 0;) {
        p--;
        lbl_803DCB9C--;
    }
    loadAssetFileById((int)&lbl_803DCBBC, 0x3d);
    lbl_803DCBB8 = 0;
    for (q = lbl_803DCBBC; *q != -1;) {
        q++;
        lbl_803DCBB8++;
    }
    lbl_803DCBB8--;
    lbl_803DCBA8 = (u8 *)mmAlloc(lbl_803DCBB8 * 4, 0xe, 0);
    lbl_803DCBA4 = (u8 *)mmAlloc(lbl_803DCBB8, 0xe, 0);
    for (i = 0; i < lbl_803DCBB8; i++) {
        lbl_803DCBA4[i] = 0;
    }
    loadAssetFileById((int)&lbl_803DCBB4, 0x16);
    loadAssetFileById((int)&lbl_803DCBB0, 0x17);
    lbl_803DCBAC = 0;
    for (q = lbl_803DCBB0; *q != -1;) {
        q++;
        lbl_803DCBAC++;
    }
    lbl_803DCB88 = mmAlloc(0x960, 0xe, 0);
    ObjHits_InitWorkBuffers();
    lbl_803DCB94 = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB70 = 0;
    lbl_803DCB84 = 0;
    fn_80013B6C(&lbl_803DCB7C, 0x38);
    lbl_803DCBC4 = 0;
    ObjGroup_ClearAll();
    ObjHits_ResetWorkBuffers();
}
#pragma dont_inline reset
#pragma pop

extern int loadModLines(int n, s16 *out);
extern void intersectModLineBuild(u8 *buf);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
u8 *loadObjectFile(int id)
{
    int size;
    int base;
    u8 *buf;
    int off;
    int n;
    s16 modLine;

    if (id >= lbl_803DCBB8) {
        return 0;
    }
    if (lbl_803DCBA4[id] != 0) {
        lbl_803DCBA4[id]++;
        return *(u8 **)((int)lbl_803DCBA8 + (id << 2));
    }
    off = id << 2;
    base = ((int *)lbl_803DCBBC)[id];
    {
        int *t = (int *)((int)lbl_803DCBBC + off);
        size = t[1] - base;
    }
    buf = (u8 *)mmAlloc(size, 0xe, 0);
    if (buf != 0) {
        fileLoadToBufferOffset(0x3e, buf, base, size);
        if (*(void **)(buf + 0x20) != 0) {
            *(int *)(buf + 0x20) = (int)buf + *(int *)(buf + 0x20);
        }
        if (*(void **)(buf + 0x24) != 0) {
            *(int *)(buf + 0x24) = (int)buf + *(int *)(buf + 0x24);
        }
        if (*(void **)(buf + 0x28) != 0) {
            *(int *)(buf + 0x28) = (int)buf + *(int *)(buf + 0x28);
        }
        *(int *)(buf + 8) = (int)buf + *(int *)(buf + 8);
        *(int *)(buf + 0xc) = (int)buf + *(int *)(buf + 0xc);
        *(int *)(buf + 0x10) = (int)buf + *(int *)(buf + 0x10);
        if (*(void **)(buf + 0x18) != 0) {
            *(int *)(buf + 0x18) = (int)buf + *(int *)(buf + 0x18);
        }
        if (*(void **)(buf + 0x40) != 0) {
            *(int *)(buf + 0x40) = (int)buf + *(int *)(buf + 0x40);
        }
        if (*(void **)(buf + 0x1c) != 0) {
            *(int *)(buf + 0x1c) = (int)buf + *(int *)(buf + 0x1c);
        }
        *(int *)(buf + 0x2c) = (int)buf + *(int *)(buf + 0x2c);
        *(int *)(buf + 0x30) = 0;
        *(int *)(buf + 0x34) = 0;
        n = (s8)buf[0x5d];
        if (n > -1) {
            *(int *)(buf + 0x30) = loadModLines(n, &modLine);
            *(u8 *)(buf + 0x5c) = modLine;
            intersectModLineBuild(buf);
        }
        *(u8 **)((int)lbl_803DCBA8 + off) = buf;
        lbl_803DCBA4[id] = 1;
        return buf;
    }
    return 0;
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int objGetTotalDataSize(void *tmpl, u8 *def, s16 *data, int flags)
{
    int size;
    int extra;
    int (*cb)(void *, int);

    size = *(s8 *)(def + 0x55) * 4 + 0x10c;
    switch (*(s16 *)((u8 *)tmpl + 0x46)) {
    case 0:
    case 0x1f:
        extra = 0x8e0;
        break;
    default:
        if (*(int **)((u8 *)tmpl + 0x68) == 0) {
            goto none;
        }
        cb = (int (*)(void *, int))*(int *)(**(int **)((u8 *)tmpl + 0x68) + 0x1c);
        if (cb == 0) {
            goto none;
        }
        extra = cb(tmpl, size);
        break;
    none:
        extra = 0;
        break;
    }
    size += extra;
    if ((flags & 0x40) || (*(u32 *)(def + 0x44) & 0x400000)) {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x50;
    }
    if (flags & 0x100) {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x800;
    }
    if ((flags & 2) && *(s16 *)(def + 0x48) != 0) {
        size = roundUpTo4(size) + 0x44;
    }
    if (*(u8 *)(def + 0x61) != 0) {
        size = roundUpTo4(size) + 0xb8;
        if (*(s8 *)(def + 0x65) & 8) {
            size += 0x110;
        }
    }
    if (*(u8 *)(def + 0x5a) != 0) {
        size = roundUpTo4(size) + *(u8 *)(def + 0x5a) * 0x12;
    }
    if (*(u8 *)(def + 0x59) != 0) {
        size = roundUpTo4(size) + *(u8 *)(def + 0x59) * 0x10;
    }
    if (*(u8 *)(def + 0x72) != 0) {
        size = roundUpTo4(size) + *(u8 *)(def + 0x72) * 0x18;
    }
    if (*(u8 *)(def + 0x61) != 0 && *(u8 *)(def + 0x66) != 0) {
        size = roundUpTo8(size) + 0x12c;
    }
    if (*(u8 *)(def + 0x72) != 0) {
        size = roundUpTo4(size) + *(u8 *)(def + 0x72) * 5;
    }
    return roundUpTo32(size);
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *mmAlloc(int size, int type, int flag);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_strength_reduction off
#pragma opt_loop_invariants off
#pragma opt_loop_invariants reset
#pragma opt_strength_reduction reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline on
#pragma dont_inline reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

extern void PSVECCrossProduct(f32 *a, f32 *b, f32 *out);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void fn_800213D0(f32 *a, f32 *b, s16 *out0, s16 *out1, s16 *out2);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

extern void PSMTXRotAxisRad(f32 *m, f32 *axis, f32 angle);

#pragma push
#pragma scheduling off
void fn_8002A5DC(u8 *obj)
{
    extern f32 lbl_803DCECC;
    extern f32 lbl_803DCED0;
    extern f32 lbl_803DE888;
    extern f32 lbl_803DE894;
    extern f32 lbl_803DE898;
    f32 m2[16];
    f32 rot[12];
    f32 vecA[3];
    f32 vecB[3];
    f32 cross[3];
    f32 len;
    f32 dz;
    f32 dx;
    f32 denom;
    f32 sum;

    denom = lbl_803DE888 * *(f32 *)(obj + 0xa8);
    denom *= *(f32 *)(obj + 8);
    dx = ((*(f32 *)(obj + 0x88) - lbl_803DCECC) - (*(f32 *)(obj + 0x14) - playerMapOffsetZ)) / denom;
    dz = ((*(f32 *)(obj + 0xc) - lbl_803DCED0) - (*(f32 *)(obj + 0x80) - playerMapOffsetX)) / denom;
    sum = dz * dz + dx * dx;
    if (sum > lbl_803DE88C) {
        len = sqrtf(sum);
        vecA[0] = dz / len;
        vecA[1] = lbl_803DE88C;
        vecA[2] = -dx / len;
        vecB[0] = lbl_803DE88C;
        vecB[1] = lbl_803DE890;
        vecB[2] = lbl_803DE88C;
        PSVECCrossProduct(vecA, vecB, cross);
        PSMTXRotAxisRad(rot, cross, lbl_803DE894 * (lbl_803DE898 * -len));
        setMatrixFromObjectTransposed(obj, m2);
        m2[3] = lbl_803DE88C;
        m2[7] = lbl_803DE88C;
        m2[11] = lbl_803DE88C;
        PSMTXConcat(rot, m2, rot);
        vecA[0] = rot[8];
        vecA[1] = rot[9];
        vecA[2] = rot[10];
        vecB[0] = rot[4];
        vecB[1] = rot[5];
        vecB[2] = rot[6];
        fn_800213D0(vecA, vecB, (s16 *)(obj + 4), (s16 *)(obj + 2), (s16 *)obj);
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma opt_strength_reduction off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void modelInitBones(f32 scale, void *model) {
    extern f32 lbl_803DE88C;
    extern f32 lbl_803DE890;
    extern f32 lbl_803DE8D4;
    extern f32 lbl_803DE8D8;
    f32 *srcP;
    int off;
    int boneOff;
    f32 *sumP;
    u8 *hdr;
    u8 *tbl;
    int i;
    int parent;
    f32 *src;
    u8 *bone;
    f32 zero;
    f32 sc;
    f32 minScale;
    f32 w;
    f32 len;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 v;
    f32 pv;
    f32 sums[152];
    u8 *m = model;

    sc = scale;
    hdr = *(u8 **)m;
    if (!(!*(u16 *)(hdr + 2) & 0x1000)) {
        if (*(u8 *)(hdr + 0xf3) == 0) {
        } else if ((src = *(f32 **)(hdr + 0x18)) != NULL && (tbl = *(u8 **)(m + 0x14)) != NULL) {
        **(f32 **)(tbl + 4) = src[0] * sc;
        if (**(f32 **)(tbl + 4) == lbl_803DE88C) {
            **(f32 **)(tbl + 4) = src[1] * sc;
        }
        **(f32 **)(tbl + 8) = **(f32 **)(tbl + 4) * **(f32 **)(tbl + 4);
        **(f32 **)(tbl + 0xc) = lbl_803DE8D4;
        **(f32 **)(tbl + 0x10) = **(f32 **)(tbl + 4);
        zero = lbl_803DE88C;
        sums[0] = zero;
        i = 1;
        srcP = src + 1;
        off = 4;
        boneOff = 0x1c;
        sumP = &sums[1];
        minScale = lbl_803DE890;
        for (; i < *(u8 *)(*(u8 **)m + 0xf3); srcP++, off += 4, boneOff += 0x1c, sumP++, i++) {
            *(f32 *)(*(u8 **)(tbl + 4) + off) = sc * *srcP;
            *(f32 *)(*(u8 **)(tbl + 8) + off) =
                *(f32 *)(*(u8 **)(tbl + 4) + off) * *(f32 *)(*(u8 **)(tbl + 4) + off);
            bone = *(u8 **)(hdr + 0x3c) + boneOff;
            parent = *(s8 *)bone;
            vx = *(f32 *)(bone + 4);
            vy = *(f32 *)(bone + 8);
            vz = *(f32 *)(bone + 0xc);
            len = sqrtf(vx * vx + vy * vy + vz * vz);
            *(f32 *)(*(u8 **)(tbl + 0xc) + off) = sc * len;
            if (*(f32 *)(*(u8 **)(tbl + 0xc) + off) == zero) {
                *(f32 *)(*(u8 **)(tbl + 0xc) + off) = lbl_803DE8D8;
            }
            w = *(f32 *)(*(u8 **)(hdr + 0x1c) + off);
            if (w >= minScale) {
                *(f32 *)(*(u8 **)(tbl + 0xc) + off) *= w;
            }
            *sumP = sums[parent] + *(f32 *)(*(u8 **)(tbl + 0xc) + off);
            if (*srcP == zero) {
                *(f32 *)(*(u8 **)(tbl + 0x10) + off) = *(f32 *)(*(u8 **)(tbl + 0x10) + parent * 4);
            } else {
                *(f32 *)(*(u8 **)(tbl + 0x10) + off) = *sumP + *(f32 *)(*(u8 **)(tbl + 4) + off);
                v = *(f32 *)(*(u8 **)(tbl + 0x10) + off);
                pv = *(f32 *)(*(u8 **)(tbl + 0x10) + parent * 4);
                *(f32 *)(*(u8 **)(tbl + 0x10) + off) = (v > pv) ? v : pv;
            }
        }
    }
}
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma fp_contract off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma optimization_level 1
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
int loadModLines(int idx, s16 *outCount) {
    int result;
    int *hdr;
    int size;
    int start;

    result = 0;
    if (idx > (getDataFileSize(0x38) - 4) >> 2) {
        return 0;
    }
    hdr = mmAlloc(0x10, 0x1a, 0);
    fileLoadToBufferOffset(0x38, hdr, idx << 2, 8);
    start = hdr[0];
    size = hdr[1] - hdr[0];
    if (size > 0) {
        result = (int)mmAlloc(size, 5, 0);
        fileLoadToBufferOffset(0x37, (void *)result, start, size);
    }
    mm_free(hdr);
    *outCount = (u32)size / 20;
    return result;
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern f32 lbl_803DCED0;
extern f32 lbl_803DCECC;
extern f32 playerMapOffsetZ;
extern f32 playerMapOffsetX;

#pragma dont_inline off

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop
