#include "ghidra_import.h"
#include "main/asset_load.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/engine_8001746C_phantoms.h"
#include "main/mapEvent.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/objlib.h"
#include "main/resource.h"

extern void mm_free(void *ptr);

/*
 * --INFO--
 *
 * Function: gameTextSetWindow
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
    ObjAnimComponent *objAnim;
    int renderOpAlpha;
    int renderOpIndex;
    ObjModelFileHeaderLite *modelFile;
    ObjModelInstanceLite *model;

    objAnim = (ObjAnimComponent *)obj;
    renderOpAlpha = alpha;
    model = (ObjModelInstanceLite *)objAnim->banks[objAnim->bankIndex];
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
    ObjAnimComponent *objAnim;

    objAnim = (ObjAnimComponent *)obj;
    return objAnim->banks[objAnim->bankIndex];
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

    ((GameObject *)obj)->unkE6 = 0;
    ((GameObject *)obj)->unkE5 &= ~0x6;
    i = 0;
    childScan = obj;
    while (i < ((GameObject *)obj)->unkEB) {
        Obj_ClearModelColorFadeRecursive(((GameObject *)childScan)->unkC8);
        childScan += 4;
        i++;
    }
}

void Obj_TickModelColorFadeRecursive(u8 *obj) {
    f32 alpha;
    int i;
    u8 *childScan;

    if ((((GameObject *)obj)->unkE5 & 4) != 0) {
        alpha = (f32)obj[0xef] + lbl_803DE89C * timeDelta;
    } else {
        alpha = (f32)obj[0xef] - lbl_803DE89C * timeDelta;
    }

    if (alpha < lbl_803DE88C) {
        alpha = -alpha;
        ((GameObject *)obj)->unkE5 ^= 4;
    } else if (alpha > lbl_803DE8A0) {
        alpha = lbl_803DE8A0 - (alpha - lbl_803DE8A0);
        ((GameObject *)obj)->unkE5 ^= 4;
    }

    ((GameObject *)obj)->unkEF = (int)alpha;
    if ((((GameObject *)obj)->unkE5 & 8) == 0) {
        ((GameObject *)obj)->unkE6 -= framesThisStep;
        if (((GameObject *)obj)->unkE6 <= 0 && ((GameObject *)obj)->unkC4 == NULL) {
            Obj_ClearModelColorFadeRecursive(obj);
        }
    }

    i = 0;
    childScan = obj;
    while (i < ((GameObject *)obj)->unkEB) {
        Obj_TickModelColorFadeRecursive(((GameObject *)childScan)->unkC8);
        childScan += 4;
        i++;
    }
}

#pragma dont_inline on
void Obj_SetModelColorFadeRecursive(u8 *obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf) {
    int i;
    u8 *childScan;

    ((GameObject *)obj)->unkE6 = (s16)frames;
    ((GameObject *)obj)->unkE5 &= ~4;
    ((GameObject *)obj)->unkE5 |= 2;
    obj[0xec] = red;
    obj[0xed] = green;
    obj[0xee] = blue;
    if (frames == 10000) {
        ((GameObject *)obj)->unkE5 |= 8;
    } else {
        ((GameObject *)obj)->unkE5 &= ~8;
    }
    if (startAtHalf != 0) {
        obj[0xef] = 0x7f;
    } else {
        obj[0xef] = 0;
    }

    i = 0;
    childScan = obj;
    while (i < ((GameObject *)obj)->unkEB) {
        Obj_SetModelColorFadeRecursive(((GameObject *)childScan)->unkC8, frames, red, green, blue, startAtHalf);
        childScan += 4;
        i++;
    }
}
#pragma dont_inline reset

void Obj_SetModelColorOverrideRecursive(u8 *obj, u8 red, u8 green, u8 blue, u8 alpha, u8 enabled) {
    int i;
    u8 *childScan;

    if (enabled != 0) {
        ((GameObject *)obj)->unkE5 |= 0x10;
        obj[0xec] = red;
        obj[0xed] = green;
        obj[0xee] = blue;
        obj[0xef] = alpha;
    } else {
        ((GameObject *)obj)->unkE5 &= ~0x10;
    }

    i = 0;
    childScan = obj;
    while (i < ((GameObject *)obj)->unkEB) {
        Obj_SetModelColorOverrideRecursive(((GameObject *)childScan)->unkC8, red, green, blue, alpha, enabled);
        childScan += 4;
        i++;
    }
}

void Obj_ResetModelColorState(u8 *obj) {
    ((GameObject *)obj)->unkE6 = 0;
    ((GameObject *)obj)->unkE5 &= ~1;
    ((GameObject *)obj)->unkF0 = 0;
    ObjModel_ClearRenderAttachment((u8 *)Obj_GetActiveModel(obj));
    (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))((int)obj, 0x7fb, 0, 0x50, 0);
    (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))((int)obj, 0x7fc, 0, 0x32, 0);
}

#pragma peephole off
void Obj_StartModelFadeIn(u8 *obj, int frames) {
    ObjAnimComponent *objAnim;
    f32 mtx[16];
    int fadeLimit;
    s16 objType;

    objAnim = (ObjAnimComponent *)obj;
    fadeLimit = 10;
    objType = ((GameObject *)obj)->anim.classId;
    if (objType == 0x1c || objType == 0x6d || objType == 0x2a) {
        fadeLimit = 40;
    }
    if ((*(u8 *)((u8 *)((GameObject *)obj)->anim.modelInstance + 0x76) & 1) != 0) {
        if (((GameObject *)obj)->unkF0 < fadeLimit) {
            ((GameObject *)obj)->unkF0++;
            Obj_SetModelColorFadeRecursive(obj, 0x1e, 0xa0, 0xff, 0xff, 0);
        }
        if (((GameObject *)obj)->unkF0 == fadeLimit) {
            if ((((GameObject *)obj)->unkE5 & 2) != 0) {
                Obj_ClearModelColorFadeRecursive(obj);
            }
            ((GameObject *)obj)->unkE6 = (s16)frames;
            ((GameObject *)obj)->unkE5 = (u8)(((GameObject *)obj)->unkE5 | 1);
            Obj_BuildWorldTransformMatrix(obj, mtx, 0);
            ((void (*)(u8 *, u8 *, f32 *, int, f32))ObjModel_EnableDefaultRenderCallback)(
                obj, (u8 *)objAnim->banks[objAnim->bankIndex], mtx, 1,
                ((GameObject *)obj)->anim.hitboxScale * ((GameObject *)obj)->anim.rootMotionScale);
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
    return ((GameObject *)obj)->unkE5 & 1;
}

int objGetFlagsE5_2(u8 *obj) {
    return ((GameObject *)obj)->unkE5 & 2;
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
    ((GameObject *)obj)->unkE8 = (u8)idx;
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
        if ((((ObjAnimComponent *)obj)->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) == 0) {
            return;
        }
    }
    ((GameObject *)obj)->anim.activeHitboxMode = slot;
}

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

#pragma peephole on
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

void Obj_InsertIntoUpdateList(u8 *obj) {
    if (((GameObject *)obj)->objectFlags & 0x10) {
        int *list = &lbl_803DCB7C;
        int prev = 0;
        int cur = list[1];
        int linkOff = *(s16 *)((u8 *)list + 2);
        while (cur != 0 && (s8)obj[0xae] < (s8)((u8 *)cur)[0xae]) {
            prev = cur;
            cur = *(int *)((u8 *)cur + linkOff);
        }
        objListAdd(&lbl_803DCB7C, prev, (int)obj);
    }
}

void Obj_RemoveFromUpdateList(u8 *obj) {
    if (((GameObject *)obj)->objectFlags & 0x10) {
        objList_remove(&lbl_803DCB7C, obj);
    }
}

void *Obj_GetPlayerObject(void) {
    int count;
    void **objs = (void **)ObjGroup_GetObjects(0, &count);
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
    ObjAnimComponent *objAnim;

    objAnim = (ObjAnimComponent *)obj;
    if (idx == objAnim->bankIndex) {
        return;
    }
    if (idx < 0) {
        idx = 0;
    } else {
        int max = objAnim->modelInstance->modelCount;
        if (idx >= max) {
            idx = max - 1;
        }
    }
    objAnim->bankIndex = idx;
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
    void **objs = (void **)ObjGroup_GetObjects(1, &count);
    if (count != 0) {
        return objs[0];
    }
    return NULL;
}

ObjListObject *ObjList_FindObjectById(u32 objectId) {
    ObjListObjectDef *def;
    ObjListObject *obj;
    int i;
    int count = lbl_803DCB84;
    ObjListObject **arr = lbl_803DCB88;
    for (i = 0; i < count; i++) {
        obj = arr[i];
        def = obj->def;
        if (def != NULL && def->objectId == objectId) {
            return obj;
        }
    }
    return NULL;
}

#pragma dont_inline on

#pragma dont_inline reset

#pragma pop

typedef f32 Mtx[3][4];

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

extern f32 lbl_803DE890;

#pragma dont_inline on
void Obj_TransformLocalPointByWorldMatrix(u8 *obj, f32 *src, f32 *dst, u8 flag) {
    f32 savedZ;
    f32 mtx[16];
    if (flag) {
        savedZ = ((GameObject *)obj)->anim.rootMotionScale;
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803DE890;
    }
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    PSMTXMultVec(mtx, src, dst);
    if (flag) {
        ((GameObject *)obj)->anim.rootMotionScale = savedZ;
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
    union { f32 m[16]; f64 a8; } rotU;
    f32 transposed[16];
#define rotMtx rotU.m

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
    {
        struct WLPVec3 { int x, y, z; };
        *(struct WLPVec3 *)out = *(struct WLPVec3 *)rotated;
    }
#undef rotMtx
}

extern void PSMTXConcat(f32 *a, f32 *b, f32 *ab);

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop


#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma peephole reset


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
    ((GameObject *)obj)->anim.localPosX += dx;
    ((GameObject *)obj)->anim.localPosY += dy;
    ((GameObject *)obj)->anim.localPosZ += dz;
    ObjGroup_GetObjects(0, &n);
    return 0;
}

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
    src = *(u8 **)((u8 *)((GameObject *)obj)->anim.modelInstance + 0x40);
    idx = ((GameObject *)obj)->unkE4;
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

extern f32 lbl_803DE8B8;

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma dont_inline on

#pragma dont_inline reset

int objApplyVelocity(u8 *obj) {
    ((GameObject *)obj)->anim.localPosX += timeDelta * (lbl_803DE8B8 * (((GameObject *)obj)->unkFC + ((GameObject *)obj)->anim.velocityX));
    ((GameObject *)obj)->anim.localPosY += timeDelta * (lbl_803DE8B8 * (((GameObject *)obj)->unk100 + ((GameObject *)obj)->anim.velocityY));
    ((GameObject *)obj)->anim.localPosZ += timeDelta * (lbl_803DE8B8 * (((GameObject *)obj)->unk104 + ((GameObject *)obj)->anim.velocityZ));
    return 1;
}

void Obj_ApplyPendingParentLinks(void) {
    int i;
    for (i = 0; i < lbl_803DCB84; i++) {
        u8 *obj = ((u8 **)lbl_803DCB88)[i];
        obj[0xaf] &= ~7;
        if (((GameObject *)obj)->unkC0 != NULL) {
            if (((GameObject *)obj)->anim.parent == NULL &&
                *(void **)((u8 *)((GameObject *)obj)->unkC0 + 0x30) != NULL) {
                ((GameObject *)obj)->anim.parent = *(void **)((u8 *)((GameObject *)obj)->unkC0 + 0x30);
            }
            ((GameObject *)obj)->unkC0 = NULL;
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
    p += ((GameObject *)obj)->unkE4 * 5;
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
    void *obj;
    int type;
    int objF30;
    objF30 = *(int *)(src + 0x30);
    type = *(s8 *)(src + 0xac);
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


#pragma push
#pragma scheduling off
#pragma peephole off

extern void objLoadPlayerFromSave(u8 *obj);

void Obj_RunInitCallback(u8 *obj, int cb, int unused) {
    s16 mode = ((GameObject *)obj)->anim.seqId;
    if (mode == 0x1f || mode == 0) {
        objLoadPlayerFromSave(obj);
    } else {
        int *p = (int *)((GameObject *)obj)->anim.dll;
        if (p != NULL) {
            int fn = ((int *)*p)[1];
            if (fn != -1 && (void *)fn != NULL) {
                ((void (*)(u8 *))fn)(obj);
            }
        }
    }
    {
        ObjModelState *modelState = ((GameObject *)obj)->anim.modelState;
        if (modelState != NULL) {
            modelState->flags |= OBJ_MODEL_STATE_SHADOW_INIT_CALLBACK_RAN;
        }
    }
    {
        f32 v;
        ((GameObject *)obj)->anim.previousLocalPosX = ((GameObject *)obj)->anim.localPosX;
        ((GameObject *)obj)->anim.previousLocalPosY = ((GameObject *)obj)->anim.localPosY;
        ((GameObject *)obj)->anim.previousLocalPosZ = ((GameObject *)obj)->anim.localPosZ;
        ((GameObject *)obj)->anim.previousWorldPosX = ((GameObject *)obj)->anim.localPosX;
        ((GameObject *)obj)->anim.previousWorldPosY = ((GameObject *)obj)->anim.localPosY;
        ((GameObject *)obj)->anim.previousWorldPosZ = ((GameObject *)obj)->anim.localPosZ;
        v = lbl_803DE88C;
        ((GameObject *)obj)->unkFC = v;
        ((GameObject *)obj)->unk100 = v;
        ((GameObject *)obj)->unk104 = v;
    }
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void objGetWeaponDa(u8 *obj, int objType, ObjWeaponDaTable *weaponDaTable, int key, u8 load) {
    int i;
    s16 *tbl;
    s16 da2;

    tbl = ((GameObject *)obj)->anim.modelInstance->weaponDaTable;
    weaponDaTable->byteCount = 0;
    if (tbl == NULL) {
        return;
    }
    i = 0;
    while (tbl[i] != -1) {
        if (tbl[i] == key) {
            da2 = tbl[i + 1];
            weaponDaTable->byteCount = tbl[i + 2];
            if (weaponDaTable->byteCount > 0x800) {
                weaponDaTable->byteCount = 0x800;
            }
            if (load) {
                getTabEntry(weaponDaTable->entries, 0x34, da2, weaponDaTable->byteCount);
            } else {
                fileLoadToBufferOffset(0x34, weaponDaTable->entries, da2,
                                       weaponDaTable->byteCount);
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
void ObjAnim_LoadMoveEvents(u8 *obj, int dummy, ObjAnimEventTable *eventTable, u32 moveId, u8 load) {
    int i;
    s16 *tbl;
    s16 da2;

    tbl = ((GameObject *)obj)->anim.modelInstance->eventMoveTable;
    eventTable->byteCount = 0;
    if (tbl == NULL) {
        return;
    }
    i = 0;
    while (tbl[i] != -1) {
        if (tbl[i] == moveId) {
            da2 = tbl[i + 1];
            eventTable->byteCount = tbl[i + 2];
            if (eventTable->byteCount > 0x50) {
                eventTable->byteCount = 0x50;
            }
            if (load == 0) {
                getTabEntry(eventTable->entries, 0x40, da2, eventTable->byteCount);
            } else {
                fileLoadToBufferOffset(0x40, eventTable->entries, da2, eventTable->byteCount);
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

    if (((GameObject *)obj)->anim.parent == NULL) {
        ((GameObject *)obj)->anim.localPosX -= playerMapOffsetX;
        ((GameObject *)obj)->anim.localPosZ -= playerMapOffsetZ;
    }
    transform.x = -((GameObject *)obj)->anim.localPosX;
    transform.y = -((GameObject *)obj)->anim.localPosY;
    transform.z = -((GameObject *)obj)->anim.localPosZ;
    transform.rotX = -((GameObject *)obj)->anim.rotX;
    transform.rotY = -((GameObject *)obj)->anim.rotY;
    transform.rotZ = -((GameObject *)obj)->anim.rotZ;
    transform.scale = lbl_803DE890;
    mtxRotateByVec3s(rotMtx, &transform);
    mtx44Transpose(rotMtx, out);
    if (((GameObject *)obj)->anim.parent == NULL) {
        ((GameObject *)obj)->anim.localPosX += playerMapOffsetX;
        ((GameObject *)obj)->anim.localPosZ += playerMapOffsetZ;
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
            if (((ObjAnimComponent *)arr[i])->modelInstance->flags & 1) {
                i++;
            } else {
                stop = -1;
            }
        }
        stop = 0;
        while (j >= 0 && stop == 0) {
            if (((ObjAnimComponent *)arr[j])->modelInstance->flags & 1) {
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

    if (((GameObject *)obj)->anim.parent == NULL) {
        ((GameObject *)obj)->anim.localPosX -= playerMapOffsetX;
        ((GameObject *)obj)->anim.localPosZ -= playerMapOffsetZ;
    }
    if ((u8)flags != 0) {
        savedZ = ((GameObject *)obj)->anim.rootMotionScale;
        if ((((GameObject *)obj)->objectFlags & 0x8) == 0) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803DE890;
        }
    }
    setMatrixFromObjectTransposed(obj, mtx);
    if ((u8)flags != 0) {
        ((GameObject *)obj)->anim.rootMotionScale = savedZ;
    }
    parent = ((GameObject *)obj)->anim.parent;
    if (parent == NULL) {
        ((GameObject *)obj)->anim.localPosX += playerMapOffsetX;
        ((GameObject *)obj)->anim.localPosZ += playerMapOffsetZ;
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
    ObjHitReactState *hitReactState;
    u8 pad58[0x4];
    ObjWeaponDaTable *weaponDaTable;
    ObjAnimEventTable *objAnimEventTable;
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
    ObjModelInstance *modelDef;
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
    modelDef = (ObjModelInstance *)def;
    tmpl.f44 = *(s16 *)(def + 0x52);
    tmpl.scale = modelDef->rootMotionScaleBase;
    tmpl.flags06 = 2;
    if (modelDef->flags & 0x80) {
        tmpl.flags06 = tmpl.flags06 | 0x80;
    }
    if (modelDef->flags & 0x40000) {
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
    if (modelDef->flags & 0x20) {
        flags29 = fnFlags & ~1;
    } else {
        flags29 = fnFlags | 1;
    }
    if (modelDef->shadowType != 0) {
        flags29 |= 2;
    } else {
        flags29 &= ~2;
    }
    if (modelDef->shadowType == 3) {
        flags29 |= 0x8000;
    }
    if (modelDef->flags & 1) {
        flags29 |= 0x200;
    }
    total = 0;
    i = 0;
    count = modelDef->modelCount;
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
    modelDef->flags |= 0x800000LL;
    i = 0;
    obj->f108 = 0;
    if (flags29 & 0x400) {
        idx = (flags29 >> 0xb) & 0xf;
        if (idx < count) {
            obj->models[idx] = (u8 *)obj + base + offsets[idx];
            ObjModel_LoadAnimData(models[idx], flags29, (int)obj->models[idx]);
            if (!(*(u16 *)(*(u8 **)obj->models[idx] + 2) & 0x8000)) {
                modelDef->flags &= ~0x800000LL;
            }
            ObjModel_LoadRenderOpTextures(obj->models[idx], (int)obj);
            modelInitBones(obj->scale, obj->models[idx]);
            if (((ObjModelInstance *)obj->def)->flags & 0x800) {
                ObjModel_SetRenderCallback(obj->models[idx], objCallback_80074d04);
            } else {
                cb = modelDef->renderFlags;
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
                modelDef->flags &= ~0x800000LL;
            }
            ObjModel_LoadRenderOpTextures(obj->models[i], (int)obj);
            modelInitBones(obj->scale, obj->models[i]);
            if (((ObjModelInstance *)obj->def)->flags & 0x800) {
                ObjModel_SetRenderCallback(obj->models[i], objCallback_80074d04);
            } else {
                cb = modelDef->renderFlags;
                if (cb & 1) {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80073d04);
                } else if (cb & 0x80) {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80074518);
                }
            }
        }
    }
    cursor = roundUpTo4((int)obj->models + count * 4);
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
    if ((flags29 & 0x40) || (((ObjModelInstance *)obj->def)->flags & 0x400000)) {
        seq2 = obj->seqId;
        tmp = roundUpTo4(cursor);
        obj->objAnimEventTable = (ObjAnimEventTable *)tmp;
        cursor = roundUpTo8(tmp + 8);
        obj->objAnimEventTable->entries = (s16 *)cursor;
        ObjAnim_LoadMoveEvents((u8 *)obj, seq2, obj->objAnimEventTable, 0, 1);
        cursor += 0x50;
    }
    if ((flags29 & 0x100) && *(void **)obj->models != NULL) {
        tmp = roundUpTo4(cursor);
        obj->weaponDaTable = (ObjWeaponDaTable *)tmp;
        cursor = roundUpTo8(tmp + 8);
        obj->weaponDaTable->entries = (s16 *)cursor;
        cursor += 0x800;
    }
    if ((flags29 & 2) && modelDef->shadowType != 0) {
        cursor = shadowInit(obj, cursor, 0);
    }
    max = lbl_803DE8CC;
    i = 0;
    for (; i < count; i++) {
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
        cursor = ObjHits_AllocObjectState((int)obj, cursor);
        if (modelDef->primaryHitboxShapeFlags & 8) {
            cursor = ObjHitbox_AllocRotatedBounds((ObjHitbox *)obj, cursor);
        }
    }
    if (modelDef->jointCount != 0) {
        tmp = roundUpTo4(cursor);
        obj->f6c = tmp;
        cursor = tmp + modelDef->jointCount * 0x12;
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
        cursor = ObjHitReact_InitState(obj->seqId, (ObjAnimBank *)*(u8 **)obj->models,
                                       obj->hitReactState, tmp, (ObjAnimComponent *)obj);
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
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern void *gTitleMenuControlInterface;
extern ExpgfxInterface **gExpgfxInterface;
extern void *gModgfxInterface;
extern WaterfxInterface **gWaterfxInterface;
extern MapEventInterface **gMapEventInterface;

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
    ObjAnimComponent *objAnim = (ObjAnimComponent *)objp;
    int defs[46];
    void (*fp)(u8 *, int);
    void (*cb)(u8 *);
    void (*cb2)(u8 *, int, int, int, int);
    int i;
    int count;
    int n;
    u8 *o;
    int *bp;
    void *curTex;
    void *tex;
    void *shadowRenderResource;
    ObjModelState *modelState;
    s8 modelCount;
    int group;
    int type;

    if (((GameObject *)obj)->unkE9 != 0) {
        ObjContact_RemoveObjectCallbacks((int)obj);
    }
    switch (((GameObject *)obj)->anim.seqId) {
    case 0:
    case 0x1f:
        fn_802B4DE0(obj, flag);
        break;
    default:
        if (((GameObject *)obj)->anim.dll != NULL) {
            fp = (void (*)(u8 *, int))*(int *)(*(int *)&((GameObject *)obj)->anim.dll + 0x14);
            if (fp != NULL) {
                fp(obj, flag);
            }
            Resource_Release(((GameObject *)obj)->anim.dll);
            *(int *)&((GameObject *)obj)->anim.dll = 0;
        }
        break;
    }
    (*(void (**)(u8 *))(*(int *)gTitleMenuControlInterface + 0x48))(obj);
    (*gExpgfxInterface)->freeOwner3((u32)obj);
    if (((ObjAnimComponent *)obj)->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) {
        ObjGroup_RemoveObject((uint)obj, 6);
        if (flag == 0) {
            count = 0;
            for (i = 0; i < lbl_803DCB84; i++) {
                o = ((u8 **)lbl_803DCB88)[i];
                if (((GameObject *)o)->anim.parent == obj) {
                    *(int *)&((GameObject *)o)->anim.parent = 0;
                    if (*(int *)&((GameObject *)o)->anim.placementData != 0) {
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
    if (flag == 0 && ((GameObject *)obj)->anim.classId == 0x10) {
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
    if (((ObjAnimComponent *)obj)->modelInstance->group8RegistrationCount > 0) {
        ObjGroup_RemoveObject((uint)obj, 8);
    }
    modelState = objAnim->modelState;
    if (modelState != NULL) {
        if (objAnim->modelInstance->shadowType == 1) {
            setShadowFlag_803db658(1);
        }
        if (modelState->shadowTexture != NULL) {
            curTex = textureFn_8006c5c4();
            tex = modelState->shadowTexture;
            if (tex != curTex) {
                if ((objAnim->modelInstance->renderFlags & 4) == 0) {
                    textureFree(tex);
                } else {
                    mm_free(tex);
                }
            }
        }
        if (modelState->shadowWorkBuffer != NULL) {
            mm_free(modelState->shadowWorkBuffer);
        }
        shadowRenderResource = modelState->shadowRenderResource;
        if (shadowRenderResource != NULL && shadowRenderResource != (void *)-1) {
            mm_free(shadowRenderResource);
        }
    }
    if (*(int *)&((GameObject *)obj)->unkDC != 0) {
        mm_free(((GameObject *)obj)->unkDC);
        *(int *)&((GameObject *)obj)->unkDC = 0;
    }
    modelCount = objAnim->modelInstance->modelCount;
    for (i = 0; i < modelCount; i++) {
        if (objAnim->banks[i] != NULL) {
            ObjModel_Release((u8 *)objAnim->banks[i]);
        }
    }
    if (((GameObject *)obj)->unkE5 & 1) {
        *(u16 *)&((GameObject *)obj)->unkE6 = 0;
        ((GameObject *)obj)->unkE5 = ((GameObject *)obj)->unkE5 & ~1;
        ((GameObject *)obj)->unkF0 = 0;
        ObjModel_ClearRenderAttachment((u8 *)objAnim->banks[objAnim->bankIndex]);
        cb2 = (void (*)(u8 *, int, int, int, int))*(int *)(*(int *)lbl_803DCAB4 + 0xc);
        cb2(obj, 0x7fb, 0, 0x50, 0);
        cb2 = (void (*)(u8 *, int, int, int, int))*(int *)(*(int *)lbl_803DCAB4 + 0xc);
        cb2(obj, 0x7fc, 0, 0x32, 0);
    }
    if (((GameObject *)obj)->unkE5 & 2) {
        Obj_ClearModelColorFadeRecursive(obj);
    }
    group = ObjGroup_GetObjectGroup((uint)obj);
    if (group != 0) {
        ObjGroup_RemoveObject((uint)obj, group - 1);
    }
    type = ((GameObject *)obj)->anim.defId;
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
    if (((GameObject *)obj)->unkB4 >= 0) {
        if (flag == 0) {
            (*gObjectTriggerInterface)->endSequence(((GameObject *)obj)->unkB4);
        }
        ((GameObject *)obj)->unkB4 = 0xffff;
    }
    if ((*(u16 *)&((GameObject *)obj)->anim.flags & 0x2000) && *(int *)&((GameObject *)obj)->anim.placementData != 0) {
        mm_free(((GameObject *)obj)->anim.placementData);
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
    ObjAnimComponent *object;
    ObjHitsPriorityState *hitState;
    ObjHitsPriorityState *childHitState;
    u8 *t;
    void (*cb)(u8 *, int, int, int, int);
    void (*cb2)(u8 *);

    object = (ObjAnimComponent *)obj;
    if (((GameObject *)obj)->objectFlags & 0x40) {
        return;
    }
    if (lbl_803DCB78 & 1) {
        switch (object->seqId) {
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
            cb2 = (void (*)(u8 *))*(int *)(**object->dll + 8);
            cb2(obj);
            break;
        }
        return;
    }
    if (((GameObject *)obj)->unkE5 != 0 && *(int *)&((GameObject *)obj)->unkC4 == 0 && (((GameObject *)obj)->unkE5 & 2)) {
        Obj_TickModelColorFadeRecursive(obj);
    }
    if (*(int *)&((GameObject *)obj)->unkC0 != 0) {
        if (*(int *)&((GameObject *)obj)->unkC8 != 0) {
            t = *(u8 **)((u8 *)((GameObject *)obj)->unkC8 + 0x54);
            if (t != 0) {
                childHitState = (ObjHitsPriorityState *)t;
                childHitState->lastHitObject = 0;
                childHitState->priorityHitCount = 0;
            }
        }
        hitState = (ObjHitsPriorityState *)object->hitReactState;
        if (hitState == NULL) {
            return;
        }
        hitState->lastHitObject = 0;
        hitState->priorityHitCount = 0;
        return;
    }
    if ((object->flags & 8) == 0) {
        object->previousLocalPosX = object->localPosX;
        object->previousLocalPosY = object->localPosY;
        object->previousLocalPosZ = object->localPosZ;
        object->previousWorldPosX = object->worldPosX;
        object->previousWorldPosY = object->worldPosY;
        object->previousWorldPosZ = object->worldPosZ;
    }
    ((GameObject *)obj)->unkFC = object->velocityX;
    ((GameObject *)obj)->unk100 = object->velocityY;
    ((GameObject *)obj)->unk104 = object->velocityZ;
    if (((GameObject *)obj)->unkE5 != 0 && *(int *)&((GameObject *)obj)->unkC4 == 0 && (((GameObject *)obj)->unkE5 & 1)) {
        ((GameObject *)obj)->unkE6 = (s16)(int)((f32)((GameObject *)obj)->unkE6 - timeDelta);
        if (((GameObject *)obj)->unkE6 <= 0) {
            ((GameObject *)obj)->unkE6 = 0;
            ((GameObject *)obj)->unkE5 &= ~1;
            ((GameObject *)obj)->unkF0 = 0;
            ObjModel_ClearRenderAttachment((u8 *)object->banks[object->bankIndex]);
            cb = (void (*)(u8 *, int, int, int, int))*(int *)(*lbl_803DCAB4 + 0xc);
            cb(obj, 0x7fb, 0, 0x50, 0);
            cb = (void (*)(u8 *, int, int, int, int))*(int *)(*lbl_803DCAB4 + 0xc);
            cb(obj, 0x7fc, 0, 0x32, 0);
            Sfx_PlayFromObject(obj, 0x47b);
        }
    }
    if ((((GameObject *)obj)->objectFlags & 0x8000) == 0) {
        switch (object->seqId) {
        case 0:
        case 0x1f:
            playerUpdate(obj);
            break;
        default:
            if (object->dll == NULL) {
                goto skip;
            }
            cb2 = (void (*)(u8 *))*(int *)(**object->dll + 8);
            if (cb2 != 0) {
                cb2(obj);
            }
            break;
        }
        Obj_GetWorldPosition(obj, &object->worldPosX, &object->worldPosY, &object->worldPosZ);
    }
skip:
    hitState = (ObjHitsPriorityState *)object->hitReactState;
    if (hitState != NULL) {
        if (*(int *)&((GameObject *)obj)->unkC8 != 0) {
            t = *(u8 **)((u8 *)((GameObject *)obj)->unkC8 + 0x54);
            if (t != 0) {
                childHitState = (ObjHitsPriorityState *)t;
                childHitState->lastHitObject = 0;
                childHitState->priorityHitCount = 0;
            }
        }
        hitState->lastHitObject = 0;
        hitState->priorityHitCount = 0;
    }
    if (*(int *)(obj + 0x58) != 0) {
        *(u8 *)(*(u8 **)(obj + 0x58) + 0x10f) = 0;
    }
}
#pragma dont_inline reset
#pragma pop

extern void objFn_80065604(void);
extern void Obj_UpdateModelBlendStates(void);
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
    while (obj != 0 && ((ObjAnimComponent *)obj)->activeHitboxMode == 0x64) {
        Obj_UpdateObject((u8 *)obj);
        obj = *(int *)(obj + off);
    }
    while (obj != 0 &&
           (((ObjAnimComponent *)obj)->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE)) {
        Obj_UpdateObject((u8 *)obj);
        *(s8 *)(obj + 0x35) = (s8)Obj_BuildTransformMatrixSlot(obj);
        obj = *(int *)(obj + off);
    }
    if (timeStop == 0) {
        ObjHitReact_UpdateResetObjects();
    }
    for (; obj != 0; obj = *(int *)(obj + off)) {
        t = (void *)((GameObject *)obj)->anim.hitReactState;
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
    if (obj2 != 0 && ((GameObject *)obj2)->unkC8 != 0) {
        *(int *)((u8 *)((GameObject *)obj2)->unkC8 + 0x30) = *(int *)&((GameObject *)obj2)->anim.parent;
        Obj_UpdateObject(((GameObject *)obj2)->unkC8);
    }
    if (timeStop == 0) {
        ObjHits_Update(lbl_803DCB84);
        obj = *(int *)((u8 *)&lbl_803DCB7C + 4);
        for (; obj != 0; obj = *(int *)(obj + off)) {
            if ((((GameObject *)obj)->objectFlags & 0x2000) == 0) {
                switch (((GameObject *)obj)->anim.seqId) {
                case 0:
                case 0x1f:
                    playerDoHitDetection(obj);
                    break;
                default:
                    if (((GameObject *)obj)->anim.dll == 0) {
                        goto next;
                    }
                    cb = (void (*)(int))*(int *)((u8 *)*((GameObject *)obj)->anim.dll + 0xc);
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
        if (obj2 != 0 && ((GameObject *)obj2)->unkC8 != 0) {
            *(int *)((u8 *)((GameObject *)obj2)->unkC8 + 0x30) = *(int *)&((GameObject *)obj2)->anim.parent;
            child = *(int *)&((GameObject *)obj2)->unkC8;
            if ((((GameObject *)child)->objectFlags & 0x2000) == 0) {
                switch (((GameObject *)child)->anim.seqId) {
                case 0:
                case 0x1f:
                    playerDoHitDetection(child);
                    break;
                default:
                    if (((GameObject *)child)->anim.dll == 0) {
                        goto done;
                    }
                    cb = (void (*)(int))*(int *)((u8 *)*((GameObject *)child)->anim.dll + 0xc);
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
        (*gWaterfxInterface)->runFrame(framesThisStep);
    }
    if ((f & 2) == 0) {
        ((ModgfxInterface *)*(void **)gModgfxInterface)->updateActiveEffects(0, 0, 0);
        (*gExpgfxInterface)->updateFrameState(0, framesThisStep, 0, 0);
    }
    if (timeStop == 0) {
        ObjHits_TickPriorityHitCooldowns();
        (*gObjectTriggerInterface)->run();
        (*gObjectTriggerInterface)->updateCamera();
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
extern f32 mathSinf(f32);
extern f32 mathCosf(f32);
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

    base = (u8 *)(int)&lbl_802CABF8;
    mapType = getCurMapType();
    if (mapType == 2 || mapType == 3) {
        OSReport((char *)(base + 0x70));
        Obj_ResetObjectSystem();
    } else {
        playerNo = (*gMapEventInterface)->getPlayerNo();
        pos = (f32 *)(*gMapEventInterface)->getWarpPos();
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
                    OSReport((char *)(base + 0x5c), *(int *)&((GameObject *)obj)->anim.modelInstance + 0x91);
                }
            }
        }
        *(f32 *)(base + 8) = lbl_803DE8BC * mathSinf((lbl_803DE8C0 * (f32)(*(s8 *)((u8 *)pos + 0xc) << 8)) / lbl_803DE8C4) + x;
        *(f32 *)(base + 0xc) = lbl_803DE8C8 + y;
        *(f32 *)(base + 0x10) = lbl_803DE8BC * mathCosf((lbl_803DE8C0 * (f32)(*(s8 *)((u8 *)pos + 0xc) << 8)) / lbl_803DE8C4) + z;
        uiDll = getCurUiDll();
        if ((u32)(uiDll - 2) <= 4 || uiDll == 7) {
            (*(void (**)(u8 *, f32, f32, f32))(*(int *)gCameraInterface + 4))(obj, *(f32 *)(base + 8), *(f32 *)(base + 0xc), *(f32 *)(base + 0x10));
            (*(void (**)(int, int, int, int, int, int, int))(*(int *)gCameraInterface + 0x1c))(0x57, 0, 3, 0, 0, 0, 0);
            (*(void (**)(u8 *, int))(*(int *)gCameraInterface + 0x28))(obj, 0);
            (*(void (**)(int))(*(int *)gCameraInterface + 8))(1);
        } else {
            (*(void (**)(u8 *, f32, f32, f32))(*(int *)gCameraInterface + 4))(obj, *(f32 *)(base + 8), *(f32 *)(base + 0xc), *(f32 *)(base + 0x10));
            (*(void (**)(int, int, int, int, u8 *, int, int))(*(int *)gCameraInterface + 0x1c))(0x42, 0, 0, 0x20, (u8 *)(int)&lbl_802CABF8, 0, 0xff);
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
    ObjAnimComponent *objAnim;
    ObjAnimComponent *childAnim;
    u8 *obj;
    int j;
    int i;
    int k;
    int ioff;
    u8 *walker;
    u8 *child;
    u8 *m;
    u8 *c0;
    u8 *bp;
    ObjModelState *modelState;

    i = 0;
    ioff = 0;
    for (; i < lbl_803DCB84; i++) {
        obj = *(u8 **)((int)lbl_803DCB88 + ioff);
        objAnim = (ObjAnimComponent *)obj;
        if (obj != 0 && objAnim->modelInstance != NULL) {
            modelState = objAnim->modelState;
            if (modelState != NULL) {
                modelState->shadowCastSlot = NULL;
            }
            j = 0;
            for (; j < objAnim->modelInstance->modelCount; j++) {
                m = (u8 *)objAnim->banks[j];
                if (m != 0) {
                    *(u16 *)(m + 0x18) &= ~8;
                    if (*(u8 *)(*(u8 **)m + 0xf9) != 0) {
                        ObjModel_AdvanceBlendChannels(m, timeDelta);
                    }
                }
            }
            j = 0;
            walker = obj;
            for (; j < ((GameObject *)obj)->unkEB; j++) {
                child = *(u8 **)(walker + 0xc8);
                childAnim = (ObjAnimComponent *)child;
                if (child != 0 && childAnim->modelInstance != NULL) {
                    k = 0;
                    for (; k < childAnim->modelInstance->modelCount; k++) {
                        m = (u8 *)childAnim->banks[k];
                        if (m != 0) {
                            *(u16 *)(m + 0x18) &= ~8;
                            if (*(u8 *)(*(u8 **)m + 0xf9) != 0) {
                                c0 = ((GameObject *)child)->unkC0;
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
    ObjAnimComponent *object;
    ObjHitsPriorityState *hitState;
    int id;
    int prev;
    int cur;
    int off;

    object = (ObjAnimComponent *)obj;
    if (object->parent != NULL) {
        ((void (*)(f32, f32, f32, f32 *, f32 *, f32 *, void *))Obj_TransformLocalPointToWorld)(
            object->localPosX, object->localPosY, object->localPosZ, &object->worldPosX,
            &object->worldPosY, &object->worldPosZ, object->parent);
    } else {
        object->worldPosX = object->localPosX;
        object->worldPosY = object->localPosY;
        object->worldPosZ = object->localPosZ;
    }
    object->previousWorldPosX = object->worldPosX;
    object->previousWorldPosY = object->worldPosY;
    object->previousWorldPosZ = object->worldPosZ;
    object->previousLocalPosX = object->localPosX;
    object->previousLocalPosY = object->localPosY;
    object->previousLocalPosZ = object->localPosZ;
    Obj_RunInitCallback(obj, (int)object->placementData, 0);
    hitState = (ObjHitsPriorityState *)object->hitReactState;
    if (hitState != NULL) {
        hitState->localPosX = object->localPosX;
        hitState->localPosY = object->localPosY;
        hitState->localPosZ = object->localPosZ;
        hitState->worldPosX = object->localPosX;
        hitState->worldPosY = object->localPosY;
        hitState->worldPosZ = object->localPosZ;
    }
    id = object->modelInstance->mapLoadObjectId;
    if (id > -1) {
        mapLoadForObject(id, obj);
    }
    if (object->modelInstance->flags & 0x40) {
        ObjGroup_AddObject((uint)obj, 6);
        if (object->activeHitboxMode != 0x5a && (object->modelInstance->flags & 0x40)) {
            object->activeHitboxMode = 0x5a;
        }
    } else {
        if (object->activeHitboxMode == 0) {
            object->activeHitboxMode = 0x50;
        }
    }
    if (flags & 1) {
        ((GameObject *)obj)->objectFlags |= 0x10;
        ((u8 **)lbl_803DCB88)[lbl_803DCB84++] = obj;
        if (((GameObject *)obj)->objectFlags & 0x10) {
            prev = 0;
            cur = *(int *)((u8 *)&lbl_803DCB7C + 4);
            off = *(s16 *)((u8 *)&lbl_803DCB7C + 2);
            while (cur != 0 && object->activeHitboxMode < *(s8 *)(cur + 0xae)) {
                prev = cur;
                cur = *(int *)(cur + off);
            }
            objListAdd(&lbl_803DCB7C, prev, (int)obj);
        }
    }
    if (object->modelInstance->group8RegistrationCount > 0) {
        ObjGroup_AddObject((uint)obj, 8);
    }
    if (object->modelInstance->flags & 1) {
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

    if (((GameObject *)obj)->objectFlags & 0x40) {
        return;
    }
    Sfx_RemoveLoopedObjectSoundForObject(obj);
    Sfx_StopObjectChannel(obj, 0x7f);
    if (((GameObject *)obj)->objectFlags & 0x10) {
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
        if (((GameObject *)obj)->objectFlags & 0x10) {
            objList_remove(&lbl_803DCB7C, obj);
        }
        lbl_803DCBC4 = 0;
    }
    for (i = 0; i < lbl_803DCB94; i++) {
    }
    ((GameObject *)obj)->objectFlags |= 0x40;
    if (((GameObject *)obj)->unkEA != 0) {
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
    ObjModelInstance *modelDef;
    int size;
    int r;
    int extra;
    int (*cb)(void *, int);

    modelDef = (ObjModelInstance *)def;
    size = modelDef->modelCount * 4 + 0x10c;
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
    if ((flags & 0x40) || (modelDef->flags & 0x400000)) {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x50;
    }
    if (flags & 0x100) {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x800;
    }
    if ((flags & 2) && modelDef->shadowType != 0) {
        size = roundUpTo4(size) + 0x44;
    }
    if (*(u8 *)(def + 0x61) != 0) {
        size = roundUpTo4(size) + 0xb8;
        if (modelDef->primaryHitboxShapeFlags & 8) {
            size += 0x110;
        }
    }
    if (modelDef->jointCount != 0) {
        r = roundUpTo4(size);
        size = r + modelDef->jointCount * 0x12;
    }
    if (*(u8 *)(def + 0x59) != 0) {
        r = roundUpTo4(size);
        size = r + *(u8 *)(def + 0x59) * 0x10;
    }
    if (*(u8 *)(def + 0x72) != 0) {
        r = roundUpTo4(size);
        size = r + *(u8 *)(def + 0x72) * 0x18;
    }
    if (*(u8 *)(def + 0x61) != 0 && *(u8 *)(def + 0x66) != 0) {
        size = roundUpTo8(size) + 0x12c;
    }
    if (*(u8 *)(def + 0x72) != 0) {
        r = roundUpTo4(size);
        size = r + *(u8 *)(def + 0x72) * 5;
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
    f32 m2[12];
    f32 rot[12];
    f32 vecA[3];
    f32 vecB[3];
    f32 cross[3];
    f32 len;
    f32 dz;
    f32 dx;
    f32 denom;
    f32 sum;

    denom = lbl_803DE888 * ((GameObject *)obj)->anim.hitboxScale;
    denom *= ((GameObject *)obj)->anim.rootMotionScale;
    dx = ((((GameObject *)obj)->anim.previousLocalPosZ - lbl_803DCECC) - (((GameObject *)obj)->anim.localPosZ - playerMapOffsetZ)) / denom;
    dz = ((((GameObject *)obj)->anim.localPosX - lbl_803DCED0) - (((GameObject *)obj)->anim.previousLocalPosX - playerMapOffsetX)) / denom;
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

#pragma dont_inline off

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop
