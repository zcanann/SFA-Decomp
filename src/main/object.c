#include "main/dll/objpathtransform_struct.h"
#include "main/dll/objmodel_types.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/engine_8001746C_phantoms.h"
#include "main/mapEvent.h"
#include "main/object_transform.h"
#include "main/objseq.h"
#include "main/objlib.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/gameplay_runtime.h"
#include "main/mm.h"
#include "main/texture.h"
#include "main/camera.h"
#include "main/sfa_extern_decls.h"
#include "main/object.h"
#include "main/track_dolphin.h"
#include "main/audio/sfx_trigger_ids.h"

#define OBJECT_OBJFLAG_HITDETECT_DISABLED 0x2000
#define OBJECT_OBJFLAG_UPDATE_DISABLED 0x8000

/* GameObject::colorFadeFlags bits (freeze / color-fade state machine) */
#define OBJ_COLOR_FADE_FLAG_FROZEN 0x1     /* freeze render attachment active (objIsFrozen) */
#define OBJ_COLOR_FADE_FLAG_ACTIVE 0x2     /* color fade running (objGetFlagsE5_2) */
#define OBJ_COLOR_FADE_FLAG_INCREASING 0x4 /* ping-pong direction: alpha rising */
#define OBJ_COLOR_FADE_FLAG_INFINITE 0x8   /* no frame countdown / never auto-clears */
#define OBJ_COLOR_FADE_FLAG_OVERRIDE 0x10  /* solid color override (not a fade) */

/* GameObject::objectFlags lifecycle bits */
#define OBJECT_FLAG_IN_UPDATE_LIST 0x10 /* registered in gObjList / gObjUpdateList */
#define OBJECT_FLAG_FREED 0x40          /* Obj_FreeObject ran (double-free guard) */

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803DE88C;
extern f32 gObjColorFadeRate;
extern f32 gObjColorFadeAlphaMax;
extern void Obj_BuildWorldTransformMatrix(u8* obj, f32* mtx, int flags);
extern void* memset(void* dst, int val, int n);
extern void PSMTXMultVec(f32 * mtx, f32 * in, f32 * out);
extern void PSMTXMultVecSR(f32 * mtx, f32 * in, f32 * out);
extern void Obj_TransformLocalPointByWorldMatrix(u8* obj, f32* src, f32* dst, u8 flag);
extern void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst);
extern void Obj_BuildInverseWorldTransformMatrix(u8* obj, f32* out);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int getLoadedFileFlags(int);
extern s8 gObjPtrTableCount;
extern int gObjPtrTable[];
extern void objList_remove(void* list, void* item);
extern int gObjTablesBinCount;
extern int* gObjTablesBinIndex;
extern u8* gObjTablesBinData;
extern int gObjUpdateList;
extern f32 sqrtf(f32 x);
extern int gObjCount;
extern void* gObjList;
extern const f32 lbl_803DE890;
extern void mtx44Transpose(f32* src, f32* dst);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * ab);
extern void OSReport(const char* msg, ...);
extern void* memcpy(void* dst, const void* src, int n);
extern const f32 lbl_803DE8B8;
extern void objFreeObjDef(u8* def, int flags);
extern int gObjDeferredFreeCount;
extern void** gObjDeferredFreeList;
extern void Obj_RegisterObject(u8* obj, int b);
extern char sObjSetupObjectLoadingLockedWarning[];
extern char sObjDebugStrings[];
extern void objLoadPlayerFromSave(u8 * obj);
extern s16 gObjPartitionPivot;
extern int gObjSeqToObjIdMax;
extern s16* gObjSeqToObjIdTable;
char sObjUnknownTypeUsingDummyObjectWarning[] = "Warning: Unknown object type '%d/%d romdefno %d', using DummyObject (128)\n";
extern f32 lbl_803DE8CC;
extern f32 lbl_803DE8D0;

extern void modelInitBones(f32 scale, void* model);
extern int shadowInit(void* obj, int cursor, int arg);
extern void debugPrintf(char* fmt, ...);
extern int objCallback_80074d04();
extern int modelCb_80073d04();
extern int modelCb_80074518();
extern int getDataFileSize(int id);
extern void* gTitleMenuControlInterface;
extern void* gModgfxInterface;
extern void fn_802B4DE0(u8* obj, int flag);
extern void Obj_FreeObject(u8* obj);
extern void fn_80059A50(int arg);
extern void* textureFn_8006c5c4(void);
extern u8* gObjFileRefCount;
extern u8* gObjFileBufferTable;
char sObjFreeObjdefError[] = "objFreeObjdef: Error!! (%d)\n";
extern void playerUpdateWhileTimeStopped(u8 * obj);
extern void playerRenderQuakeSpell(void);
extern void playerUpdate(u8 * obj);
extern u32 gObjUpdateFlags;

extern int Obj_BuildTransformMatrixSlot(int obj);
extern void playerDoHitDetection(int obj);

u8 gObjCameraSetupBlock[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0x3C, 0x00, 0x5A, 0x00, 0x55, 0x1E, 0x14,
};
extern s16 gObjPlayerSpawnIdTable[2];
extern f32 lbl_803DE8BC;
extern f32 gObjPi;
extern f32 lbl_803DE8C4;
extern f32 lbl_803DE8C8;
extern float mathSinf(float x);
extern float mathCosf(float x);
extern int getCurUiDll(void);
extern int lbl_803DCB70;
extern void fn_80013B6C(int* p, int n);
extern void AudioStream_StopAll(void);
extern int gObjDefCaptureMode;
extern int lbl_803DCB8C;
extern void mapLoadForObject(int id, void* obj);
char sObjFreeNonExistentObjectWarning[] = "Tried to free non-existent object\n";
extern void* lbl_803DCB90;
extern void* lbl_803DCBC0;
extern int* gObjFileOffsetTable;
extern int gObjFileCount;
extern int loadModLines(int n, s16* out);
extern void intersectModLineBuild(u8 * buf);
extern void PSVECCrossProduct(f32 * a, f32 * b, f32 * out);
extern void PSMTXRotAxisRad(f32* m, f32* axis, f32 angle);
extern f32 lbl_803DCED0;
extern f32 lbl_803DCECC;
void doNothing_afterRenderObject(void)
{
}

void doNothing_beforeRenderObject(void)
{
}

void fn_8002B85C(void)
{
}

void* ObjModel_GetRenderOp(u8* model, int renderOpIndex);

u16 modelFileHeaderGetCullDistance(u8 * modelFile);

void ObjModel_ClearRenderAttachment(u8 * model);

void ObjModel_EnableDefaultRenderCallback(void* obj, u8* model, f32* mtx, int enabled, f32 scale);

void ObjModel_SetRenderCallback(u8* model, void* callback);

#pragma scheduling off
#pragma peephole off
void Obj_SetModelRenderOpAlpha(u8* obj, s8 alpha)
{
    ObjAnimComponent* objAnim;
    ObjModelFileHeaderLite* modelFile;
    int renderOpIndex;
    ObjModelInstanceLite* model;

    objAnim = (ObjAnimComponent*)obj;
    model = (ObjModelInstanceLite*)objAnim->banks[objAnim->bankIndex];
    if (model != NULL)
    {
        modelFile = model->file;
        if (modelFile != NULL)
        {
            for (renderOpIndex = 0; renderOpIndex < modelFile->renderOpCount; renderOpIndex++)
            {
                ((ObjModelRenderOpLite*)ObjModel_GetRenderOp((u8*)modelFile, renderOpIndex))
                    ->alpha = alpha;
            }
        }
    }
}

void Obj_SetModelSlotIndex(u8* obj, int slotIndex)
{
    ((ObjAnimComponent*)obj)->mapEventSlot = slotIndex;
}

void Obj_ClearModelSlotIndex(u8* obj)
{
    ((ObjAnimComponent*)obj)->mapEventSlot = -1;
}

void* Obj_GetActiveModel(u8* obj)
{
    ObjAnimComponent* objAnim;

    objAnim = (ObjAnimComponent*)obj;
    return objAnim->banks[objAnim->bankIndex];
}

void Obj_ClearModelColorFadeRecursive(u8* obj)
{
    u8* childScan;
    int i;

    ((GameObject*)obj)->colorFadeFrames = 0;
    ((GameObject*)obj)->colorFadeFlags &= ~(OBJ_COLOR_FADE_FLAG_ACTIVE | OBJ_COLOR_FADE_FLAG_INCREASING);
    i = 0;
    childScan = obj;
    while (i < ((GameObject*)obj)->childCount)
    {
        Obj_ClearModelColorFadeRecursive(((GameObject*)childScan)->childObjs[i]);
        i++;
    }
}

void Obj_TickModelColorFadeRecursive(u8* obj)
{
    f32 alpha;
    u8* childScan;
    int i;

    if ((((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_INCREASING) != 0)
    {
        alpha = obj[0xef] + gObjColorFadeRate * timeDelta;
    }
    else
    {
        alpha = obj[0xef] - gObjColorFadeRate * timeDelta;
    }

    if (alpha < lbl_803DE88C)
    {
        alpha = -alpha;
        ((GameObject*)obj)->colorFadeFlags ^= OBJ_COLOR_FADE_FLAG_INCREASING;
    }
    else if (alpha > gObjColorFadeAlphaMax)
    {
        alpha = gObjColorFadeAlphaMax - (alpha - gObjColorFadeAlphaMax);
        ((GameObject*)obj)->colorFadeFlags ^= OBJ_COLOR_FADE_FLAG_INCREASING;
    }

    ((GameObject*)obj)->colorFadeAlpha = alpha;
    if ((((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_INFINITE) == 0)
    {
        ((GameObject*)obj)->colorFadeFrames -= framesThisStep;
        if (((GameObject*)obj)->colorFadeFrames <= 0 && ((GameObject*)obj)->ownerObj == NULL)
        {
            Obj_ClearModelColorFadeRecursive(obj);
        }
    }

    i = 0;
    childScan = obj;
    while (i < ((GameObject*)obj)->childCount)
    {
        Obj_TickModelColorFadeRecursive(((GameObject*)childScan)->childObjs[i]);
        i++;
    }
}

#pragma dont_inline on
void Obj_SetModelColorFadeRecursive(u8* obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf)
{
    u8* childScan;
    int i;

    ((GameObject*)obj)->colorFadeFrames = frames;
    ((GameObject*)obj)->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_INCREASING;
    ((GameObject*)obj)->colorFadeFlags |= OBJ_COLOR_FADE_FLAG_ACTIVE;
    obj[0xec] = red;
    obj[0xed] = green;
    obj[0xee] = blue;
    if (frames == 10000)
    {
        ((GameObject*)obj)->colorFadeFlags |= OBJ_COLOR_FADE_FLAG_INFINITE;
    }
    else
    {
        ((GameObject*)obj)->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_INFINITE;
    }
    if (startAtHalf != 0)
    {
        obj[0xef] = 0x7f;
    }
    else
    {
        obj[0xef] = 0;
    }

    i = 0;
    childScan = obj;
    while (i < ((GameObject*)obj)->childCount)
    {
        Obj_SetModelColorFadeRecursive(((GameObject*)childScan)->childObjs[i], frames, red, green, blue, startAtHalf);
        i++;
    }
}

#pragma dont_inline off
void Obj_SetModelColorOverrideRecursive(u8* obj, u8 red, u8 green, u8 blue, u8 alpha, u8 enabled)
{
    u8* childScan;
    int i;

    if (enabled != 0)
    {
        ((GameObject*)obj)->colorFadeFlags |= OBJ_COLOR_FADE_FLAG_OVERRIDE;
        obj[0xec] = red;
        obj[0xed] = green;
        obj[0xee] = blue;
        obj[0xef] = alpha;
    }
    else
    {
        ((GameObject*)obj)->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_OVERRIDE;
    }

    i = 0;
    childScan = obj;
    while (i < ((GameObject*)obj)->childCount)
    {
        Obj_SetModelColorOverrideRecursive(((GameObject*)childScan)->childObjs[i], red, green, blue, alpha, enabled);
        i++;
    }
}

void Obj_ResetModelColorState(u8* obj)
{
    ((GameObject*)obj)->colorFadeFrames = 0;
    ((GameObject*)obj)->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_FROZEN;
    ((GameObject*)obj)->fadeCounter = 0;
    ObjModel_ClearRenderAttachment((u8*)Obj_GetActiveModel(obj));
    (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fb, NULL, 0x50, NULL);
    (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fc, NULL, 0x32, NULL);
}

void Obj_StartModelFadeIn(u8* obj, int frames)
{
    ObjAnimComponent* objAnim;
    f32 mtx[16];
    int fadeLimit;
    s16 objType;

    objAnim = (ObjAnimComponent*)obj;
    fadeLimit = 10;
    objType = ((GameObject*)obj)->anim.classId;
    if (objType == 0x1c || objType == 0x6d || objType == 0x2a)
    {
        fadeLimit = 40;
    }
    if ((((GameObject*)obj)->anim.modelInstance->effectFlags & 1) != 0)
    {
        if (((GameObject*)obj)->fadeCounter < fadeLimit)
        {
            ((GameObject*)obj)->fadeCounter++;
            Obj_SetModelColorFadeRecursive(obj, 0x1e, 0xa0, 0xff, 0xff, 0);
        }
        if (((GameObject*)obj)->fadeCounter == fadeLimit)
        {
            if ((((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE) != 0)
            {
                Obj_ClearModelColorFadeRecursive(obj);
            }
            ((GameObject*)obj)->colorFadeFrames = frames;
            ((GameObject*)obj)->colorFadeFlags = (u8)(((GameObject*)obj)->colorFadeFlags | OBJ_COLOR_FADE_FLAG_FROZEN);
            Obj_BuildWorldTransformMatrix(obj, mtx, 0);
            ((void (*)(u8*, u8*, f32*, int, f32))ObjModel_EnableDefaultRenderCallback)(
                obj, (u8*)objAnim->banks[objAnim->bankIndex], mtx, 1,
                ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale);
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fc, NULL, 0x64, NULL);
        }
    }
}

#pragma scheduling on
#pragma peephole on
int objIsFrozen(u8* obj)
{
    return ((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_FROZEN;
}

int objGetFlagsE5_2(u8* obj)
{
    return ((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE;
}

int roundUpTo32(int x);

#pragma scheduling off
#pragma peephole off
void objSetHintTextIdx(int obj, u16 idx)
{
    if (idx > 4)
    {
        idx = 0;
    }
    ((GameObject*)obj)->paletteIndex = idx;
}

int Obj_IsLoadingLocked(void)
{
    return !(getLoadedFileFlags(0) & 0x100000);
}

void objSetSlot(u8* obj, s8 slot)
{
    if (slot == 0x5a)
    {
        if ((((ObjAnimComponent*)obj)->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) == 0)
        {
            return;
        }
    }
    ((GameObject*)obj)->anim.activeHitboxMode = slot;
}

void fn_8002B758(void* v)
{
    int i;

    for (i = 0; i < gObjPtrTableCount && (void*)gObjPtrTable[i] != v; i++)
    {
    }
    if (i == gObjPtrTableCount)
    {
        return;
    }
    for (; i < gObjPtrTableCount - 1; i++)
    {
        gObjPtrTable[i] = gObjPtrTable[i + 1];
    }
    gObjPtrTableCount--;
}

#pragma peephole on
void fn_8002B860(void* v)
{
    s8 i = gObjPtrTableCount;
    gObjPtrTableCount = i + 1;
    gObjPtrTable[i] = (int)v;
}

#pragma peephole off
void* getTablesBinEntry(int i)
{
    if (i < 0 || i >= gObjTablesBinCount)
    {
        return gObjTablesBinData;
    }
    return gObjTablesBinData + gObjTablesBinIndex[i] * 4;
}

void Obj_InsertIntoUpdateList(u8* obj)
{
    if (((GameObject*)obj)->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
    {
        int* list = &gObjUpdateList;
        int prev = 0;
        int cur = list[1];
        int linkOff = *(s16*)((u8*)list + 2);
        while (cur != 0 && (s8)obj[0xae] < (s8)((u8*)cur)[0xae])
        {
            prev = cur;
            cur = *(int*)((u8*)cur + linkOff);
        }
        objListAdd(&gObjUpdateList, prev, obj);
    }
}

void Obj_RemoveFromUpdateList(u8* obj)
{
    if (((GameObject*)obj)->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
    {
        objList_remove(&gObjUpdateList, obj);
    }
}

void* Obj_GetPlayerObject(void)
{
    int count;
    void** objs = (void**)ObjGroup_GetObjects(0, &count);
    if (count != 0)
    {
        return objs[0];
    }
    return NULL;
}

void* ObjList_GetObjects(int* outA, int* outB)
{
    if (outA != NULL)
    {
        *outA = 0;
    }
    if (outB != NULL)
    {
        *outB = gObjCount;
    }
    return gObjList;
}

void* loadAssetFileById(int id, int arg);

void Obj_SetActiveModelIndex(u8* obj, int idx)
{
    ObjAnimComponent* objAnim;

    objAnim = (ObjAnimComponent*)obj;
    if (idx == objAnim->bankIndex)
    {
        return;
    }
    if (idx < 0)
    {
        idx = 0;
    }
    else
    {
        int max = objAnim->modelInstance->modelCount;
        if (idx >= max)
        {
            idx = max - 1;
        }
    }
    objAnim->bankIndex = idx;
}

typedef struct ObjListObjectDef
{
    u8 pad00[0x14];
    u32 objectId;
} ObjListObjectDef;

typedef struct ObjListObject
{
    u8 pad00[0x4c];
    ObjListObjectDef* def;
} ObjListObject;

void* getTrickyObject(void)
{
    int count;
    void** objs = (void**)ObjGroup_GetObjects(1, &count);
    if (count != 0)
    {
        return objs[0];
    }
    return NULL;
}

ObjListObject* ObjList_FindObjectById(u32 objectId)
{
    ObjListObjectDef* def;
    ObjListObject* obj;
    int i;
    int count = gObjCount;
    ObjListObject** arr = gObjList;
    for (i = 0; i < count; i++)
    {
        obj = arr[i];
        def = obj->def;
        if (def != NULL && def->objectId == objectId)
        {
            return obj;
        }
    }
    return NULL;
}

typedef f32 Mtx[3][4];

void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst)
{
    f32 mtx[16];
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    PSMTXMultVecSR(mtx, src, dst);
}

void Obj_TransformLocalPointByWorldMatrix(u8* obj, f32* src, f32* dst, u8 flag)
{
    f32 savedZ;
    f32 mtx[16];
    if (flag)
    {
        savedZ = ((GameObject*)obj)->anim.rootMotionScale;
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803DE890;
    }
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    PSMTXMultVec(mtx, src, dst);
    if (flag)
    {
        ((GameObject*)obj)->anim.rootMotionScale = savedZ;
    }
    dst[0] += playerMapOffsetX;
    dst[2] += playerMapOffsetZ;
}

/* rotation(s16)+scale+position transform block consumed by mtxRotateByVec3s */
typedef struct ObjLocalTransform
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjLocalTransform;

void objWorldToLocalPos(f32* out, u8* transform, f32* in)
{
    f32 rotated[3];
    ObjLocalTransform inverse;
    union
    {
        f32 m[16];
        f64 a8;
    } rotU;
    f32 transposed[16];
#define rotMtx rotU.m

    inverse.x = -((ObjLocalTransform*)transform)->x;
    inverse.y = -((ObjLocalTransform*)transform)->y;
    inverse.z = -((ObjLocalTransform*)transform)->z;
    inverse.rotX = -((ObjLocalTransform*)transform)->rotX;
    inverse.rotY = -((ObjLocalTransform*)transform)->rotY;
    inverse.rotZ = -((ObjLocalTransform*)transform)->rotZ;
    inverse.scale = lbl_803DE890;
    mtxRotateByVec3s(rotMtx, &inverse);
    mtx44Transpose(rotMtx, transposed);
    PSMTXMultVec(transposed, in, rotated);
    {
        struct WLPVec3
        {
            int x, y, z;
        };
        *(struct WLPVec3*)out = *(struct WLPVec3*)rotated;
    }
#undef rotMtx
}

void* Obj_AllocObjectSetup(int size, int b)
{
    u8* p = mmAlloc(size, 0xe, 0);
    memset(p, 0, size);
    *(int*)(p + 0x14) = -1;
    p[6] = 0x64;
    p[7] = 0x96;
    p[4] = 8;
    p[5] = 4;
    *(s16*)p = b;
    p[2] = size;
    return p;
}

void ObjModel_LoadRenderOpTextures(u8* model, int arg);

int objMove(u8* obj, f32 dx, f32 dy, f32 dz)
{
    int n;
    ((GameObject*)obj)->anim.localPosX += dx;
    ((GameObject*)obj)->anim.localPosY += dy;
    ((GameObject*)obj)->anim.localPosZ += dz;
    ObjGroup_GetObjects(0, &n);
    return 0;
}

void mtx44Transpose(f32 * src, f32 * dst);

void setMatrixFromObjectTransposed(void* obj, f32* out);

void objFn_8002b67c(u8* obj)
{
    ObjHitVolumeRuntimeBounds *dst;
    ObjDefHitVolume *src;
    int idx;

    if (obj == NULL)
    {
        return;
    }
    dst = ((GameObject *)obj)->anim.hitVolumeBounds;
    if (dst == NULL)
    {
        return;
    }
    src = ((GameObject *)obj)->anim.modelInstance->hitVolumes;
    idx = ((GameObject *)obj)->hitVolumeIndex;
    src += idx;
    dst += idx;
    dst->bounds[0] = src->bounds[0];
    dst->bounds[1] = src->bounds[1];
    dst->bounds[2] = src->bounds[2];
    dst->bounds[3] = src->bounds[3];
    dst->flags = src->flags;
}

int objApplyVelocity(u8* obj)
{
    ((GameObject*)obj)->anim.localPosX += timeDelta * (lbl_803DE8B8 * (((GameObject*)obj)->externalVelX + ((GameObject*)
        obj)->anim.velocityX));
    ((GameObject*)obj)->anim.localPosY += timeDelta * (lbl_803DE8B8 * (((GameObject*)obj)->externalVelY + ((GameObject*)
        obj)->anim.velocityY));
    ((GameObject*)obj)->anim.localPosZ += timeDelta * (lbl_803DE8B8 * (((GameObject*)obj)->externalVelZ + ((GameObject*)
        obj)->anim.velocityZ));
    return 1;
}

void Obj_ApplyPendingParentLinks(void)
{
    int i;
    for (i = 0; i < gObjCount; i++)
    {
        u8* obj = ((u8**)gObjList)[i];
        obj[0xaf] &= ~7;
        if (((GameObject*)obj)->pendingParentObj != NULL)
        {
            if (((GameObject*)obj)->anim.parent == NULL &&
                *(void**)((u8*)((GameObject*)obj)->pendingParentObj + 0x30) != NULL)
            {
                ((GameObject*)obj)->anim.parent = *(void**)((u8*)((GameObject*)obj)->pendingParentObj + 0x30);
            }
            ((GameObject*)obj)->pendingParentObj = NULL;
        }
    }
}

static inline void Obj_FreeDeferredObjects(void)
{
    int i;
    for (i = 0; i < gObjDeferredFreeCount; i++)
    {
        void* p = gObjDeferredFreeList[i];
        if (p != NULL)
        {
            objFreeObjDef(p, 0);
            gObjDeferredFreeList[i] = NULL;
        }
    }
}

void Obj_FlushDeferredFreeList(void)
{
    int i;
    for (i = 0; i < gObjDeferredFreeCount; i++)
    {
        void* p = gObjDeferredFreeList[i];
        if (p != NULL)
        {
            objFreeObjDef(p, 0);
            gObjDeferredFreeList[i] = NULL;
        }
    }
    gObjDeferredFreeCount = 0;
}

void Obj_SetActiveHitVolumeBounds(GameObject* obj, int xBound, int zBound, int yBound,
                                  u8 radiusOrHeight, u8 flags)
{
    ObjHitVolumeRuntimeBounds* bounds;
    if (obj == NULL)
    {
        return;
    }
    bounds = obj->anim.hitVolumeBounds;
    if (bounds == NULL)
    {
        return;
    }
    bounds += obj->hitVolumeIndex;
    if (xBound != 0)
    {
        bounds->bounds[0] = xBound >> 2;
    }
    if (yBound != 0)
    {
        bounds->bounds[1] = yBound >> 2;
    }
    if (zBound != 0)
    {
        bounds->bounds[2] = zBound >> 2;
    }
    if (radiusOrHeight != 0)
    {
        bounds->bounds[3] = radiusOrHeight;
    }
    if (flags != 0)
    {
        bounds->flags = flags;
    }
}

void ObjModel_AdvanceBlendChannels(u8* model, f32 dt);

void* ObjModel_LoadAnimData(u8* p, int b, int c);

void* ObjModel_Load(int id, int arg2, int* outSize);

void* Obj_SetupObject(int a, int b, int c, int d, int e)
{
    void* obj;
    if (getLoadedFileFlags(0) & 0x100000)
    {
        OSReport(sObjSetupObjectLoadingLockedWarning, d);
        return NULL;
    }
    obj = loadCharacter((s16*)a, b, c, d, (void*)e, 0);
    if (obj != NULL)
    {
        Obj_RegisterObject(obj, b);
        OSReport(sObjDebugStrings, *(int*)&((GameObject*)obj)->anim.modelInstance + 0x91);
    }
    return obj;
}

void* loadObjectAtObject(u8* src, int arg1)
{
    void* obj;
    int type;
    int objF30;
    objF30 = (int)((ObjAnimComponent*)src)->parent;
    type = ((ObjAnimComponent*)src)->mapEventSlot;
    if (getLoadedFileFlags(0) & 0x100000)
    {
        OSReport(sObjSetupObjectLoadingLockedWarning, -1);
        obj = NULL;
    }
    else
    {
        obj = loadCharacter((s16*)arg1, 5, type, -1, (void*)objF30, 0);
        if (obj != NULL)
        {
            Obj_RegisterObject(obj, 5);
            OSReport(sObjDebugStrings, *(int*)&((GameObject*)obj)->anim.modelInstance + 0x91);
        }
    }
    return obj;
}

void ObjModel_Release(u8 * model);

void Obj_RunInitCallback(u8* obj, int cb, int unused)
{
    s16 mode = ((GameObject*)obj)->anim.seqId;
    switch (mode)
    {
    case 0x1f:
    case 0:
        objLoadPlayerFromSave(obj);
        break;
    default:
    {
        int* p = (int*)((GameObject*)obj)->anim.dll;
        if (p != NULL)
        {
            int fn = ((int*)*p)[1];
            if (fn != -1 && (void*)fn != NULL)
            {
                ((void (*)(u8*))fn)(obj);
            }
        }
        break;
    }
    }
    {
        ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
        if (modelState != NULL)
        {
            modelState->flags |= OBJ_MODEL_STATE_SHADOW_INIT_CALLBACK_RAN;
        }
    }
    {
        f32 v;
        ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
        ((GameObject*)obj)->anim.previousWorldPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.previousWorldPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.previousWorldPosZ = ((GameObject*)obj)->anim.localPosZ;
        v = lbl_803DE88C;
        ((GameObject*)obj)->externalVelX = v;
        ((GameObject*)obj)->externalVelY = v;
        ((GameObject*)obj)->externalVelZ = v;
    }
}

void objGetWeaponDa(u8* obj, int objType, ObjWeaponDaTable* weaponDaTable, int key, u8 load)
{
    int i;
    s16* tbl;
    s16 da2;

    tbl = ((GameObject*)obj)->anim.modelInstance->weaponDaTable;
    weaponDaTable->byteCount = 0;
    if (tbl == NULL)
    {
        return;
    }
    i = 0;
    while (tbl[i] != -1)
    {
        if (tbl[i] == key)
        {
            da2 = tbl[i + 1];
            weaponDaTable->byteCount = tbl[i + 2];
            if (weaponDaTable->byteCount > 0x800)
            {
                weaponDaTable->byteCount = 0x800;
            }
            if (load)
            {
                getTabEntry(weaponDaTable->entries, 0x34, da2, weaponDaTable->byteCount);
            }
            else
            {
                fileLoadToBufferOffset(0x34, weaponDaTable->entries, da2,
                                       weaponDaTable->byteCount);
            }
            return;
        }
        i += 3;
    }
}

void ObjAnim_LoadMoveEvents(u8* obj, int dummy, ObjAnimEventTable* eventTable, u32 moveId, u8 load)
{
    int i;
    s16* tbl;
    s16 da2;

    tbl = ((GameObject*)obj)->anim.modelInstance->eventMoveTable;
    eventTable->byteCount = 0;
    if (tbl == NULL)
    {
        return;
    }
    i = 0;
    while (tbl[i] != -1)
    {
        if (tbl[i] == (int)moveId)
        {
            da2 = tbl[i + 1];
            eventTable->byteCount = tbl[i + 2];
            if (eventTable->byteCount > 0x50)
            {
                eventTable->byteCount = 0x50;
            }
            if (load == 0)
            {
                getTabEntry(eventTable->entries, 0x40, da2, eventTable->byteCount);
            }
            else
            {
                fileLoadToBufferOffset(0x40, eventTable->entries, da2, eventTable->byteCount);
            }
            return;
        }
        i += 3;
    }
}

void Obj_BuildInverseWorldTransformMatrix(u8* obj, f32* out)
{
    ObjPathTransform transform;
    f32 rotMtx[16];

    if (((GameObject*)obj)->anim.parent == NULL)
    {
        ((GameObject*)obj)->anim.localPosX -= playerMapOffsetX;
        ((GameObject*)obj)->anim.localPosZ -= playerMapOffsetZ;
    }
    transform.x = -((GameObject*)obj)->anim.localPosX;
    transform.y = -((GameObject*)obj)->anim.localPosY;
    transform.z = -((GameObject*)obj)->anim.localPosZ;
    transform.rotX = -((GameObject*)obj)->anim.rotX;
    transform.rotY = -((GameObject*)obj)->anim.rotY;
    transform.rotZ = -((GameObject*)obj)->anim.rotZ;
    transform.scale = lbl_803DE890;
    mtxRotateByVec3s(rotMtx, &transform);
    mtx44Transpose(rotMtx, out);
    if (((GameObject*)obj)->anim.parent == NULL)
    {
        ((GameObject*)obj)->anim.localPosX += playerMapOffsetX;
        ((GameObject*)obj)->anim.localPosZ += playerMapOffsetZ;
    }
}

int ObjList_PartitionForRender(int* out)
{
    void* tmp;
    int i;
    int j;
    int hi;

    *out = gObjCount;
    i = gObjPartitionPivot;
    if (i != 0)
    {
        return i;
    }
    i = 0;
    j = gObjCount - 1;
    hi = j;
    while (i <= j)
    {
        int stop;

        stop = 0;
        while (i <= hi && stop == 0)
        {
            if (((ObjAnimComponent*)((void**)gObjList)[i])->modelInstance->flags & 1)
            {
                i++;
            }
            else
            {
                stop = -1;
            }
        }
        stop = 0;
        while (j >= 0 && stop == 0)
        {
            if (!(((ObjAnimComponent*)((void**)gObjList)[j])->modelInstance->flags & 1))
            {
                j--;
            }
            else
            {
                stop = -1;
            }
        }
        if (i < j)
        {
            tmp = ((void**)gObjList)[i];
            ((void**)gObjList)[i] = ((void**)gObjList)[j];
            ((void**)gObjList)[j] = tmp;
            i++;
            j--;
        }
    }
    gObjPartitionPivot = i;
    return i;
}

#pragma dont_inline on
void Obj_BuildWorldTransformMatrix(u8* obj, f32* mtx, int flags)
{
    f32 savedZ;
    f32 parentMtx[16];
    void* parent;

    if (((GameObject*)obj)->anim.parent == NULL)
    {
        ((GameObject*)obj)->anim.localPosX -= playerMapOffsetX;
        ((GameObject*)obj)->anim.localPosZ -= playerMapOffsetZ;
    }
    if ((u8)flags != 0)
    {
        savedZ = ((GameObject*)obj)->anim.rootMotionScale;
        if ((((GameObject*)obj)->objectFlags & 0x8) == 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803DE890;
        }
    }
    setMatrixFromObjectTransposed(obj, mtx);
    if ((u8)flags != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = savedZ;
    }
    parent = ((GameObject*)obj)->anim.parent;
    if (parent == NULL)
    {
        ((GameObject*)obj)->anim.localPosX += playerMapOffsetX;
        ((GameObject*)obj)->anim.localPosZ += playerMapOffsetZ;
    }
    else
    {
        Obj_BuildWorldTransformMatrix(parent, parentMtx, 1);
        PSMTXConcat((f32*)parentMtx, mtx, mtx);
    }
}

typedef struct LoadedObj
{
    u8 pad00[0x06];
    s16 flags06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0x18];
    void* parent;
    u8 pad34[0x2];
    u8 f36;
    u8 pad37[0x5];
    f32 f3c;
    f32 f40;
    s16 f44;
    s16 seqId;
    s16 typeId;
    u8 pad4a[0x2];
    s16* data;
    u8* def;
    ObjHitReactState* hitReactState;
    u8 pad58[0x4];
    ObjWeaponDaTable* weaponDaTable;
    ObjAnimEventTable* objAnimEventTable;
    u8 pad64[0x4];
    int** dll;
    int f6c;
    ObjTextureRuntimeSlot* textureSlots;
    ObjHitVolumeRuntimeTransform* hitVolumeTransforms;
    ObjHitVolumeRuntimeBounds* hitVolumeBounds;
    u8** models;
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
    u8 ff2;
    u8 padf3[0x15];
    int f108;
} LoadedObj;

void* loadCharacter(s16* data, int flags, int arg2, int arg3, void* parent, int unused)
{
    int id;
    int offsets[20];
    void* models[20];
    LoadedObj tmpl;
    LoadedObj* tp;
    s16 seq;
    int m;
    u8* def;
    int fnFlags;
    int (*fp)(void*);
    int (*fp2)(void*, int);
    int flags29;
    int idx;
    int i;
    int count;
    int total;
    ObjModelInstance* modelDef;
    LoadedObj* obj;
    int base;
    int cursor;
    u8 n;
    u16 h;
    u8 cb;
    f32 max;
    s16 seq2;
    u32 v;
    int size;
    int sz;
    int tmp;

    seq = *data;
    if (flags & 2)
    {
        id = seq;
    }
    else
    {
        if (seq > gObjSeqToObjIdMax)
        {
            return NULL;
        }
        id = gObjSeqToObjIdTable[seq];
    }
    memset(&tmpl, 0, 0x10c);
    tp = &tmpl;
    def = loadObjectFile(id);
    tmpl.def = def;
    if (def == NULL || (int)def == -1)
    {
        debugPrintf(sObjUnknownTypeUsingDummyObjectWarning, id, *data, tmpl.seqId);
        return NULL;
    }
    modelDef = (ObjModelInstance*)def;
    tmpl.f44 = *(s16*)(def + 0x52);
    tmpl.scale = modelDef->rootMotionScaleBase;
    tmpl.flags06 = 2;
    if (modelDef->flags & 0x80)
    {
        tmpl.flags06 = tmpl.flags06 | 0x80;
    }
    if (modelDef->flags & 0x40000)
    {
        tmpl.fb0 = tmpl.fb0 | 0x80;
    }
    if (flags & 4)
    {
        tmpl.flags06 = tmpl.flags06 | 0x2000;
    }
    tmpl.x = *(f32*)(data + 4);
    tmpl.y = *(f32*)(data + 6);
    tmpl.z = *(f32*)(data + 8);
    tmpl.typeId = id;
    tmpl.data = data;
    tmpl.seqId = seq;
    tmpl.fb2 = arg3;
    tmpl.fac = arg2;
    tmpl.fa2 = -1;
    tmpl.fb4 = -1;
    tmpl.f36 = 0xff;
    tmpl.fdc = 0;
    tmpl.ff1 = 0xff;
    tmpl.f3c = (f32)(int)(((u8*)data)[6] << 3);
    tmpl.f40 = (f32)(int)(((u8*)data)[7] << 3);
    n = (((u8*)data)[5] & 0x18) >> 3;
    tmpl.ff2 = n;
    if (n == 0)
    {
        tmpl.ff2 = *(u8*)(tmpl.def + 0x8e);
    }
    else
    {
        n -= 1;
        tmpl.ff2 = n;
    }
    tmpl.dll = NULL;
    if ((int)*(s16*)(def + 0x50) != -1)
    {
        tmpl.dll = Resource_Acquire(*(s16*)(def + 0x50) & 0xffff, 6);
    }
    switch (tmpl.seqId)
    {
    case 0:
    case 0x1f:
        fnFlags = 0x1cb;
        break;
    default:
        if (tmpl.dll != NULL && (int)(fp = (int (*)(void*))*(int*)(*(int*)tmpl.dll + 0x18)) != -1 && fp != NULL)
        {
            fnFlags = fp(tp);
        }
        else
        {
            fnFlags = 0;
        }
        break;
    }
    if (modelDef->flags & 0x20)
    {
        flags29 = fnFlags & ~1;
    }
    else
    {
        flags29 = fnFlags | 1;
    }
    if (modelDef->shadowType != 0)
    {
        flags29 |= 2;
    }
    else
    {
        flags29 &= ~2;
    }
    if (modelDef->shadowType == 3)
    {
        flags29 |= 0x8000;
    }
    if (modelDef->flags & 1)
    {
        flags29 |= 0x200;
    }
    total = 0;
    i = 0;
    count = modelDef->modelCount;
    if (flags29 & 0x400)
    {
        idx = (flags29 >> 0xb) & 0xf;
        if (idx < count)
        {
            models[idx] = ObjModel_Load(-(*(int**)(def + 8))[idx], flags29, &size);
            offsets[idx] = total;
            total += size;
        }
    }
    else if (!(flags29 & 0x200))
    {
        for (; i < count; i++)
        {
            models[i] = ObjModel_Load(-(*(int**)(def + 8))[i], flags29, &size);
            offsets[i] = total;
            total += size;
        }
    }
    base = objGetTotalDataSize(tp, def, data, flags29);
    obj = mmAlloc(base + total, 0xe, 0);
    memcpy(obj, &tmpl, 0x10c);
    memset((u8*)obj + 0x10c, 0, base + total - 0x10c);
    obj->models = (u8**)(obj + 1);
    ((ObjModelInstance*)obj->def)->flags |= 0x800000LL;
    i = 0;
    obj->f108 = 0;
    if (flags29 & 0x400)
    {
        idx = (flags29 >> 0xb) & 0xf;
        if (idx < count)
        {
            obj->models[idx] = (u8*)obj + base + offsets[idx];
            ObjModel_LoadAnimData(models[idx], flags29, (int)obj->models[idx]);
            if (!(*(u16*)(*(u8**)obj->models[idx] + 2) & 0x8000))
            {
                ((ObjModelInstance*)obj->def)->flags &= ~0x800000LL;
            }
            ObjModel_LoadRenderOpTextures(obj->models[idx], (int)obj);
            modelInitBones(obj->scale, obj->models[idx]);
            if (((ObjModelInstance*)obj->def)->flags & 0x800)
            {
                ObjModel_SetRenderCallback(obj->models[idx], objCallback_80074d04);
            }
            else
            {
                cb = ((ObjModelInstance*)obj->def)->renderFlags;
                if (cb & 1)
                {
                    ObjModel_SetRenderCallback(obj->models[idx], modelCb_80073d04);
                }
                else if (cb & 0x80)
                {
                    ObjModel_SetRenderCallback(obj->models[idx], modelCb_80074518);
                }
            }
        }
    }
    else if (!(flags29 & 0x200))
    {
        for (; i < count; i++)
        {
            obj->models[i] = (u8*)obj + base + offsets[i];
            ObjModel_LoadAnimData(models[i], flags29, (int)obj->models[i]);
            h = *(u16*)(*(u8**)obj->models[i] + 2);
            if (!(h & 0x8000) && !(h & 0x4000))
            {
                ((ObjModelInstance*)obj->def)->flags &= ~0x800000LL;
            }
            ObjModel_LoadRenderOpTextures(obj->models[i], (int)obj);
            modelInitBones(obj->scale, obj->models[i]);
            if (((ObjModelInstance*)obj->def)->flags & 0x800)
            {
                ObjModel_SetRenderCallback(obj->models[i], objCallback_80074d04);
            }
            else
            {
                cb = ((ObjModelInstance*)obj->def)->renderFlags;
                if (cb & 1)
                {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80073d04);
                }
                else if (cb & 0x80)
                {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80074518);
                }
            }
        }
    }
    cursor = roundUpTo4((int)obj->models + modelDef->modelCount * 4);
    switch (obj->seqId)
    {
    case 0:
    case 0x1f:
        sz = 0x8e0;
        break;
    default:
        if (obj->dll != NULL && (fp2 = (int (*)(void*, int))*(int*)(*(int*)obj->dll + 0x1c)) != NULL)
        {
            sz = fp2(obj, cursor);
        }
        else
        {
            sz = 0;
        }
        break;
    }
    if (sz != 0)
    {
        obj->fb8 = cursor;
        cursor += sz;
    }
    else
    {
        obj->fb8 = 0;
    }
    if ((flags29 & 0x40) || (((ObjModelInstance*)obj->def)->flags & 0x400000))
    {
        seq2 = obj->seqId;
        tmp = roundUpTo4(cursor);
        obj->objAnimEventTable = (ObjAnimEventTable*)tmp;
        cursor = roundUpTo8(tmp + 8);
        obj->objAnimEventTable->entries = (s16*)cursor;
        ObjAnim_LoadMoveEvents((u8*)obj, seq2, obj->objAnimEventTable, 0, 1);
        cursor += 0x50;
    }
    if ((flags29 & 0x100) && *(void**)obj->models != NULL)
    {
        tmp = roundUpTo4(cursor);
        obj->weaponDaTable = (ObjWeaponDaTable*)tmp;
        cursor = roundUpTo8(tmp + 8);
        obj->weaponDaTable->entries = (s16*)cursor;
        cursor += 0x800;
    }
    if ((flags29 & 2) && modelDef->shadowType != 0)
    {
        cursor = shadowInit(obj, cursor, 0);
    }
    max = lbl_803DE8CC;
    i = 0;
    for (; i < *(s8*)((u8*)obj->def + 0x55); i++)
    {
        m = *(int*)((u8*)obj->models + i * 4);
        if (m != 0)
        {
            if ((f32)modelFileHeaderGetCullDistance(*(u8**)m) > max)
            {
                max = modelFileHeaderGetCullDistance(*(u8**)m);
            }
        }
    }
    v = *(u8*)(obj->def + 0x73);
    if (v != 0)
    {
        max = max * ((lbl_803DE8CC * v) / lbl_803DE8D0);
    }
    obj->cullDist = max;
    if (*(u8*)(def + 0x61) != 0)
    {
        cursor = ObjHits_AllocObjectState((int)obj, cursor);
        if ((s8)modelDef->primaryHitboxShapeFlags & 8)
        {
            cursor = ObjHitbox_AllocRotatedBounds((ObjHitbox*)obj, cursor);
        }
    }
    if (modelDef->jointCount != 0)
    {
        tmp = roundUpTo4(cursor);
        obj->f6c = tmp;
        cursor = tmp + modelDef->jointCount * 0x12;
    }
    if (modelDef->textureSlotCount != 0)
    {
        tmp = roundUpTo4(cursor);
        obj->textureSlots = (ObjTextureRuntimeSlot*)tmp;
        cursor = tmp + modelDef->textureSlotCount * sizeof(ObjTextureRuntimeSlot);
    }
    if (modelDef->hitVolumeCount != 0)
    {
        tmp = roundUpTo4(cursor);
        obj->hitVolumeTransforms = (ObjHitVolumeRuntimeTransform*)tmp;
        cursor = tmp + modelDef->hitVolumeCount * 0x18;
    }
    if (*(u8*)(def + 0x61) != 0 && *(u8*)(def + 0x66) != 0)
    {
        tmp = roundUpTo4(cursor);
        cursor = ObjHitReact_InitState(obj->seqId, (ObjAnimBank*)*(u8**)obj->models,
                                       obj->hitReactState, tmp, (ObjAnimComponent*)obj);
    }
    if (modelDef->hitVolumeCount != 0)
    {
        obj->hitVolumeBounds = (ObjHitVolumeRuntimeBounds*)roundUpTo4(cursor);
        i = 0;
        for (; i < modelDef->hitVolumeCount; i++)
        {
            obj->hitVolumeBounds[i].flags = modelDef->hitVolumes[i].flags;
            obj->hitVolumeBounds[i].bounds[0] = modelDef->hitVolumes[i].bounds[0];
            obj->hitVolumeBounds[i].bounds[3] = modelDef->hitVolumes[i].bounds[3];
            obj->hitVolumeBounds[i].bounds[1] = modelDef->hitVolumes[i].bounds[1];
            obj->hitVolumeBounds[i].bounds[2] = modelDef->hitVolumes[i].bounds[2];
        }
    }
    obj->parent = parent;
    return obj;
}

#pragma dont_inline off
void objFreeObjDef(u8* obj, int flag)
{
    int defs[40];
    void(*fp)(u8 *, int);
    void(*cb)(u8 *);
    BoneParticleEffectSpawnFn cb2;
    int i;
    int count;
    int n;
    u8* o;
    int* bp;
    void* curTex;
    void* tex;
    void* shadowRenderResource;
    s8 modelCount;
    int group;
    int type;

    if (*(u8*)&((GameObject*)obj)->unkE9 != 0)
    {
        ObjContact_RemoveObjectCallbacks((int)obj);
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0:
    case 0x1f:
        fn_802B4DE0(obj, flag);
        break;
    default:
        if (((GameObject*)obj)->anim.dll != NULL)
        {
            fp = (void (*)(u8*, int))*(int*)(*(int*)((GameObject*)obj)->anim.dll + 0x14);
            if (fp != NULL)
            {
                fp(obj, flag);
            }
            Resource_Release(((GameObject*)obj)->anim.dll);
            *(int*)&((GameObject*)obj)->anim.dll = 0;
        }
        break;
    }
    (*(void (**)(u8*))(*(int*)gTitleMenuControlInterface + 0x48))(obj);
    (*gExpgfxInterface)->freeOwner3((u32)obj);
    if (((ObjAnimComponent*)obj)->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE)
    {
        ObjGroup_RemoveObject((u32)obj, 6);
        if (flag == 0)
        {
            count = 0;
            for (i = 0; i < gObjCount; i++)
            {
                o = ((u8**)gObjList)[i];
                if (*(int*)&((GameObject*)o)->anim.parent == (int)obj)
                {
                    *(int*)&((GameObject*)o)->anim.parent = 0;
                    if (*(void**)&((GameObject*)o)->anim.placementData != NULL)
                    {
                        defs[count++] = (int)o;
                    }
                }
            }
            for (n = 0; n < count; n++)
            {
                Obj_FreeObject((void*)defs[n]);
            }
            fn_80059A50(*(u8*)(obj + 0x34));
        }
    }
    if (flag == 0 && ((GameObject*)obj)->anim.classId == 0x10)
    {
        for (i = 0; i < gObjCount; i++)
        {
            o = ((u8**)gObjList)[i];
            if (*(int*)(o + 0xc0) == (int)obj)
            {
                *(int*)(o + 0xc0) = 0;
            }
        }
    }
    for (i = 0; i < gObjCount; i++)
    {
        if (*(s16*)(((u8**)gObjList)[i] + 0x44) == 0x10)
        {
            bp = *(int**)(((u8**)gObjList)[i] + 0xb8);
            if (*(u8**)bp == obj)
            {
                *bp = 0;
                *((u8*)bp + 0x8f) = 1;
            }
        }
    }
    if (((ObjAnimComponent*)obj)->modelInstance->group8RegistrationCount > 0)
    {
        ObjGroup_RemoveObject((u32)obj, 8);
    }
    if (((ObjAnimComponent*)obj)->modelState != NULL)
    {
        if (((ObjAnimComponent*)obj)->modelInstance->shadowType == 1)
        {
            setShadowFlag_803db658(1);
        }
        if (((ObjAnimComponent*)obj)->modelState->shadowTexture != NULL)
        {
            curTex = textureFn_8006c5c4();
            tex = ((ObjAnimComponent*)obj)->modelState->shadowTexture;
            if (tex != curTex)
            {
                if (((ObjAnimComponent*)obj)->modelInstance->renderFlags & 4)
                {
                    mm_free(tex);
                }
                else
                {
                    textureFree(tex);
                }
            }
        }
        if (((ObjAnimComponent*)obj)->modelState->shadowWorkBuffer != NULL)
        {
            mm_free(((ObjAnimComponent*)obj)->modelState->shadowWorkBuffer);
        }
        shadowRenderResource = ((ObjAnimComponent*)obj)->modelState->shadowRenderResource;
        if (shadowRenderResource != NULL && shadowRenderResource != (void*)-1)
        {
            mm_free(shadowRenderResource);
        }
    }
    if (*(void**)&((GameObject*)obj)->unkDC != NULL)
    {
        mm_free(((GameObject*)obj)->unkDC);
        *(int*)&((GameObject*)obj)->unkDC = 0;
    }
    modelCount = ((ObjAnimComponent*)obj)->modelInstance->modelCount;
    for (i = 0; i < modelCount; i++)
    {
        if ((int)((ObjAnimComponent*)obj)->banks[i] != 0)
        {
            ObjModel_Release((u8*)((ObjAnimComponent*)obj)->banks[i]);
        }
    }
    if (((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_FROZEN)
    {
        *(u16*)&((GameObject*)obj)->colorFadeFrames = 0;
        ((GameObject*)obj)->colorFadeFlags = ((GameObject*)obj)->colorFadeFlags & ~OBJ_COLOR_FADE_FLAG_FROZEN;
        ((GameObject*)obj)->fadeCounter = 0;
        ObjModel_ClearRenderAttachment((u8*)((ObjAnimComponent*)obj)->banks[((ObjAnimComponent*)obj)->bankIndex]);
        cb2 = (*gBoneParticleEffectInterface)->spawnEffect;
        cb2(obj, 0x7fb, NULL, 0x50, NULL);
        cb2 = (*gBoneParticleEffectInterface)->spawnEffect;
        cb2(obj, 0x7fc, NULL, 0x32, NULL);
    }
    if (((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE)
    {
        Obj_ClearModelColorFadeRecursive(obj);
    }
    group = ObjGroup_GetObjectGroup((u32)obj);
    if (group != 0)
    {
        ObjGroup_RemoveObject((u32)obj, group - 1);
    }
    type = ((GameObject*)obj)->anim.defId;
    if (*(u8*)(gObjFileRefCount + type) == 0)
    {
        debugPrintf(sObjFreeObjdefError);
    }
    else
    {
        *(u8*)(gObjFileRefCount + type) -= 1;
        if (*(u8*)(gObjFileRefCount + type) == 0)
        {
            o = ((u8**)gObjFileBufferTable)[type];
            if (*(void**)&((GameObject*)o)->anim.parent != NULL)
            {
                mm_free(((GameObject*)o)->anim.parent);
            }
            if (*(void**)(o + 0x34) != NULL)
            {
                mm_free(*(void**)(o + 0x34));
            }
            mm_free(o);
        }
    }
    if (((GameObject*)obj)->seqIndex > -1)
    {
        if (flag == 0)
        {
            (*gObjectTriggerInterface)->endSequence(((GameObject*)obj)->seqIndex);
        }
        ((GameObject*)obj)->seqIndex = 0xffff;
    }
    if ((*(s16*)&((GameObject*)obj)->anim.flags & 0x2000) && *(void**)&((GameObject*)obj)->anim.placementData != NULL)
    {
        mm_free(((GameObject*)obj)->anim.placementData);
    }
    mm_free(obj);
}

void Obj_UpdateObject(u8* obj)
{
    ObjAnimComponent* object;
    ObjHitsPriorityState* hitState;
    ObjHitsPriorityState* childHitState;
    u8* t;
    BoneParticleEffectSpawnFn cb;
    void(*cb2)(u8 *);

    object = (ObjAnimComponent*)obj;
    if (((GameObject*)obj)->objectFlags & OBJECT_FLAG_FREED)
    {
        return;
    }
    if (gObjUpdateFlags & 1)
    {
        switch (object->seqId)
        {
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
            cb2 = (void (*)(u8*))*(int*)((u8*)*object->dll + 8);
            cb2(obj);
            break;
        }
        return;
    }
    if (((GameObject*)obj)->colorFadeFlags != 0 && ((GameObject*)obj)->ownerObj == NULL && (((GameObject*)obj)->
        colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE))
    {
        Obj_TickModelColorFadeRecursive(obj);
    }
    if (((GameObject*)obj)->pendingParentObj != NULL)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            t = *(u8**)((u8*)((GameObject*)obj)->childObjs[0] + 0x54);
            if (t != 0)
            {
                ((ObjHitsPriorityState*)*(u8**)((u8*)((GameObject*)obj)->childObjs[0] + 0x54))->lastHitObject = 0;
                ((ObjHitsPriorityState*)*(u8**)((u8*)((GameObject*)obj)->childObjs[0] + 0x54))->priorityHitCount = 0;
            }
        }
        if (object->hitReactState == NULL)
        {
            return;
        }
        ((ObjHitsPriorityState*)object->hitReactState)->lastHitObject = 0;
        ((ObjHitsPriorityState*)object->hitReactState)->priorityHitCount = 0;
        return;
    }
    if ((object->flags & 8) == 0)
    {
        object->previousLocalPosX = object->localPosX;
        object->previousLocalPosY = object->localPosY;
        object->previousLocalPosZ = object->localPosZ;
        object->previousWorldPosX = object->worldPosX;
        object->previousWorldPosY = object->worldPosY;
        object->previousWorldPosZ = object->worldPosZ;
    }
    ((GameObject*)obj)->externalVelX = object->velocityX;
    ((GameObject*)obj)->externalVelY = object->velocityY;
    ((GameObject*)obj)->externalVelZ = object->velocityZ;
    if (((GameObject*)obj)->colorFadeFlags != 0 && ((GameObject*)obj)->ownerObj == NULL && (((GameObject*)obj)->
        colorFadeFlags & OBJ_COLOR_FADE_FLAG_FROZEN))
    {
        ((GameObject*)obj)->colorFadeFrames = (s16)((f32)((GameObject*)obj)->colorFadeFrames - timeDelta);
        if (((GameObject*)obj)->colorFadeFrames <= 0)
        {
            ((GameObject*)obj)->colorFadeFrames = 0;
            ((GameObject*)obj)->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_FROZEN;
            ((GameObject*)obj)->fadeCounter = 0;
            ObjModel_ClearRenderAttachment((u8*)object->banks[object->bankIndex]);
            cb = (*gBoneParticleEffectInterface)->spawnEffect;
            cb(obj, 0x7fb, NULL, 0x50, NULL);
            cb = (*gBoneParticleEffectInterface)->spawnEffect;
            cb(obj, 0x7fc, NULL, 0x32, NULL);
            Sfx_PlayFromObject((u32)obj, SFXTRIG_barrel_bounce1);
        }
    }
    if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_UPDATE_DISABLED) == 0)
    {
        switch (object->seqId)
        {
        case 0:
        case 0x1f:
            playerUpdate(obj);
            break;
        default:
            if (object->dll == NULL)
            {
                goto skip;
            }
            cb2 = (void (*)(u8*))*(int*)((u8*)*object->dll + 8);
            if (cb2 != 0)
            {
                cb2(obj);
            }
            break;
        }
        Obj_GetWorldPosition((u32)obj, &object->worldPosX, &object->worldPosY, &object->worldPosZ);
    }
skip:
    if (object->hitReactState != NULL)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            t = *(u8**)((u8*)((GameObject*)obj)->childObjs[0] + 0x54);
            if (t != 0)
            {
                ((ObjHitsPriorityState*)*(u8**)((u8*)((GameObject*)obj)->childObjs[0] + 0x54))->lastHitObject = 0;
                ((ObjHitsPriorityState*)*(u8**)((u8*)((GameObject*)obj)->childObjs[0] + 0x54))->priorityHitCount = 0;
            }
        }
        ((ObjHitsPriorityState*)object->hitReactState)->lastHitObject = 0;
        ((ObjHitsPriorityState*)object->hitReactState)->priorityHitCount = 0;
    }
    if (*(void**)(obj + 0x58) != NULL)
    {
        *(u8*)(*(u8**)(obj + 0x58) + 0x10f) = 0;
    }
}

void Obj_UpdateAllObjects(u8 flags)
{
    int f;
    int off;
    int timeStop;
    u8* obj2;
    int child;
    int obj;
    int obj3;
    int count1;
    int count2;
    u8* t;
    void (*cb)(int);

    f = flags;
    gObjUpdateFlags = f;
    off = *(s16*)((u8*)&gObjUpdateList + 2);
    timeStop = f & 1;
    if (timeStop == 0)
    {
        objFn_80065604();
    }
    Obj_UpdateModelBlendStates();
    ObjHitReact_ResetActiveObjects(gObjCount);
    obj = *(int*)((u8*)&gObjUpdateList + 4);
    while (obj != 0 && ((ObjAnimComponent*)obj)->activeHitboxMode == 0x64)
    {
        Obj_UpdateObject((u8*)obj);
        obj = *(int*)(obj + off);
    }
    while (obj != 0 &&
        (((ObjAnimComponent*)obj)->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE))
    {
        Obj_UpdateObject((u8*)obj);
        *(s8*)(obj + 0x35) = Obj_BuildTransformMatrixSlot(obj);
        obj = *(int*)(obj + off);
    }
    if (timeStop == 0)
    {
        ObjHitReact_UpdateResetObjects();
    }
    for (; obj != 0; obj = *(int*)(obj + off))
    {
        t = (void*)((GameObject*)obj)->anim.hitReactState;
        if (t != 0)
        {
            if ((((ObjHitsPriorityState*)t)->shapeFlags & 8) == 0 || (((ObjHitsPriorityState*)t)->flags & 1) == 0)
            {
                Obj_UpdateObject((u8*)obj);
            }
        }
        else
        {
            Obj_UpdateObject((u8*)obj);
        }
    }
    obj2 = (u8*)ObjGroup_GetObjects(0, &count1);
    if (count1 != 0)
    {
        obj2 = *(u8**)obj2;
    }
    else
    {
        obj2 = 0;
    }
    if (obj2 != 0 && (u32)(child = (int)((GameObject*)obj2)->childObjs[0]) != 0)
    {
        *(int*)((u8*)child + 0x30) = *(int*)&((GameObject*)obj2)->anim.parent;
        Obj_UpdateObject(((GameObject*)obj2)->childObjs[0]);
    }
    if (timeStop == 0)
    {
        ObjHits_Update(gObjCount);
        obj3 = *(int*)((u8*)&gObjUpdateList + 4);
        for (; obj3 != 0; obj3 = *(int*)(obj3 + off))
        {
            if ((((GameObject*)obj3)->objectFlags & OBJECT_OBJFLAG_HITDETECT_DISABLED) == 0)
            {
                switch (((GameObject*)obj3)->anim.seqId)
                {
                case 0:
                case 0x1f:
                    playerDoHitDetection(obj3);
                    break;
                default:
                    if (((GameObject*)obj3)->anim.dll == 0)
                    {
                        goto next;
                    }
                    cb = (void (*)(int))*(int*)((u8*)*((GameObject*)obj3)->anim.dll + 0xc);
                    if (cb == 0)
                    {
                        goto next;
                    }
                    cb(obj3);
                    break;
                }
                Obj_GetWorldPosition((u32)obj3, &((GameObject *)obj3)->anim.worldPosX, &((GameObject *)obj3)->anim.worldPosY, &((GameObject *)obj3)->anim.worldPosZ);
            }
        next:;
        }
        obj2 = (u8*)ObjGroup_GetObjects(0, &count2);
        obj2 = (count2 != 0) ? *(u8**)obj2 : 0;
        if (obj2 != 0 && ((GameObject*)obj2)->childObjs[0] != 0)
        {
            *(int*)((u8*)((GameObject*)obj2)->childObjs[0] + 0x30) = *(int*)&((GameObject*)obj2)->anim.parent;
            child = *(int*)&((GameObject*)obj2)->childObjs[0];
            if ((((GameObject*)child)->objectFlags & OBJECT_OBJFLAG_HITDETECT_DISABLED) == 0)
            {
                switch (((GameObject*)child)->anim.seqId)
                {
                case 0:
                case 0x1f:
                    playerDoHitDetection(child);
                    break;
                default:
                    if (((GameObject*)child)->anim.dll == 0)
                    {
                        goto done;
                    }
                    cb = (void (*)(int))*(int*)((u8*)*((GameObject*)child)->anim.dll + 0xc);
                    if (cb == 0)
                    {
                        goto done;
                    }
                    cb(child);
                    break;
                }
                Obj_GetWorldPosition((u32)child, (f32 *)(child + 0x18), (f32 *)(child + 0x1c), (f32 *)(child + 0x20));
            }
        }
    done:
        (*gWaterfxInterface)->runFrame(framesThisStep);
    }
    if ((f & 2) == 0)
    {
        ((ModgfxInterface*)*(void**)gModgfxInterface)->updateActiveEffects(0, 0, 0);
        (*gExpgfxInterface)->updateFrameState(0, framesThisStep, 0, 0);
    }
    if (timeStop == 0)
    {
        ObjHits_TickPriorityHitCooldowns();
        (*gObjectTriggerInterface)->run();
        (*gObjectTriggerInterface)->updateCamera();
        (*gCameraInterface)->update(framesThisStep);
    }
}

typedef struct CharSpawn
{
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
    int mapId;
} CharSpawn;

void mapSetupPlayer(void)
{
    u8* base;
    int playerNo;
    int mapType;
    u8* obj;
    f32* pos;
    f32 x, y, z;
    int uiDll;
    u8* view;
    u8* vp;
    CharSpawn spawn;

    base = (u8*)(int)&gObjCameraSetupBlock;
    mapType = getCurMapType();
    if (mapType == 2 || mapType == 3)
    {
        OSReport((char*)(base + 0x70));
        Obj_ResetObjectSystem();
    }
    else
    {
        playerNo = (*gMapEventInterface)->getCurChar();
        pos = (f32*)(*gMapEventInterface)->getCurCharPos();
        x = pos[0];
        y = pos[1];
        z = pos[2];
        obj = 0;
        if (playerNo > -1 && mapType != 4)
        {
            OSReport((char*)(base + 0x88), mapType, playerNo);
            memset(&spawn, 0, 0x18);
            spawn.mapId = -1;
            spawn.unk3 = 0;
            spawn.unk4 = 1;
            spawn.unk5 = 4;
            spawn.unk6 = 0xff;
            spawn.unk7 = 0xff;
            spawn.id = gObjPlayerSpawnIdTable[playerNo];
            spawn.unk2 = 0x18;
            spawn.x = x;
            spawn.y = y;
            spawn.z = z;
            if (getLoadedFileFlags(0) & 0x100000)
            {
                OSReport((char*)(base + 0x20), -1);
                obj = 0;
            }
            else
            {
                obj = loadCharacter((s16*)&spawn, 1, -1, -1, 0, 0);
                if (obj != 0)
                {
                    Obj_RegisterObject(obj, 1);
                    OSReport((char*)(base + 0x5c), *(int*)&((GameObject*)obj)->anim.modelInstance + 0x91);
                }
            }
        }
        *(f32*)(base + 8) = lbl_803DE8BC * mathSinf((gObjPi * (f32)(*(s8*)((u8*)pos + 0xc) << 8)) / lbl_803DE8C4)
            + x;
        *(f32*)(base + 0xc) = lbl_803DE8C8 + y;
        *(f32*)(base + 0x10) = lbl_803DE8BC * mathCosf(
            (gObjPi * (f32)(*(s8*)((u8*)pos + 0xc) << 8)) / lbl_803DE8C4) + z;
        uiDll = getCurUiDll();
        if ((u32)(uiDll - 2) <= 4 || uiDll == 7)
        {
            (*gCameraInterface)->init(obj, *(f32*)(base + 8), *(f32*)(base + 0xc), *(f32*)(base + 0x10));
            (*gCameraInterface)->setMode(0x57, 0, 3, 0, NULL, 0, 0);
            (*gCameraInterface)->setFocus(obj, 0);
            (*gCameraInterface)->update(1);
        }
        else
        {
            (*gCameraInterface)->init(obj, *(f32*)(base + 8), *(f32*)(base + 0xc), *(f32*)(base + 0x10));
            (*gCameraInterface)->setMode(0x42, 0, 0, 0x20, (u8*)(int)&gObjCameraSetupBlock, 0, 0xff);
            (*gCameraInterface)->update(1);
        }
        vp = Camera_GetCurrentViewSlot();
        view = (*gCameraInterface)->getCamera();
        *(f32*)(vp + 0xc) = *(f32*)(view + 0x18);
        *(f32*)(vp + 0x10) = *(f32*)(view + 0x1c);
        *(f32*)(vp + 0x14) = *(f32*)(view + 0x20);
        (*(void (**)(u8*))(*(int*)gTitleMenuControlInterface + 0x10))(obj);
        lbl_803DCB70 = 0;
        playerUpdateFn_8005649c();
    }
}

void Obj_ResetObjectSystem(void)
{
    int off;
    int i;

    Obj_FreeDeferredObjects();
    gObjDeferredFreeCount = 0;
    gObjDefCaptureMode = 0;
    i = gObjCount - 1;
    off = i << 2;
    for (; i >= 0; i--)
    {
        Obj_FreeObject(*(void**)((int)gObjList + off));
        off -= 4;
    }
    Obj_FreeDeferredObjects();
    gObjDefCaptureMode = 2;
    gObjDeferredFreeCount = 0;
    lbl_803DCB8C = 0;
    gObjCount = 0;
    fn_80013B6C(&gObjUpdateList, 0x38);
    gObjDeferredFreeCount = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB70 = 0;
    gObjCount = 0;
    fn_80013B6C(&gObjUpdateList, 0x38);
    gObjPartitionPivot = 0;
    ObjGroup_ClearAll();
    ObjHits_ResetWorkBuffers();
    (*gCameraInterface)->setFocus(NULL, 0);
    AudioStream_StopAll();
}

void Obj_UpdateModelBlendStates(void)
{
    ObjAnimComponent* objAnim;
    ObjAnimComponent* childAnim;
    int ioff;
    int k;
    int i;
    int j;
    u8* walker;
    u8* obj;
    u8* child;
    u8* m;
    u8* c0;
    u8* bp;
    ObjModelState* modelState;

    i = 0;
    ioff = 0;
    for (; i < gObjCount; i++)
    {
        obj = *(u8**)((int)gObjList + ioff);
        objAnim = (ObjAnimComponent*)obj;
        if (obj != 0 && objAnim->modelInstance != NULL)
        {
            modelState = objAnim->modelState;
            if (modelState != NULL)
            {
                modelState->shadowCastSlot = NULL;
            }
            j = 0;
            for (; j < objAnim->modelInstance->modelCount; j++)
            {
                m = (u8*)objAnim->banks[j];
                if (m != 0)
                {
                    *(u16*)(m + 0x18) &= ~8;
                    if (*(u8*)(*(u8**)m + 0xf9) != 0)
                    {
                        ObjModel_AdvanceBlendChannels(m, timeDelta);
                    }
                }
            }
            j = 0;
            walker = obj;
            for (; j < ((GameObject*)obj)->childCount; j++)
            {
                child = *(u8**)(walker + 0xc8);
                childAnim = (ObjAnimComponent*)child;
                if (child != 0 && childAnim->modelInstance != NULL)
                {
                    k = 0;
                    for (; k < childAnim->modelInstance->modelCount; k++)
                    {
                        m = (u8*)childAnim->banks[k];
                        if (m != 0)
                        {
                            *(u16*)(m + 0x18) &= ~8;
                            if (*(u8*)(*(u8**)m + 0xf9) != 0)
                            {
                                c0 = ((GameObject*)child)->pendingParentObj;
                                if (c0 != 0)
                                {
                                    bp = *(u8**)(c0 + 0xb8);
                                }
                                else
                                {
                                    bp = 0;
                                }
                                if (c0 == 0 || (bp != 0 && *(s8*)(bp + 0x56) == 0))
                                {
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

#pragma dont_inline on
void Obj_RegisterObject(u8* obj, int flags)
{
    ObjAnimComponent* object;
    ObjHitsPriorityState* hitState;
    int id;
    int prev;
    int cur;
    int off;

    object = (ObjAnimComponent*)obj;
    if (object->parent != NULL)
    {
        Obj_TransformLocalPointToWorld(object->localPosX, object->localPosY, object->localPosZ,
                                       &object->worldPosX, &object->worldPosY, &object->worldPosZ,
                                       (u32)object->parent);
    }
    else
    {
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
    if (object->hitReactState != NULL)
    {
        ((ObjHitsPriorityState*)object->hitReactState)->localPosX = object->localPosX;
        ((ObjHitsPriorityState*)object->hitReactState)->localPosY = object->localPosY;
        ((ObjHitsPriorityState*)object->hitReactState)->localPosZ = object->localPosZ;
        ((ObjHitsPriorityState*)object->hitReactState)->worldPosX = object->localPosX;
        ((ObjHitsPriorityState*)object->hitReactState)->worldPosY = object->localPosY;
        ((ObjHitsPriorityState*)object->hitReactState)->worldPosZ = object->localPosZ;
    }
    id = object->modelInstance->mapLoadObjectId;
    if (id > -1)
    {
        mapLoadForObject(id, obj);
    }
    if (object->modelInstance->flags & 0x40)
    {
        ObjGroup_AddObject((u32)obj, 6);
        if (object->activeHitboxMode != 0x5a && (object->modelInstance->flags & 0x40))
        {
            object->activeHitboxMode = 0x5a;
        }
    }
    else
    {
        if (object->activeHitboxMode == 0)
        {
            object->activeHitboxMode = 0x50;
        }
    }
    if (flags & 1)
    {
        ((GameObject*)obj)->objectFlags |= OBJECT_FLAG_IN_UPDATE_LIST;
        ((u8**)gObjList)[gObjCount++] = obj;
        if (((GameObject*)obj)->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
        {
            prev = 0;
            cur = *(int*)((u8*)&gObjUpdateList + 4);
            off = *(s16*)((u8*)&gObjUpdateList + 2);
            while (cur != 0 && object->activeHitboxMode < *(s8*)(cur + 0xae))
            {
                prev = cur;
                cur = *(int*)(cur + off);
            }
            objListAdd(&gObjUpdateList, prev, obj);
        }
    }
    if (object->modelInstance->group8RegistrationCount > 0)
    {
        ObjGroup_AddObject((u32)obj, 8);
    }
    if (object->modelInstance->flags & 1)
    {
        gObjPartitionPivot = 0;
    }
}

#pragma dont_inline off
void Obj_FreeObject(u8* obj)
{
    u8** p;
    int n;
    int i;
    u8** base;
    int off;
    u8* q;

    if (((GameObject*)obj)->objectFlags & OBJECT_FLAG_FREED)
    {
        return;
    }
    Sfx_RemoveLoopedObjectSoundForObject((u32)obj);
    Sfx_StopObjectChannel((u32)obj, 0x7f);
    if (((GameObject*)obj)->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
    {
        for (i = 0; i < gObjCount; i++)
        {
            if (((u8**)gObjList)[i] == obj)
            {
                break;
            }
        }
        if (i < gObjCount)
        {
            gObjCount--;
            off = i << 2;
            for (; i < gObjCount; i++)
            {
                q = (u8*)gObjList + off;
                *(int*)q = *(int*)(q + 4);
                off += 4;
            }
        }
        else
        {
            OSReport(sObjFreeNonExistentObjectWarning);
        }
        if (((GameObject*)obj)->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
        {
            objList_remove(&gObjUpdateList, obj);
        }
        gObjPartitionPivot = 0;
    }
    for (i = 0; i < gObjDeferredFreeCount; i++)
    {
    }
    ((GameObject*)obj)->objectFlags |= OBJECT_FLAG_FREED;
    if (((GameObject*)obj)->unkEA != 0)
    {
        i = 0;
        base = lbl_803DCB90;
        for (; i < lbl_803DCB8C; i++)
        {
            if (base[i] == obj)
            {
                break;
            }
        }
        if (i == lbl_803DCB8C)
        {
            if (lbl_803DCB8C < 0x18)
            {
                ((u8**)lbl_803DCB90)[lbl_803DCB8C] = obj;
                lbl_803DCB8C++;
                return;
            }
        }
        else
        {
            return;
        }
    }
    if (gObjDefCaptureMode == 2)
    {
        i = gObjDeferredFreeCount;
        if (gObjDeferredFreeCount != 0)
        {
            for (i = 0; i < gObjDeferredFreeCount; i++)
            {
                if (((u8**)gObjDeferredFreeList)[i] == obj)
                {
                    break;
                }
            }
        }
        if (i == gObjDeferredFreeCount)
        {
            ((u8**)gObjDeferredFreeList)[gObjDeferredFreeCount] = obj;
            gObjDeferredFreeCount++;
            if (gObjDeferredFreeCount == 400)
            {
                gObjDeferredFreeCount--;
            }
        }
    }
    else
    {
        objFreeObjDef(obj, !gObjDefCaptureMode);
    }
}

void Obj_InitObjectSystem(void)
{
    s16* p;
    int* q;
    int i;

    gObjDeferredFreeList = mmAlloc(0x640, 0xe, 0);
    lbl_803DCB90 = mmAlloc(0x60, 0xe, 0);
    lbl_803DCBC0 = mmAlloc(0x10, 0xe, 0);
    loadAssetFileById((int)&gObjSeqToObjIdTable, 0x3f);
    gObjSeqToObjIdMax = (getDataFileSize(0x3f) >> 1) - 1;
    for (p = gObjSeqToObjIdTable + gObjSeqToObjIdMax; *p == 0;)
    {
        p--;
        gObjSeqToObjIdMax--;
    }
    loadAssetFileById((int)&gObjFileOffsetTable, 0x3d);
    gObjFileCount = 0;
    for (q = gObjFileOffsetTable; *q != -1;)
    {
        q++;
        gObjFileCount++;
    }
    gObjFileCount--;
    gObjFileBufferTable = mmAlloc(gObjFileCount * 4, 0xe, 0);
    gObjFileRefCount = mmAlloc(gObjFileCount, 0xe, 0);
    for (i = 0; i < gObjFileCount; i++)
    {
        gObjFileRefCount[i] = 0;
    }
    loadAssetFileById((int)&gObjTablesBinData, 0x16);
    loadAssetFileById((int)&gObjTablesBinIndex, 0x17);
    gObjTablesBinCount = 0;
    for (q = gObjTablesBinIndex; *q != -1;)
    {
        q++;
        gObjTablesBinCount++;
    }
    gObjList = mmAlloc(0x960, 0xe, 0);
    ObjHits_InitWorkBuffers();
    gObjDeferredFreeCount = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB70 = 0;
    gObjCount = 0;
    fn_80013B6C(&gObjUpdateList, 0x38);
    gObjPartitionPivot = 0;
    ObjGroup_ClearAll();
    ObjHits_ResetWorkBuffers();
}

u8* loadObjectFile(int id)
{
    int size;
    int base;
    u8* buf;
    int off;
    int n;
    s16 modLine;

    if (id >= gObjFileCount)
    {
        return 0;
    }
    if (gObjFileRefCount[id] != 0)
    {
        gObjFileRefCount[id]++;
        return *(u8**)((int)gObjFileBufferTable + (id << 2));
    }
    {
        int* offsets = (int*)gObjFileOffsetTable;
        base = offsets[id];
        size = (&offsets[id])[1] - base;
    }
    off = id << 2;
    buf = mmAlloc(size, 0xe, 0);
    if (buf != 0)
    {
        fileLoadToBufferOffset(0x3e, buf, base, size);
        if (*(void**)(buf + 0x20) != 0)
        {
            *(int*)(buf + 0x20) = (int)buf + *(int*)(buf + 0x20);
        }
        if (*(void**)(buf + 0x24) != 0)
        {
            *(int*)(buf + 0x24) = (int)buf + *(int*)(buf + 0x24);
        }
        if (*(void**)(buf + 0x28) != 0)
        {
            *(int*)(buf + 0x28) = (int)buf + *(int*)(buf + 0x28);
        }
        *(int*)(buf + 8) = (int)buf + *(int*)(buf + 8);
        *(int*)(buf + 0xc) = (int)buf + *(int*)(buf + 0xc);
        *(int*)(buf + 0x10) = (int)buf + *(int*)(buf + 0x10);
        if (*(void**)(buf + 0x18) != 0)
        {
            *(int*)(buf + 0x18) = (int)buf + *(int*)(buf + 0x18);
        }
        if (*(void**)(buf + 0x40) != 0)
        {
            *(int*)(buf + 0x40) = (int)buf + *(int*)(buf + 0x40);
        }
        if (*(void**)(buf + 0x1c) != 0)
        {
            *(int*)(buf + 0x1c) = (int)buf + *(int*)(buf + 0x1c);
        }
        *(int*)(buf + 0x2c) = (int)buf + *(int*)(buf + 0x2c);
        *(int*)(buf + 0x30) = 0;
        *(int*)(buf + 0x34) = 0;
        n = (s8)buf[0x5d];
        if (n > -1)
        {
            *(int*)(buf + 0x30) = loadModLines(n, &modLine);
            *(u8*)(buf + 0x5c) = modLine;
            intersectModLineBuild(buf);
        }
        *(u8**)((int)gObjFileBufferTable + off) = buf;
        gObjFileRefCount[id] = 1;
    }
    else
    {
        return 0;
    }
    return buf;
}

int objGetTotalDataSize(void* tmpl, u8* def, s16* data, int flags)
{
    ObjModelInstance* modelDef;
    int size;
    int r;
    int extra;
    int (*cb)(void*, int);

    modelDef = (ObjModelInstance*)def;
    size = modelDef->modelCount * 4 + 0x10c;
    switch (*(s16*)((u8*)tmpl + 0x46))
    {
    case 0:
    case 0x1f:
        extra = 0x8e0;
        break;
    default:
        if (*(int**)((u8*)tmpl + 0x68) == 0)
        {
            goto none;
        }
        cb = (int (*)(void*, int))*(int*)(**(int**)((u8*)tmpl + 0x68) + 0x1c);
        if (cb == 0)
        {
            goto none;
        }
        extra = cb(tmpl, size);
        break;
    none:
        extra = 0;
        break;
    }
    size += extra;
    if ((flags & 0x40) || (modelDef->flags & 0x400000))
    {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x50;
    }
    if (flags & 0x100)
    {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x800;
    }
    if ((flags & 2) && modelDef->shadowType != 0)
    {
        size = roundUpTo4(size) + 0x44;
    }
    if (*(u8*)(def + 0x61) != 0)
    {
        size = roundUpTo4(size) + 0xb8;
        if ((s8)modelDef->primaryHitboxShapeFlags & 8)
        {
            size += 0x110;
        }
    }
    if (modelDef->jointCount != 0)
    {
        r = roundUpTo4(size);
        size = r + modelDef->jointCount * 0x12;
    }
    if (modelDef->textureSlotCount != 0)
    {
        r = roundUpTo4(size);
        size = r + modelDef->textureSlotCount * sizeof(ObjTextureRuntimeSlot);
    }
    if (modelDef->hitVolumeCount != 0)
    {
        r = roundUpTo4(size);
        size = r + modelDef->hitVolumeCount * 0x18;
    }
    if (*(u8*)(def + 0x61) != 0 && *(u8*)(def + 0x66) != 0)
    {
        size = roundUpTo8(size) + 0x12c;
    }
    if (modelDef->hitVolumeCount != 0)
    {
        r = roundUpTo4(size);
        size = r + modelDef->hitVolumeCount * 5;
    }
    return roundUpTo32(size);
}

void fn_800213D0(f32 * a, f32 * b, s16 * out0, s16 * out1, s16 * out2);

void fn_8002A5DC(u8* obj)
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

    len = lbl_803DE888 * ((GameObject*)obj)->anim.hitboxScale;
    denom = len * ((GameObject*)obj)->anim.rootMotionScale;
    dx = ((((GameObject*)obj)->anim.previousLocalPosZ - lbl_803DCECC) - (((GameObject*)obj)->anim.localPosZ -
        playerMapOffsetZ)) / denom;
    dz = ((((GameObject*)obj)->anim.localPosX - lbl_803DCED0) - (((GameObject*)obj)->anim.previousLocalPosX -
        playerMapOffsetX)) / denom;
    sum = dz * dz + dx * dx;
    if (sum > lbl_803DE88C)
    {
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
        fn_800213D0(vecA, vecB, &((GameObject*)obj)->anim.rotZ, &((GameObject*)obj)->anim.rotY, (s16*)obj);
    }
}

void modelInitBones(f32 scale, void* model)
{
    extern f32 lbl_803DE88C;
    extern const f32 lbl_803DE890;
    extern f32 lbl_803DE8D4;
    extern f32 lbl_803DE8D8;
    f32* srcP;
    int off;
    int boneOff;
    f32* sumP;
    u8* hdr;
    u8* tbl;
    int i;
    int parent;
    f32* src;
    u8* bone;
    f32 zero;
    f32 sc;
    f32 w;
    f32 len;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 v;
    f32 pv;
    f32 sums[152];
    u8* m = model;

    sc = scale;
    hdr = *(u8**)m;
    if ((!*(u16*)(hdr + 2) & 0x1000) || (*(u8*)(hdr + 0xf3) == 0))
    {
        return;
    }
    {
        if ((src = *(f32**)(hdr + 0x18)) != NULL && (tbl = *(u8**)(m + 0x14)) != NULL)
        {
            **(f32**)(tbl + 4) = src[0] * sc;
            if (**(f32**)(tbl + 4) == lbl_803DE88C)
            {
                **(f32**)(tbl + 4) = src[1] * sc;
            }
            **(f32**)(tbl + 8) = **(f32**)(tbl + 4) * **(f32**)(tbl + 4);
            **(f32**)(tbl + 0xc) = lbl_803DE8D4;
            **(f32**)(tbl + 0x10) = **(f32**)(tbl + 4);
            zero = lbl_803DE88C;
            sums[0] = zero;
            i = 1;
            srcP = src + 1;
            off = 4;
            boneOff = 0x1c;
            sumP = &sums[1];
            for (; i < *(u8*)(*(u8**)m + 0xf3); srcP++, off += 4, boneOff += 0x1c, sumP++, i++)
            {
                *(f32*)(*(u8**)(tbl + 4) + off) = sc * *srcP;
                *(f32*)(*(u8**)(tbl + 8) + off) =
                    *(f32*)(*(u8**)(tbl + 4) + off) * *(f32*)(*(u8**)(tbl + 4) + off);
                bone = *(u8**)(hdr + 0x3c) + boneOff;
                parent = *(s8*)bone;
                vx = *(f32*)(bone + 4);
                vy = *(f32*)(bone + 8);
                vz = *(f32*)(bone + 0xc);
                len = sqrtf(vx * vx + vy * vy + vz * vz);
                *(f32*)(*(u8**)(tbl + 0xc) + off) = sc * len;
                v = *(f32*)(*(u8**)(tbl + 0xc) + off);
                if (v == zero)
                {
                    *(f32*)(*(u8**)(tbl + 0xc) + off) = lbl_803DE8D8;
                }
                w = *(f32*)(*(u8**)(hdr + 0x1c) + off);
                if (w >= lbl_803DE890)
                {
                    *(f32*)(*(u8**)(tbl + 0xc) + off) *= w;
                }
                *sumP = sums[parent] + *(f32*)(*(u8**)(tbl + 0xc) + off);
                if (*srcP == zero)
                {
                    *(f32*)(*(u8**)(tbl + 0x10) + off) = *(f32*)(*(u8**)(tbl + 0x10) + parent * 4);
                }
                else
                {
                    *(f32*)(*(u8**)(tbl + 0x10) + off) = *sumP + *(f32*)(*(u8**)(tbl + 4) + off);
                    v = *(f32*)(*(u8**)(tbl + 0x10) + off);
                    pv = *(f32*)(*(u8**)(tbl + 0x10) + parent * 4);
                    *(f32*)(*(u8**)(tbl + 0x10) + off) = (v > pv) ? v : pv;
                }
            }
        }
    }
}

int loadModLines(int idx, s16* outCount)
{
    int result;
    int* hdr;
    int size;
    int start;

    result = 0;
    if (idx > (getDataFileSize(0x38) - 4) >> 2)
    {
        return 0;
    }
    hdr = mmAlloc(0x10, 0x1a, 0);
    fileLoadToBufferOffset(0x38, hdr, idx << 2, 8);
    start = hdr[0];
    size = hdr[1] - hdr[0];
    if (size > 0)
    {
        result = (int)mmAlloc(size, 5, 0);
        fileLoadToBufferOffset(0x37, (void*)result, start, size);
    }
    mm_free(hdr);
    *outCount = (u32)size / 20;
    return result;
}

char sObjDebugStrings[] = {
    0x4C, 0x4F, 0x41, 0x44, 0x45, 0x44, 0x20, 0x4F, 0x42, 0x4A, 0x45, 0x43,
    0x54, 0x20, 0x25, 0x73, 0x0A, 0x00, 0x00, 0x00, 0x3D, 0x3D, 0x3D, 0x3D,
    0x3D, 0x3D, 0x3D, 0x20, 0x20, 0x4F, 0x42, 0x4A, 0x46, 0x52, 0x45, 0x45,
    0x41, 0x4C, 0x4C, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x20, 0x20, 0x20, 0x20, 0x4C, 0x4F, 0x41, 0x44, 0x49,
    0x4E, 0x47, 0x20, 0x43, 0x48, 0x41, 0x52, 0x41, 0x43, 0x54, 0x45, 0x52,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x6D, 0x61, 0x70, 0x74, 0x79, 0x70, 0x65,
    0x20, 0x25, 0x64, 0x20, 0x20, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x6E,
    0x6F, 0x20, 0x25, 0x64, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x00,
};

char sObjSetupObjectLoadingLockedWarning[] = "<objSetupObject>  loading is locked can't setup objno %d\n";
