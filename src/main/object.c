#include "dolphin/os/OSReport.h"
#include "main/dll/objpathtransform_struct.h"
#include "main/shader_api.h"
#include "main/shader_map_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/model_engine_ui_api.h"
#include "main/asset_load.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/sfx.h"
#include "main/audio/stream_api.h"
#include "main/camera_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/waterfx_interface.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/mapEvent.h"
#include "main/object_transform.h"
#include "main/objHitReact.h"
#include "main/obj_contact.h"
#include "main/obj_group.h"
#include "main/obj_list.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/loaded_file_flags.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/mm.h"
#include "main/texture.h"
#include "main/camera.h"
#include "main/object.h"
#include "main/object_update_list.h"
#include "main/object_api.h"
#include "main/newshadows_shadow_api.h"
#include "main/pi_dolphin.h"
#include "main/pi_data_file_api.h"
#include "main/track_dolphin_api.h"
#include "track/intersect_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/player.h"
#include "string.h"
#include "main/dll/dll_0004_dummy04.h"

s16 gObjPartitionPivot;
void* lbl_803DCBC0;
int* gObjFileOffsetTable;
int gObjFileCount;
u8* gObjTablesBinData;
int* gObjTablesBinIndex;
int gObjTablesBinCount;
u8** gObjFileBufferTable;
u8* gObjFileRefCount;
s16* gObjSeqToObjIdTable;
int gObjSeqToObjIdMax;
GameObject** gObjDeferredFreeList;
int gObjDeferredFreeCount;
GameObject** lbl_803DCB90;
int lbl_803DCB8C;
GameObject** gObjList;
int gObjCount;
ObjLinkedList gObjUpdateList;
u32 gObjUpdateFlags;
s8 gEffectBoxObjectCount;
int lbl_803DCB70;

int gObjDefCaptureMode = 2;
s16 gObjPlayerSpawnIdTable[2] = {0x1F, 0};

typedef struct ObjListObjectDef
{
    u8 pad00[0x14];
    u32 objectId;
} ObjListObjectDef;

typedef f32 Mtx[3][4];

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

#define OBJECT_CAMMODE_TITLE   0x57 /* cameramode DLL dll_0057_cameramodetitle */
#define OBJECT_CAMMODE_DEFAULT 0x42 /* default gameplay cameramode DLL */

/* special-cased seqIds (retail OBJECTS.bin names) */
#define OBJECT_SEQID_SABRE       0x0   /* "Sabre" - the player object */
#define OBJECT_SEQID_KRYSTAL     0x1f  /* "Krystal" - the player object */
#define OBJECT_SEQID_STAFF       0x69  /* "staff" (DLL 0xE2) */
#define OBJECT_SEQID_DIE_DUSTER  0x4f3 /* "DieDuster" (DLL 0x10E) */
#define OBJECT_SEQID_DIE_FOX     0x882 /* "DieFox" (DLL 0x10E) */
#define OBJECT_SEQID_DIE_KRYSTAL 0x887 /* "DieKrystal" (DLL 0x10E) */

/* GameObject::objectFlags lifecycle bits */
#define OBJECT_FLAG_IN_UPDATE_LIST 0x10 /* registered in gObjList / gObjUpdateList */
#define OBJECT_FLAG_FREED          0x40 /* Obj_FreeObject ran (double-free guard) */

/* ObjGroup ids (registered/unregistered in Obj_SetupObject / Obj_FreeObject) */
#define OBJECT_OBJGROUP_HITBOX 6 /* joined when modelInstance flags & 0x40 (SKIP_RESET_UPDATE) */
#define OBJECT_OBJGROUP_GROUP8 8 /* joined when modelInstance->group8RegistrationCount > 0 */

enum
{
    OBJ_LIST_CAPACITY = 600,
    OBJ_DEFERRED_FREE_CAPACITY = 400,
    OBJ_PENDING_DEF_FREE_CAPACITY = 24
};

/* loadCharacter model-load config word (flags29), passed to ObjModel_Load etc. */
#define OBJLOAD_FLAG_HAS_SHADOW    0x0002 /* modelDef->shadowType != 0 */
#define OBJLOAD_FLAG_ANIM_EVENTS   0x0040 /* allocate anim move-event table */
#define OBJLOAD_FLAG_WEAPON_DA     0x0100 /* allocate weapon-DA table */
#define OBJLOAD_FLAG_SINGLE_MODEL  0x0200 /* skip multi-model loop (modelDef->flags & 1) */
#define OBJLOAD_FLAG_INDEXED_MODEL 0x0400 /* load one model at index (flags29>>11 & 0xf) */
#define OBJLOAD_FLAG_SHADOW_TYPE3  0x8000 /* modelDef->shadowType == 3 */

extern f32 lbl_803DE888;
extern f32 lbl_803DE88C;
extern f32 lbl_803DE894;
extern f32 lbl_803DE898;
extern f32 lbl_803DE8D4;
extern f32 lbl_803DE8D8;
extern f32 gObjColorFadeRate;
extern f32 gObjColorFadeAlphaMax;
GameObject* gEffectBoxObjects[20];
extern int gObjTablesBinCount;
extern int* gObjTablesBinIndex;
extern u8* gObjTablesBinData;
extern int gObjCount;
extern GameObject** gObjList;
extern const f32 lbl_803DE890;
extern const f32 lbl_803DE8B8;
extern int gObjDeferredFreeCount;
extern GameObject** gObjDeferredFreeList;
extern char sObjSetupObjectLoadingLockedWarning[];
extern char sObjDebugStrings[];
extern s16 gObjPartitionPivot;
extern int gObjSeqToObjIdMax;
extern s16* gObjSeqToObjIdTable;
extern f32 lbl_803DE8CC;
extern f32 lbl_803DE8D0;
extern u8* gObjFileRefCount;
extern u32 gObjUpdateFlags;
extern f32 lbl_803DE8BC;
extern f32 gObjPi;
extern f32 lbl_803DE8C4;
extern f32 lbl_803DE8C8;
extern int lbl_803DCB70;
extern int lbl_803DCB8C;
extern GameObject** lbl_803DCB90;
extern void* lbl_803DCBC0;
extern int* gObjFileOffsetTable;
extern int gObjFileCount;
extern f32 gMapSavedPlayerOffsetX;
extern f32 gMapSavedPlayerOffsetZ;

void Obj_RegisterObject(GameObject* obj, int b);
int loadModLines(int n, s16* out);

char sObjUnknownTypeUsingDummyObjectWarning[] =
    "Warning: Unknown object type '%d/%d romdefno %d', using DummyObject (128)\n";

char sObjFreeObjdefError[] = "objFreeObjdef: Error!! (%d)\n";

u8 gObjCameraSetupBlock[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x3C, 0x00, 0x5A, 0x00, 0x55, 0x1E, 0x14,
};

char sObjFreeNonExistentObjectWarning[] = "Tried to free non-existent object\n";
void Obj_RunInitCallback(u8* obj, int cb, int unused);
void ObjAnim_LoadMoveEvents(u8* obj, int dummy, ObjAnimEventTable* eventTable, u32 moveId, u8 load);

void doNothing_afterRenderObject(void)
{
}

void doNothing_beforeRenderObject(int a)
{
}


void Obj_UpdateRollingRotation(GameObject* obj)
{
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

    len = lbl_803DE888 * obj->anim.hitboxScale;
    denom = len * obj->anim.rootMotionScale;
    dx = ((obj->anim.previousLocalPosZ - gMapSavedPlayerOffsetZ) -
          (obj->anim.localPosZ - playerMapOffsetZ)) /
         denom;
    dz = ((obj->anim.localPosX - gMapSavedPlayerOffsetX) -
          (obj->anim.previousLocalPosX - playerMapOffsetX)) /
         denom;
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
        basisVectorsToEulerAngles(vecA, vecB, &obj->anim.rotZ, &obj->anim.rotY, (s16*)obj);
    }
}
void Obj_SetModelRenderOpAlpha(void* obj, u8 alpha)
{
    ObjAnimComponent* objAnim;
    ModelFileHeader* modelFile;
    int renderOpIndex;
    ObjModel* model;

    objAnim = (ObjAnimComponent*)obj;
    model = (ObjModel*)objAnim->banks[objAnim->bankIndex];
    if (model != NULL)
    {
        modelFile = model->file;
        if (modelFile != NULL)
        {
            for (renderOpIndex = 0; renderOpIndex < modelFile->renderOpCount; renderOpIndex++)
            {
                ObjModel_GetRenderOp(modelFile, renderOpIndex)->alphaOverride = alpha;
            }
        }
    }
}

void Obj_SetModelSlotIndex(GameObject* obj, int slotIndex)
{
    obj->anim.mapEventSlot = slotIndex;
}

void Obj_ClearModelSlotIndex(GameObject* obj)
{
    obj->anim.mapEventSlot = -1;
}

ObjModel* Obj_GetActiveModel(GameObject* obj)
{
    return (ObjModel*)obj->anim.banks[obj->anim.bankIndex];
}

void Obj_ClearModelColorFadeRecursive(GameObject* obj)
{
    int i;

    obj->colorFadeFrames = 0;
    obj->colorFadeFlags &= ~(OBJ_COLOR_FADE_FLAG_ACTIVE | OBJ_COLOR_FADE_FLAG_INCREASING);
    i = 0;
    while (i < obj->childCount)
    {
        Obj_ClearModelColorFadeRecursive((GameObject*)obj->childObjs[i]);
        i++;
    }
}

void Obj_TickModelColorFadeRecursive(GameObject* obj)
{
    f32 alpha;
    u8* childScan;
    int i;

    if ((obj->colorFadeFlags & OBJ_COLOR_FADE_FLAG_INCREASING) != 0)
    {
        alpha = obj->colorFadeAlpha + gObjColorFadeRate * timeDelta;
    }
    else
    {
        alpha = obj->colorFadeAlpha - gObjColorFadeRate * timeDelta;
    }

    if (alpha < lbl_803DE88C)
    {
        alpha = -alpha;
        obj->colorFadeFlags ^= OBJ_COLOR_FADE_FLAG_INCREASING;
    }
    else if (alpha > gObjColorFadeAlphaMax)
    {
        alpha = gObjColorFadeAlphaMax - (alpha - gObjColorFadeAlphaMax);
        obj->colorFadeFlags ^= OBJ_COLOR_FADE_FLAG_INCREASING;
    }

    obj->colorFadeAlpha = alpha;
    if ((obj->colorFadeFlags & OBJ_COLOR_FADE_FLAG_INFINITE) == 0)
    {
        obj->colorFadeFrames -= framesThisStep;
        if (obj->colorFadeFrames <= 0 && obj->ownerObj == NULL)
        {
            Obj_ClearModelColorFadeRecursive(obj);
        }
    }

    i = 0;
    childScan = (u8*)obj;
    while (i < obj->childCount)
    {
        Obj_TickModelColorFadeRecursive((GameObject*)((GameObject*)childScan)->childObjs[i]);
        i++;
    }
}


int objGetFlagsE5_2(u8* obj)
{
    return ((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE;
}

void Obj_SetModelColorFadeRecursive(GameObject* obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf)
{
    u8* childScan;
    int i;
    int f;

    obj->colorFadeFrames = frames;
    f = obj->colorFadeFlags;
    f &= ~OBJ_COLOR_FADE_FLAG_INCREASING;
    obj->colorFadeFlags = (u8)f;
    f = obj->colorFadeFlags;
    f |= OBJ_COLOR_FADE_FLAG_ACTIVE;
    obj->colorFadeFlags = (u8)f;
    obj->colorFadeRed = red;
    obj->colorFadeGreen = green;
    obj->colorFadeBlue = blue;
    if (frames == 10000)
    {
        f = obj->colorFadeFlags;
        f |= OBJ_COLOR_FADE_FLAG_INFINITE;
        obj->colorFadeFlags = (u8)f;
    }
    else
    {
        f = obj->colorFadeFlags;
        f &= ~OBJ_COLOR_FADE_FLAG_INFINITE;
        obj->colorFadeFlags = (u8)f;
    }
    if (startAtHalf != 0)
    {
        f = 0x7f;
        obj->colorFadeAlpha = (u8)f;
    }
    else
    {
        f = 0;
        obj->colorFadeAlpha = (u8)f;
    }

    i = 0;
    childScan = (u8*)obj;
    while (i < obj->childCount)
    {
        Obj_SetModelColorFadeRecursive((GameObject*)((GameObject*)childScan)->childObjs[i], frames, red, green, blue, startAtHalf);
        i++;
    }
}
void Obj_SetModelColorOverrideRecursive(GameObject* obj, u8 red, u8 green, u8 blue, u8 alpha, u8 enabled)
{
    u8* childScan;
    int i;

    if (enabled != 0)
    {
        obj->colorFadeFlags |= OBJ_COLOR_FADE_FLAG_OVERRIDE;
        obj->colorFadeRed = red;
        obj->colorFadeGreen = green;
        obj->colorFadeBlue = blue;
        obj->colorFadeAlpha = alpha;
    }
    else
    {
        obj->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_OVERRIDE;
    }

    i = 0;
    childScan = (u8*)obj;
    while (i < obj->childCount)
    {
        Obj_SetModelColorOverrideRecursive((GameObject*)((GameObject*)childScan)->childObjs[i], red, green, blue,
                                           alpha, enabled);
        i++;
    }
}

void Obj_Shatter(GameObject* obj)
{
    obj->colorFadeFrames = 0;
    obj->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_FROZEN;
    obj->fadeCounter = 0;
    ObjModel_ClearRenderAttachment(Obj_GetActiveModel(obj));
    (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fb, NULL, 0x50, NULL);
    (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fc, NULL, 0x32, NULL);
}

int objIsFrozen(u8* obj)
{
    return ((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_FROZEN;
}

void Obj_StartModelFadeIn(GameObject* obj, int frames)
{
    ObjAnimComponent* objAnim;
    f32 mtx[16];
    int fadeLimit;
    s16 objType;

    objAnim = &obj->anim;
    fadeLimit = 10;
    objType = obj->anim.classId;
    if (objType == 0x1c || objType == 0x6d || objType == 0x2a)
    {
        fadeLimit = 40;
    }
    if ((obj->anim.modelInstance->effectFlags & 1) != 0)
    {
        if (obj->fadeCounter < fadeLimit)
        {
            obj->fadeCounter++;
            Obj_SetModelColorFadeRecursive(obj, 0x1e, 0xa0, 0xff, 0xff, 0);
        }
        if (obj->fadeCounter == fadeLimit)
        {
            if ((obj->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE) != 0)
            {
                Obj_ClearModelColorFadeRecursive(obj);
            }
            obj->colorFadeFrames = frames;
            obj->colorFadeFlags = (u8)(obj->colorFadeFlags | OBJ_COLOR_FADE_FLAG_FROZEN);
            Obj_BuildWorldTransformMatrix(obj, mtx, 0);
            ObjModel_EnableDefaultRenderCallback(obj, (ObjModel*)objAnim->banks[objAnim->bankIndex], mtx, 1,
                                                 obj->anim.hitboxScale * obj->anim.rootMotionScale);
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fc, NULL, 0x64, NULL);
        }
    }
}


void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst)
{
    f32 mtx[16];
    Obj_BuildWorldTransformMatrix((GameObject*)obj, mtx, 0);
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
    Obj_BuildWorldTransformMatrix((GameObject*)obj, mtx, 0);
    PSMTXMultVec(mtx, src, dst);
    if (flag)
    {
        ((GameObject*)obj)->anim.rootMotionScale = savedZ;
    }
    dst[0] += playerMapOffsetX;
    dst[2] += playerMapOffsetZ;
}

void objWorldToLocalPos(f32* out, ObjLocalTransform* transform, f32* in)
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

    inverse.x = -transform->x;
    inverse.y = -transform->y;
    inverse.z = -transform->z;
    inverse.rotX = -transform->rotX;
    inverse.rotY = -transform->rotY;
    inverse.rotZ = -transform->rotZ;
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

void Obj_BuildInverseWorldTransformMatrix(GameObject* obj, f32* out)
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

void Obj_BuildWorldTransformMatrix(GameObject* obj, f32* mtx, int flags)
{
    f32 savedZ;
    f32 pos;
    f32 newPos;
    f32 scale;
    f32 parentMtx[16];
    GameObject* parent;
    int objFlags;

    parent = obj->anim.parent;
    if (parent == NULL)
    {
        pos = obj->anim.localPosX;
        newPos = pos - playerMapOffsetX;
        obj->anim.localPosX = newPos;
        pos = obj->anim.localPosZ;
        newPos = pos - playerMapOffsetZ;
        obj->anim.localPosZ = newPos;
    }
    if ((u8)flags != 0)
    {
        savedZ = obj->anim.rootMotionScale;
        objFlags = obj->objectFlags;
        objFlags &= 0x8;
        if (objFlags == 0)
        {
            scale = lbl_803DE890;
            obj->anim.rootMotionScale = scale;
        }
    }
    setMatrixFromObjectTransposed(obj, mtx);
    if ((u8)flags != 0)
    {
        scale = savedZ;
        obj->anim.rootMotionScale = scale;
    }
    parent = obj->anim.parent;
    if (parent == NULL)
    {
        pos = obj->anim.localPosX;
        newPos = pos + playerMapOffsetX;
        obj->anim.localPosX = newPos;
        pos = obj->anim.localPosZ;
        newPos = pos + playerMapOffsetZ;
        obj->anim.localPosZ = newPos;
    }
    else
    {
        Obj_BuildWorldTransformMatrix(parent, parentMtx, 1);
        PSMTXConcat((f32*)parentMtx, mtx, mtx);
    }
}


GameObject* loadObjectAtObject(GameObject* src, ObjPlacement* setup)
{
    GameObject* obj;
    int type;
    int objF30;
    objF30 = (int)src->anim.parent;
    type = src->anim.mapEventSlot;
    if (getLoadedFileFlags(0) & 0x100000)
    {
        OSReport(sObjSetupObjectLoadingLockedWarning, -1);
        obj = NULL;
    }
    else
    {
        obj = loadCharacter((s16*)setup, 5, type, -1, (void*)objF30, 0);
        if (obj != NULL)
        {
            Obj_RegisterObject(obj, 5);
            OSReport(sObjDebugStrings, *(int*)&obj->anim.modelInstance + 0x91);
        }
    }
    return obj;
}
void objSetHintTextIdx(GameObject* obj, u16 idx)
{
    if (idx > 4)
    {
        idx = 0;
    }
    (obj)->hintTextIdx = idx;
}

void Obj_ResetActiveHitVolumeBounds(GameObject* obj)
{
    ObjHitVolumeRuntimeBounds* dst;
    ObjDefHitVolume* src;
    int idx;

    if (obj == NULL)
    {
        return;
    }
    dst = obj->anim.hitVolumeBounds;
    if (dst == NULL)
    {
        return;
    }
    src = obj->anim.modelInstance->hitVolumes;
    idx = obj->hitVolumeIndex;
    src += idx;
    dst += idx;
    dst->bounds[0] = src->bounds[0];
    dst->bounds[1] = src->bounds[1];
    dst->bounds[2] = src->bounds[2];
    dst->bounds[3] = src->bounds[3];
    dst->flags = src->flags;
}

void Obj_SetActiveHitVolumeBounds(GameObject* obj, int xBound, int zBound, int yBound, u8 radiusOrHeight, u8 flags)
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

void Obj_UnregisterEffectBox(GameObject* obj)
{
    int i;

    for (i = 0; i < gEffectBoxObjectCount && gEffectBoxObjects[i] != obj; i++)
    {
    }
    if (i == gEffectBoxObjectCount)
    {
        return;
    }
    for (; i < gEffectBoxObjectCount - 1; i++)
    {
        gEffectBoxObjects[i] = gEffectBoxObjects[i + 1];
    }
    gEffectBoxObjectCount--;
}
void Obj_RegisterEffectBox(GameObject* obj)
{
    gEffectBoxObjects[gEffectBoxObjectCount++] = obj;
}

void Obj_SetActiveModelIndex(GameObject* obj, int idx)
{
    ObjAnimComponent* objAnim;

    objAnim = &obj->anim;
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

void objSetSlot(GameObject* obj, s8 slot)
{
    if (slot == 0x5a)
    {
        if ((obj->anim.modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE) == 0)
        {
            return;
        }
    }
    obj->anim.activeHitboxMode = slot;
}

int objApplyVelocity(GameObject* obj)
{
    obj->anim.localPosX += timeDelta * (lbl_803DE8B8 * (obj->externalVelX + obj->anim.velocityX));
    obj->anim.localPosY += timeDelta * (lbl_803DE8B8 * (obj->externalVelY + obj->anim.velocityY));
    obj->anim.localPosZ += timeDelta * (lbl_803DE8B8 * (obj->externalVelZ + obj->anim.velocityZ));
    return 1;
}

int objMove(GameObject* obj, f32 dx, f32 dy, f32 dz)
{
    int n;
    obj->anim.localPosX += dx;
    obj->anim.localPosY += dy;
    obj->anim.localPosZ += dz;
    ObjGroup_GetObjects(0, &n);
    return 0;
}

GameObject* getTrickyObject(void)
{
    int count;
    GameObject** objs = (GameObject**)ObjGroup_GetObjects(1, &count);
    if (count != 0)
    {
        return objs[0];
    }
    return NULL;
}

GameObject* Obj_GetPlayerObject(void)
{
    int count;
    GameObject** objs = (GameObject**)ObjGroup_GetObjects(0, &count);
    if (count != 0)
    {
        return objs[0];
    }
    return NULL;
}

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
    CameraViewSlot* vp;
    CharSpawn spawn;

    base = (u8*)(int)&gObjCameraSetupBlock;
    mapType = getCurMapType();
    if (mapType == MAPTYPE_UNLOAD_UNUSED || mapType == MAPTYPE_SUBMAP_UNUSED)
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
        if (playerNo > -1 && mapType != MAPTYPE_NO_HUD)
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
                    Obj_RegisterObject((GameObject*)obj, 1);
                    OSReport((char*)(base + 0x5c), *(int*)&((GameObject*)obj)->anim.modelInstance + 0x91);
                }
            }
        }
        *(f32*)(base + 8) = lbl_803DE8BC * mathSinf((gObjPi * (f32)(*(s8*)((u8*)pos + 0xc) << 8)) / lbl_803DE8C4) + x;
        *(f32*)(base + 0xc) = lbl_803DE8C8 + y;
        *(f32*)(base + 0x10) =
            lbl_803DE8BC * mathCosf((gObjPi * (f32)(*(s8*)((u8*)pos + 0xc) << 8)) / lbl_803DE8C4) + z;
        uiDll = getCurUiDll();
        if ((u32)(uiDll - 2) <= 4 || uiDll == 7)
        {
            (*gCameraInterface)->init(obj, *(f32*)(base + 8), *(f32*)(base + 0xc), *(f32*)(base + 0x10));
            (*gCameraInterface)->setMode(OBJECT_CAMMODE_TITLE, 0, 3, 0, NULL, 0, 0);
            (*gCameraInterface)->setFocus(obj, 0);
            (*gCameraInterface)->update(1);
        }
        else
        {
            (*gCameraInterface)->init(obj, *(f32*)(base + 8), *(f32*)(base + 0xc), *(f32*)(base + 0x10));
            (*gCameraInterface)->setMode(OBJECT_CAMMODE_DEFAULT, 0, 0, 0x20, (u8*)(int)&gObjCameraSetupBlock, 0, 0xff);
            (*gCameraInterface)->update(1);
        }
        vp = Camera_GetCurrentViewSlot();
        view = (*gCameraInterface)->getCamera();
        vp->x = *(f32*)(view + 0x18);
        vp->y = *(f32*)(view + 0x1c);
        vp->z = *(f32*)(view + 0x20);
        gTitleMenuControlInterface->vtable->func07(obj);
        lbl_803DCB70 = 0;
        playerUpdateFn_8005649c();
    }
}

char sObjDebugStrings[] = {
    0x4C, 0x4F, 0x41, 0x44, 0x45, 0x44, 0x20, 0x4F, 0x42, 0x4A, 0x45, 0x43, 0x54, 0x20, 0x25, 0x73, 0x0A, 0x00,
    0x00, 0x00, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x20, 0x20, 0x4F, 0x42, 0x4A, 0x46, 0x52, 0x45, 0x45,
    0x41, 0x4C, 0x4C, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x20, 0x20, 0x20,
    0x20, 0x4C, 0x4F, 0x41, 0x44, 0x49, 0x4E, 0x47, 0x20, 0x43, 0x48, 0x41, 0x52, 0x41, 0x43, 0x54, 0x45, 0x52,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x6D, 0x61, 0x70, 0x74, 0x79, 0x70, 0x65, 0x20, 0x25, 0x64, 0x20, 0x20, 0x70,
    0x6C, 0x61, 0x79, 0x65, 0x72, 0x6E, 0x6F, 0x20, 0x25, 0x64, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x00,
};

char sObjSetupObjectLoadingLockedWarning[] = "<objSetupObject>  loading is locked can't setup objno %d\n";
