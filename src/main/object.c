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
#include "dolphin/mtx.h"
#include "main/audio/sfx.h"
#include "main/audio/stream_api.h"
#include "main/camera_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/dll_0057_cameramodetitle.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/waterfx_interface.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/mapEvent.h"
#include "main/object_transform.h"
#include "main/objHitReact.h"
#include "main/objanim.h"
#include "main/obj_contact.h"
#include "main/objtype.h"
#include "main/obj_list.h"
#include "main/objhits.h"
#include "main/dll/player_state.h"
#include "main/objseq.h"
#include "main/loaded_file_flags.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/mm.h"
#include "main/texture.h"
#include "main/camera.h"
#include "sys/objects/lifecycle.h"
#include "main/object_update_list.h"
#include "sys/objects.h"
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
#include "main/dll/dll_0017_savegame_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/mapEventTypes.h"
#include "dolphin/mtx/vec.h"

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
GameObject** gObjPendingDefFreeList;
int gObjPendingDefFreeCount;
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

/* ObjGroup ids (registered/unregistered in objSetupObject / Obj_FreeObject) */
#define OBJECT_OBJGROUP_HITBOX 6 /* joined when modelInstance flags & 0x40 (SKIP_RESET_UPDATE) */
#define OBJECT_OBJGROUP_GROUP8 8 /* joined when modelInstance->group8RegistrationCount > 0 */

enum
{
    OBJ_LIST_CAPACITY = 600,
    OBJ_DEFERRED_FREE_CAPACITY = 400,
    OBJ_PENDING_DEF_FREE_CAPACITY = 24
};

/* loadCharacter model-load config word, passed to ObjModel_Load etc. */
#define OBJLOAD_FLAG_HAS_SHADOW    0x0002 /* modelDef->shadowType != 0 */
#define OBJLOAD_FLAG_ANIM_EVENTS   0x0040 /* allocate anim move-event table */
#define OBJLOAD_FLAG_WEAPON_DA     0x0100 /* allocate weapon-DA table */
#define OBJLOAD_FLAG_SINGLE_MODEL  0x0200 /* skip multi-model loop (modelDef->flags & 1) */
#define OBJLOAD_FLAG_INDEXED_MODEL 0x0400 /* load one model at index encoded in bits 11-14 */
#define OBJLOAD_FLAG_SHADOW_TYPE3  0x8000 /* modelDef->shadowType == 3 */

GameObject* gEffectBoxObjects[20];

void Obj_RegisterObject(GameObject* obj, int b);
void* loadModLines(int n, s16* out);

u8 gObjCameraSetupBlock[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x3C, 0x00, 0x5A, 0x00, 0x55, 0x1E, 0x14,
};

char sObjSetupObjectLoadingLockedWarning[] = "<objSetupObject>  loading is locked can't setup objno %d\n";

char sObjDebugStrings[] = {
    0x4C, 0x4F, 0x41, 0x44, 0x45, 0x44, 0x20, 0x4F, 0x42, 0x4A, 0x45, 0x43, 0x54, 0x20, 0x25, 0x73, 0x0A, 0x00,
    0x00, 0x00, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x3D, 0x20, 0x20, 0x4F, 0x42, 0x4A, 0x46, 0x52, 0x45, 0x45,
    0x41, 0x4C, 0x4C, 0x20, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x20, 0x20, 0x20,
    0x20, 0x4C, 0x4F, 0x41, 0x44, 0x49, 0x4E, 0x47, 0x20, 0x43, 0x48, 0x41, 0x52, 0x41, 0x43, 0x54, 0x45, 0x52,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x6D, 0x61, 0x70, 0x74, 0x79, 0x70, 0x65, 0x20, 0x25, 0x64, 0x20, 0x20, 0x70,
    0x6C, 0x61, 0x79, 0x65, 0x72, 0x6E, 0x6F, 0x20, 0x25, 0x64, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x00,
};

char sObjFreeObjdefError[] = "objFreeObjdef: Error!! (%d)\n";

char sObjFreeNonExistentObjectWarning[] = "Tried to free non-existent object\n";

char sObjUnknownTypeUsingDummyObjectWarning[] =
    "Warning: Unknown object type '%d/%d romdefno %d', using DummyObject (128)\n";

void Obj_RunInitCallback(GameObject* obj, void* placementData, int unused);

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

    len = 6.284f * obj->anim.hitboxScale;
    denom = len * obj->anim.rootMotionScale;
    dx = ((obj->anim.previousLocalPosZ - gMapSavedPlayerOffsetZ) -
          (obj->anim.localPosZ - playerMapOffsetZ)) /
         denom;
    dz = ((obj->anim.localPosX - gMapSavedPlayerOffsetX) -
          (obj->anim.previousLocalPosX - playerMapOffsetX)) /
         denom;
    sum = dz * dz + dx * dx;
    if (sum > 0.0f)
    {
        len = sqrtf(sum);
        vecA[0] = dz / len;
        vecA[1] = 0.0f;
        vecA[2] = -dx / len;
        vecB[0] = 0.0f;
        vecB[1] = 1.0f;
        vecB[2] = 0.0f;
        PSVECCrossProduct((Vec*)vecA, (Vec*)vecB, (Vec*)cross);
        PSMTXRotAxisRad((MtxPtr)rot, (Vec*)cross, 3.142f * (2.0f * -len));
        setMatrixFromObjectTransposed(obj, m2);
        m2[3] = 0.0f;
        m2[7] = 0.0f;
        m2[11] = 0.0f;
        PSMTXConcat((MtxPtr)rot, (MtxPtr)m2, (MtxPtr)rot);
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
    model = objAnim->modelBanks[objAnim->bankIndex];
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
    GameObject* childScan;
    int i;

    if ((obj->colorFadeFlags & OBJ_COLOR_FADE_FLAG_INCREASING) != 0)
    {
        alpha = obj->colorFadeAlpha + 12.0f * timeDelta;
    }
    else
    {
        alpha = obj->colorFadeAlpha - 12.0f * timeDelta;
    }

    if (alpha < 0.0f)
    {
        alpha = -alpha;
        obj->colorFadeFlags ^= OBJ_COLOR_FADE_FLAG_INCREASING;
    }
    else if (alpha > 127.0f)
    {
        alpha = 127.0f - (alpha - 127.0f);
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
    childScan = (GameObject*)((u8*)obj);
    while (i < obj->childCount)
    {
        Obj_TickModelColorFadeRecursive(childScan->childObjs[i]);
        i++;
    }
}

int objGetFlagsE5_2(u8* obj)
{
    return ((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE;
}

void Obj_SetModelColorFadeRecursive(GameObject* obj, int frames, u8 red, u8 green, u8 blue, u8 startAtHalf)
{
    GameObject* childScan;
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
    childScan = (GameObject*)((u8*)obj);
    while (i < obj->childCount)
    {
        Obj_SetModelColorFadeRecursive(childScan->childObjs[i], frames, red, green, blue, startAtHalf);
        i++;
    }
}
void Obj_SetModelColorOverrideRecursive(GameObject* obj, u8 red, u8 green, u8 blue, u8 alpha, u8 enabled)
{
    GameObject* childScan;
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
    childScan = (GameObject*)((u8*)obj);
    while (i < obj->childCount)
    {
        Obj_SetModelColorOverrideRecursive(childScan->childObjs[i], red, green, blue,
                                           alpha, enabled);
        i++;
    }
}

void Obj_Shatter(GameObject* obj)
{
    obj->colorFadeFrames = 0;
    obj->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_FROZEN;
    obj->fadeCounter = 0;
    ObjModel_ClearRenderAttachment(obj->anim.modelBanks[obj->anim.bankIndex]);
    (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fb, NULL, 0x50, NULL);
    (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fc, NULL, 0x32, NULL);
}

int objIsFrozen(GameObject* obj)
{
    return obj->colorFadeFlags & OBJ_COLOR_FADE_FLAG_FROZEN;
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
            ObjModel_EnableDefaultRenderCallback(obj, objAnim->modelBanks[objAnim->bankIndex], mtx, 1,
                                                 obj->anim.hitboxScale * obj->anim.rootMotionScale);
            (*gBoneParticleEffectInterface)->spawnEffect(obj, 0x7fc, NULL, 0x64, NULL);
        }
    }
}

void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst)
{
    f32 mtx[16];
    Obj_BuildWorldTransformMatrix((GameObject*)obj, mtx, 0);
    PSMTXMultVecSR((MtxPtr)mtx, (Vec*)src, (Vec*)dst);
}

void Obj_TransformLocalPointByWorldMatrix(u8* obj, f32* src, f32* dst, u8 flag)
{
    f32 savedZ;
    f32 mtx[16];
    if (flag)
    {
        savedZ = ((GameObject*)obj)->anim.rootMotionScale;
        ((GameObject*)obj)->anim.rootMotionScale = 1.0f;
    }
    Obj_BuildWorldTransformMatrix((GameObject*)obj, mtx, 0);
    PSMTXMultVec((MtxPtr)mtx, (Vec*)src, (Vec*)dst);
    if (flag)
    {
        ((GameObject*)obj)->anim.rootMotionScale = savedZ;
    }
    dst[0] += playerMapOffsetX;
    dst[2] += playerMapOffsetZ;
}

void objWorldToLocalPos(f32* out, MatrixTransform* transform, f32* in)
{
    f32 rotated[3];
    MatrixTransform inverse;
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
    inverse.scale = 1.0f;
    mtxRotateByVec3s(rotMtx, &inverse);
    mtx44Transpose(rotMtx, transposed);
    PSMTXMultVec((MtxPtr)transposed, (Vec*)in, (Vec*)rotated);
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

    if (obj->anim.parent == NULL)
    {
        obj->anim.localPosX -= playerMapOffsetX;
        obj->anim.localPosZ -= playerMapOffsetZ;
    }
    transform.x = -obj->anim.localPosX;
    transform.y = -obj->anim.localPosY;
    transform.z = -obj->anim.localPosZ;
    transform.rotX = -obj->anim.rotX;
    transform.rotY = -obj->anim.rotY;
    transform.rotZ = -obj->anim.rotZ;
    transform.scale = 1.0f;
    mtxRotateByVec3s(rotMtx, &transform);
    mtx44Transpose(rotMtx, out);
    if (obj->anim.parent == NULL)
    {
        obj->anim.localPosX += playerMapOffsetX;
        obj->anim.localPosZ += playerMapOffsetZ;
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
            scale = 1.0f;
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
        PSMTXConcat((MtxPtr)parentMtx, (MtxPtr)mtx, (MtxPtr)mtx);
    }
}

ObjModel* Obj_GetActiveModel(GameObject* obj)
{
    return obj->anim.modelBanks[obj->anim.bankIndex];
}

GameObject* loadObjectAtObject(GameObject* src, ObjPlacement* setup)
{
    GameObject* obj;
    int type;
    void* objF30;
    objF30 = src->anim.parent;
    type = src->anim.mapEventSlot;
    if (getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED)
    {
        OSReport(sObjSetupObjectLoadingLockedWarning, -1);
        obj = NULL;
    }
    else
    {
        obj = loadCharacter((s16*)setup, 5, type, -1, objF30, 0);
        if (obj != NULL)
        {
            Obj_RegisterObject(obj, 5);
            OSReport(sObjDebugStrings, obj->anim.modelInstance->name);
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
        if ((obj->anim.modelInstance->flags & OBJDEF_FLAG_HITBOX_GROUP) == 0)
        {
            return;
        }
    }
    obj->anim.activeHitboxMode = slot;
}

int objApplyVelocity(GameObject* obj)
{
    obj->anim.localPosX += timeDelta * (0.5f * (obj->externalVelX + obj->anim.velocityX));
    obj->anim.localPosY += timeDelta * (0.5f * (obj->externalVelY + obj->anim.velocityY));
    obj->anim.localPosZ += timeDelta * (0.5f * (obj->externalVelZ + obj->anim.velocityZ));
    return 1;
}

int objMove(GameObject* obj, f32 dx, f32 dy, f32 dz)
{
    int n;
    obj->anim.localPosX += dx;
    obj->anim.localPosY += dy;
    obj->anim.localPosZ += dz;
    objGetAllOfType(0, &n);
    return 0;
}

GameObject* getTrickyObject(void) {
    int count;
    GameObject** objs = objGetAllOfType(1, &count);
    if (count != 0) {
        return objs[0];
    }
    return NULL;
}

GameObject* Obj_GetPlayerObject(void) {
    int count;
    GameObject** objs = objGetAllOfType(0, &count);
    if (count != 0) {
        return objs[0];
    }
    return NULL;
}

void mapSetupPlayer(void) {
    u8* base;
    int playerNo;
    int mapType;
    GameObject* obj;
    SaveGameCharacterPosition* pos;
    f32 x, y, z;
    int uiDll;
    CameraObject* view;
    Camera* vp;
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
        pos = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
        x = pos->x;
        y = pos->y;
        z = pos->z;
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
            if (getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED)
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
                    OSReport((char*)(base + 0x5c), obj->anim.modelInstance->name);
                }
            }
        }
        *(f32*)(base + 8) = 60.0f * mathSinf((3.1415927f * (f32)(pos->angle << 8)) / 32768.0f) + x;
        *(f32*)(base + 0xc) = 40.0f + y;
        *(f32*)(base + 0x10) =
            60.0f * mathCosf((3.1415927f * (f32)(pos->angle << 8)) / 32768.0f) + z;
        uiDll = getCurUiDll();
        if ((u32)(uiDll - 2) <= 4 || uiDll == 7)
        {
            (*gCameraInterface)->init(obj, *(f32*)(base + 8), *(f32*)(base + 0xc), *(f32*)(base + 0x10));
            (*gCameraInterface)->setMode(CAMERA_MODE_TITLE_RESOURCE_ID, 0, 3, 0, NULL, 0, 0);
            (*gCameraInterface)->setFocus(obj, 0);
            (*gCameraInterface)->update(1);
        }
        else
        {
            (*gCameraInterface)->init(obj, *(f32*)(base + 8), *(f32*)(base + 0xc), *(f32*)(base + 0x10));
            (*gCameraInterface)->setMode(OBJECT_CAMMODE_DEFAULT, 0, 0, 0x20, (u8*)(int)&gObjCameraSetupBlock, 0, 0xff);
            (*gCameraInterface)->update(1);
        }
        vp = Camera_GetCurrent();
        view = (*gCameraInterface)->getCamera();
        vp->x = view->anim.worldPosX;
        vp->y = view->anim.worldPosY;
        vp->z = view->anim.worldPosZ;
        gTitleMenuControlInterface->vtable->func07(obj);
        lbl_803DCB70 = 0;
        mapUpdateCameraPosByTransformSpace();
    }
}

ObjPlacement* Obj_AllocObjectSetup(int size, int type)
{
    ObjPlacement* p = mmAlloc(size, 0xe, 0);
    memset(p, 0, size);
    p->ident = -1;
    p->color[2] = 0x64;
    p->color[3] = 0x96;
    p->color[0] = 8;
    p->color[1] = 4;
    p->objectId = type;
    p->size = size;
    return p;
}
static void objFreeObjdef(u8* obj, int flag)
{
    int defs[40];
    void (*fp)(u8*, int);
    void (*cb)(u8*);
    BoneParticleEffectSpawnFn cb2;
    int i;
    int j;
    int n;
    int count;
    GameObject* otherObj;
    int* bp;
    void* curTex;
    void* tex;
    ObjectShadowMesh* shadowMesh;
    int modelCount;
    int group;

    if (*(u8*)&((GameObject*)obj)->contactRefCount != 0)
    {
        ObjContact_RemoveObjectCallbacks((GameObject*)obj);
    }
    switch (((GameObject*)obj)->anim.romDefNo)
    {
    case 0:
    case 0x1f:
        playerFree((GameObject*)obj, flag);
        break;
    default:
        if (((GameObject*)obj)->anim.dll != NULL)
        {
            fp = (void (*)(u8*, int))((ObjectInterface*)*((GameObject*)obj)->anim.dll)->free;
            if (fp != NULL)
            {
                fp(obj, flag);
            }
            Resource_Release(((GameObject*)obj)->anim.dll);
            ((GameObject*)obj)->anim.dll = NULL;
        }
        break;
    }
    gTitleMenuControlInterface->vtable->func15(obj);
    (*gExpgfxInterface)->freeOwner3((u32)(GameObject*)obj);
    if (((ObjAnimComponent*)obj)->modelInstance->flags & OBJDEF_FLAG_HITBOX_GROUP)
    {
        objFreeObjectType((GameObject*)obj, OBJECT_OBJGROUP_HITBOX);
        if (flag == 0)
        {
            count = 0;
            for (i = 0; i < gObjCount; i++)
            {
                otherObj = gObjList[i];
                if (*(int*)&otherObj->anim.parent == (int)obj)
                {
                    otherObj->anim.parent = NULL;
                    if (*(void**)&otherObj->anim.placementData != NULL)
                    {
                        defs[count++] = (int)otherObj;
                    }
                }
            }
            for (n = 0; n < count; n++)
            {
                Obj_FreeObject((GameObject*)defs[n]);
            }
            mapUnloadRomListPage(((GameObject*)obj)->anim.hostedMapSlot);
        }
    }
    if (flag == 0 && ((GameObject*)obj)->anim.classId == 0x10)
    {
        for (i = 0; i < gObjCount; i++)
        {
            otherObj = gObjList[i];
            if (*(int*)&otherObj->pendingParentObj == (int)obj)
            {
                otherObj->pendingParentObj = NULL;
            }
        }
    }
    for (j = 0; j < gObjCount; j++)
    {
        if (gObjList[j]->anim.classId == 0x10)
        {
            bp = (int*)gObjList[j]->extra;
            if (*(u8**)bp == obj)
            {
                *bp = 0;
                *((u8*)bp + 0x8f) = 1;
            }
        }
    }
    if (((ObjAnimComponent*)obj)->modelInstance->group8RegistrationCount > 0)
    {
        objFreeObjectType((GameObject*)obj, OBJECT_OBJGROUP_GROUP8);
    }
    if (((ObjAnimComponent*)obj)->modelState != NULL)
    {
        if (((ObjAnimComponent*)obj)->modelInstance->shadowType == OBJ_SHADOW_TYPE_BIG_BOX)
        {
            shadowVolumesSetDirty(1);
        }
        if (((ObjAnimComponent*)obj)->modelState->shadowTexture != NULL)
        {
            curTex = (void*)newshadows_getSmallDiskTexture();
            tex = ((ObjAnimComponent*)obj)->modelState->shadowTexture;
            if (tex != curTex)
            {
                if (((ObjAnimComponent*)obj)->modelInstance->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW)
                {
                    mm_free(tex);
                }
                else
                {
                    textureFree((Texture*)(tex));
                }
            }
        }
        if (((ObjAnimComponent*)obj)->modelState->shadowWorkBuffer != NULL)
        {
            mm_free(((ObjAnimComponent*)obj)->modelState->shadowWorkBuffer);
        }
        shadowMesh = ((ObjAnimComponent*)obj)->modelState->shadowRenderResource;
        if (shadowMesh != NULL && shadowMesh != OBJECT_SHADOW_MESH_UNCACHED)
        {
            mm_free(shadowMesh);
        }
    }
    if (*(void**)&((GameObject*)obj)->msgQueue != NULL)
    {
        mm_free(((GameObject*)obj)->msgQueue);
        ((GameObject*)obj)->msgQueue = NULL;
    }
    modelCount = ((ObjAnimComponent*)obj)->modelInstance->modelCount;
    for (j = 0; j < modelCount; j++)
    {
        if ((int)((ObjAnimComponent*)obj)->banks[j] != 0)
        {
            ObjModel_Release((u8*)((ObjAnimComponent*)obj)->banks[j]);
        }
    }
    if (((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_FROZEN)
    {
        ((GameObject*)obj)->colorFadeFrames = 0;
        ((GameObject*)obj)->colorFadeFlags = ((GameObject*)obj)->colorFadeFlags & ~OBJ_COLOR_FADE_FLAG_FROZEN;
        ((GameObject*)obj)->fadeCounter = 0;
        ObjModel_ClearRenderAttachment((ObjModel*)((ObjAnimComponent*)obj)->banks[((ObjAnimComponent*)obj)->bankIndex]);
        cb2 = (*gBoneParticleEffectInterface)->spawnEffect;
        cb2(obj, 0x7fb, NULL, 0x50, NULL);
        cb2 = (*gBoneParticleEffectInterface)->spawnEffect;
        cb2(obj, 0x7fc, NULL, 0x32, NULL);
    }
    if (((GameObject*)obj)->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE)
    {
        Obj_ClearModelColorFadeRecursive((GameObject*)obj);
    }
    group = objGetObjectType((GameObject*)obj);
    if (group != 0)
    {
        objFreeObjectType((GameObject*)obj, group - 1);
    }
    {
        s16 type;
        u8* refCounts;

        type = ((GameObject*)obj)->anim.defId;
        refCounts = gObjFileRefCount;
        if (refCounts[((GameObject*)obj)->anim.defId] == 0)
        {
            debugPrintf(sObjFreeObjdefError);
        }
        else
        {
            refCounts[type]--;
            if (gObjFileRefCount[type] == 0)
            {
                otherObj = (GameObject*)gObjFileBufferTable[type];
                if (*(void**)&otherObj->anim.parent != NULL)
                {
                    mm_free(otherObj->anim.parent);
                }
                if (*(void**)((u8*)otherObj + 0x34) != NULL)
                {
                    mm_free(*(void**)((u8*)otherObj + 0x34));
                }
                mm_free(otherObj);
            }
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
    if ((*(s16*)&((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) &&
        *(void**)&((GameObject*)obj)->anim.placementData != NULL)
    {
        mm_free(((GameObject*)obj)->anim.placementData);
    }
    mm_free(obj);
}

void Obj_RegisterObject(GameObject* obj, int b);

void* loadModLines(int idx, s16* outCount)
{
    void* result;
    int* hdr;
    int size;
    int start;

    result = 0;
    if (idx > (getDataFileSize(MLDF_FILEID_MODLINES_TAB) - 4) >> 2)
    {
        return 0;
    }
    hdr = mmAlloc(0x10, 0x1a, 0);
    fileLoadToBufferOffset(MLDF_FILEID_MODLINES_TAB, hdr, idx << 2, 8);
    start = hdr[0];
    size = hdr[1] - hdr[0];
    if (size > 0)
    {
        result = mmAlloc(size, 5, 0);
        fileLoadToBufferOffset(MLDF_FILEID_MODLINES_BIN, result, start, size);
    }
    mm_free(hdr);
    *outCount = (u32)size / 20;
    return result;
}

static inline void Obj_FreeDeferredObjects(void)
{
    int i;
    for (i = 0; i < gObjDeferredFreeCount; i++)
    {
        void* p = gObjDeferredFreeList[i];
        if (p != NULL)
        {
            objFreeObjdef(p, 0);
            gObjDeferredFreeList[i] = NULL;
        }
    }
}

u8* loadObjectFile(int id)
{
    int size;
    int base;
    ObjDef* buf;
    int n;
    s16 modLine;

    if (id >= gObjFileCount)
    {
        return 0;
    }
    if (gObjFileRefCount[id] != 0)
    {
        gObjFileRefCount[id]++;
        return gObjFileBufferTable[id];
    }
    {
        int* offsets = (int*)gObjFileOffsetTable;
        base = offsets[id];
        size = (&offsets[id])[1] - base;
    }
    buf = (ObjDef*)mmAlloc(size, 0xe, 0);
    if (buf != 0)
    {
        fileLoadToBufferOffset(MLDF_FILEID_OBJECTS_BIN, (u8*)buf, base, size);
        if (buf->eventMoveTable != NULL)
        {
            buf->eventMoveTable = (s16*)((int)buf + (int)buf->eventMoveTable);
        }
        if (buf->hitReactMoveTable != NULL)
        {
            buf->hitReactMoveTable =
                (ObjHitReactMoveEntry*)((int)buf + (int)buf->hitReactMoveTable);
        }
        if (buf->weaponDaTable != NULL)
        {
            buf->weaponDaTable = (s16*)((int)buf + (int)buf->weaponDaTable);
        }
        buf->modelFileIds = (s32*)((int)buf + (int)buf->modelFileIds);
        buf->textureSlotDefs = (ObjTextureSlotDef*)((int)buf + (int)buf->textureSlotDefs);
        buf->jointData = (s8*)((int)buf + (int)buf->jointData);
        if (buf->extraSetupData != NULL)
        {
            buf->extraSetupData = (u8*)((int)buf + (int)buf->extraSetupData);
        }
        if (buf->hitVolumes != NULL)
        {
            buf->hitVolumes = (ObjDefHitVolume*)((int)buf + (int)buf->hitVolumes);
        }
        if (buf->sequenceMap != NULL)
        {
            buf->sequenceMap = (s16*)((int)buf + (int)buf->sequenceMap);
        }
        buf->attachPoints = (ObjAttachPoint*)((int)buf + (int)buf->attachPoints);
        buf->modLines = NULL;
        buf->intersectionLines = NULL;
        n = (s8)((u8*)buf)[0x5d];
        if (n > -1)
        {
            buf->modLines = (struct MapHitLine*)loadModLines(n, &modLine);
            buf->modLineCount = modLine;
            intersectModLineBuild((IntersectModLineObject*)buf);
        }
        gObjFileBufferTable[id] = (u8*)buf;
        gObjFileRefCount[id] = 1;
    }
    else
    {
        return 0;
    }
    return (u8*)buf;
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
                getTabEntry(weaponDaTable->entries, MLDF_FILEID_WEAPONDA_BIN, da2, weaponDaTable->byteCount);
            }
            else
            {
                fileLoadToBufferOffset(MLDF_FILEID_WEAPONDA_BIN, weaponDaTable->entries, da2, weaponDaTable->byteCount);
            }
            return;
        }
        i += 3;
    }
}

#pragma dont_inline on
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
                getTabEntry(eventTable->entries, MLDF_FILEID_OBJEVENT_BIN, da2, eventTable->byteCount);
            }
            else
            {
                fileLoadToBufferOffset(MLDF_FILEID_OBJEVENT_BIN, eventTable->entries, da2, eventTable->byteCount);
            }
            return;
        }
        i += 3;
    }
}
#pragma dont_inline reset

void Obj_UpdateObject(GameObject* obj)
{
    ObjAnimComponent* object;
    u8* t;
    BoneParticleEffectSpawnFn cb;
    void (*cb2)(GameObject*);

    object = &obj->anim;
    if (obj->objectFlags & OBJECT_FLAG_FREED)
    {
        return;
    }
    if (gObjUpdateFlags & 1)
    {
        switch (object->romDefNo)
        {
        case OBJECT_SEQID_SABRE:
        case OBJECT_SEQID_KRYSTAL:
            playerUpdateWhileTimeStopped(obj);
            break;
        case OBJECT_SEQID_STAFF:
            staffUpdateWhileTimeStopped(obj);
            break;
        case OBJECT_SEQID_DIE_DUSTER:
        case OBJECT_SEQID_DIE_FOX:
        case OBJECT_SEQID_DIE_KRYSTAL:
            cb2 = (void (*)(GameObject*))((ObjectInterface*)*object->dll)->update;
            cb2(obj);
            break;
        }
        return;
    }
    if (obj->colorFadeFlags != 0 && obj->ownerObj == NULL &&
        (obj->colorFadeFlags & OBJ_COLOR_FADE_FLAG_ACTIVE))
    {
        Obj_TickModelColorFadeRecursive(obj);
    }
    if (obj->pendingParentObj != NULL)
    {
        if (obj->childObjs[0] != NULL)
        {
            t = (u8*)((GameObject*)obj->childObjs[0])->anim.hitReactState;
            if (t != 0)
            {
                ((ObjHitsPriorityState*)((GameObject*)obj->childObjs[0])->anim.hitReactState)->lastHitObject = 0;
                ((ObjHitsPriorityState*)((GameObject*)obj->childObjs[0])->anim.hitReactState)->priorityHitCount = 0;
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
    obj->externalVelX = object->velocityX;
    obj->externalVelY = object->velocityY;
    obj->externalVelZ = object->velocityZ;
    if (obj->colorFadeFlags != 0 && obj->ownerObj == NULL &&
        (obj->colorFadeFlags & OBJ_COLOR_FADE_FLAG_FROZEN))
    {
        obj->colorFadeFrames = (s16)((f32)obj->colorFadeFrames - timeDelta);
        if (obj->colorFadeFrames <= 0)
        {
            obj->colorFadeFrames = 0;
            obj->colorFadeFlags &= ~OBJ_COLOR_FADE_FLAG_FROZEN;
            obj->fadeCounter = 0;
            ObjModel_ClearRenderAttachment(object->modelBanks[object->bankIndex]);
            cb = (*gBoneParticleEffectInterface)->spawnEffect;
            cb(obj, 0x7fb, NULL, 0x50, NULL);
            cb = (*gBoneParticleEffectInterface)->spawnEffect;
            cb(obj, 0x7fc, NULL, 0x32, NULL);
            Sfx_PlayFromObject(obj, SFXTRIG_barrel_bounce1);
        }
    }
    if ((obj->objectFlags & OBJECT_OBJFLAG_UPDATE_DISABLED) == 0)
    {
        do
        {
            switch (object->romDefNo)
            {
            case OBJECT_SEQID_SABRE:
            case OBJECT_SEQID_KRYSTAL:
                playerUpdate(obj);
                break;
            default:
                if (object->dll == NULL)
                {
                    continue;
                }
                cb2 = (void (*)(GameObject*))((ObjectInterface*)*object->dll)->update;
                if (cb2 != 0)
                {
                    cb2(obj);
                }
                break;
            }
            Obj_GetWorldPosition(obj, &object->worldPosX, &object->worldPosY, &object->worldPosZ);
        } while (0);
    }
    if (object->hitReactState != NULL)
    {
        if (obj->childObjs[0] != NULL)
        {
            t = (u8*)((GameObject*)obj->childObjs[0])->anim.hitReactState;
            if (t != 0)
            {
                ((ObjHitsPriorityState*)((GameObject*)obj->childObjs[0])->anim.hitReactState)->lastHitObject = 0;
                ((ObjHitsPriorityState*)((GameObject*)obj->childObjs[0])->anim.hitReactState)->priorityHitCount = 0;
            }
        }
        ((ObjHitsPriorityState*)object->hitReactState)->lastHitObject = 0;
        ((ObjHitsPriorityState*)object->hitReactState)->priorityHitCount = 0;
    }
    if (obj->anim.hitboxTransformState != NULL)
    {
        obj->anim.hitboxTransformState->contactObjectCount = 0;
    }
}

void Obj_RunInitCallback(GameObject* obj, void* placementData, int unused)
{
    s16 mode = obj->anim.romDefNo;
    switch (mode)
    {
    case 0x1f:
    case 0:
        objLoadPlayerFromSave(obj);
        break;
    default:
    {
        ObjectInterfaceHandle p = obj->anim.dll;
        if (p != NULL)
        {
            int fn = ((int*)*p)[1];
            if (fn != -1 && (void*)fn != NULL)
            {
                ((void (*)(GameObject*))fn)(obj);
            }
        }
        break;
    }
    }
    {
        ObjModelState* modelState = obj->anim.modelState;
        if (modelState != NULL)
        {
            modelState->flags |= OBJ_MODEL_STATE_SHADOW_INIT_CALLBACK_RAN;
        }
    }
    {
        f32 zero;
        obj->anim.previousLocalPosX = obj->anim.localPosX;
        obj->anim.previousLocalPosY = obj->anim.localPosY;
        obj->anim.previousLocalPosZ = obj->anim.localPosZ;
        obj->anim.previousWorldPosX = obj->anim.localPosX;
        obj->anim.previousWorldPosY = obj->anim.localPosY;
        obj->anim.previousWorldPosZ = obj->anim.localPosZ;
        zero = 0.0f;
        obj->externalVelX = zero;
        obj->externalVelY = zero;
        obj->externalVelZ = zero;
    }
}

void Obj_FreeObject(GameObject* obj)
{
    int i;
    GameObject** base;
    int off;
    u8* q;

    if (obj->objectFlags & OBJECT_FLAG_FREED)
    {
        return;
    }
    Sfx_RemoveLoopedObjectSoundForObject(obj);
    Sfx_StopObjectChannel(obj, 0x7f);
    if (obj->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
    {
        for (i = 0; i < gObjCount; i++)
        {
            if (gObjList[i] == obj)
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
        if (obj->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
        {
            objList_remove(&gObjUpdateList, (int)obj);
        }
        gObjPartitionPivot = 0;
    }
    for (i = 0; i < gObjDeferredFreeCount; i++)
    {
    }
    obj->objectFlags |= OBJECT_FLAG_FREED;
    if (obj->unkEA != 0)
    {
        i = 0;
        base = gObjPendingDefFreeList;
        for (; i < gObjPendingDefFreeCount; i++)
        {
            if (base[i] == obj)
            {
                break;
            }
        }
        if (i == gObjPendingDefFreeCount)
        {
            if (gObjPendingDefFreeCount < OBJ_PENDING_DEF_FREE_CAPACITY)
            {
                gObjPendingDefFreeList[gObjPendingDefFreeCount] = obj;
                gObjPendingDefFreeCount++;
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
                if (gObjDeferredFreeList[i] == obj)
                {
                    break;
                }
            }
        }
        if (i == gObjDeferredFreeCount)
        {
            gObjDeferredFreeList[gObjDeferredFreeCount] = obj;
            gObjDeferredFreeCount++;
            if (gObjDeferredFreeCount == OBJ_DEFERRED_FREE_CAPACITY)
            {
                gObjDeferredFreeCount--;
            }
        }
    }
    else
    {
        objFreeObjdef((u8*)obj, !gObjDefCaptureMode);
    }
}

void Obj_InsertIntoUpdateList(GameObject* obj)
{
    if (obj->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
    {
        ObjLinkedList* list = &gObjUpdateList;
        int prev = 0;
        int cur = list->head;
        int linkOff = list->nextOffset;
        while (cur != 0 && obj->anim.activeHitboxMode < ((GameObject*)cur)->anim.activeHitboxMode)
        {
            prev = cur;
            cur = *(int*)((u8*)cur + linkOff);
        }
        objListAdd(&gObjUpdateList, prev, (int)obj);
    }
}

void Obj_RemoveFromUpdateList(GameObject* obj)
{
    if (obj->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
    {
        objList_remove(&gObjUpdateList, (int)obj);
    }
}

void modelInitBones(f32 scale, void* model)
{
    f32* srcP;
    int off;
    int boneOff;
    f32* sumP;
    ModelFileHeader* hdr;
    ModelJointWork* tbl;
    int i;
    int parent;
    f32* src;
    ModelBone* bone;
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
    ObjModel* m = model;

    sc = scale;
    hdr = (ModelFileHeader*)*(u8**)m;
    if ((!hdr->flags & 0x1000) || (hdr->jointCount == 0))
    {
        return;
    }
    {
        if ((src = (f32*)hdr->unk18) != NULL && (tbl = m->skeletonJointData) != NULL)
        {
            zero = 0.0f;
            tbl->jointRadii[0] = src[0] * sc;
            if (tbl->jointRadii[0] == zero)
            {
                tbl->jointRadii[0] = src[1] * sc;
            }
            tbl->radiiSq[0] = tbl->jointRadii[0] * tbl->jointRadii[0];
            tbl->jointLengths[0] = 0.01f;
            tbl->jointCullDistances[0] = tbl->jointRadii[0];
            sums[0] = zero;
            i = 1;
            srcP = src + 1;
            off = 4;
            boneOff = 0x1c;
            sumP = &sums[1];
            for (; i < m->file->jointCount; srcP++, off += 4, boneOff += 0x1c, sumP++, i++)
            {
                *(f32*)((u8*)tbl->jointRadii + off) = sc * *srcP;
                *(f32*)((u8*)tbl->radiiSq + off) =
                    *(f32*)((u8*)tbl->jointRadii + off) * *(f32*)((u8*)tbl->jointRadii + off);
                bone = (ModelBone*)(hdr->jointData + boneOff);
                parent = bone->parent;
                vx = bone->head[0];
                vy = bone->head[1];
                vz = bone->head[2];
                len = sqrtf(vx * vx + vy * vy + vz * vz);
                *(f32*)((u8*)tbl->jointLengths + off) = sc * len;
                v = *(f32*)((u8*)tbl->jointLengths + off);
                if (v == zero)
                {
                    *(f32*)((u8*)tbl->jointLengths + off) = 0.1f;
                }
                w = *(f32*)(hdr->unk1C + off);
                if (w >= 1.0f)
                {
                    *(f32*)((u8*)tbl->jointLengths + off) *= w;
                }
                *sumP = sums[parent] + *(f32*)((u8*)tbl->jointLengths + off);
                if (*srcP == zero)
                {
                    *(f32*)((u8*)tbl->jointCullDistances + off) =
                        *(f32*)((u8*)tbl->jointCullDistances + parent * 4);
                }
                else
                {
                    *(f32*)((u8*)tbl->jointCullDistances + off) =
                        *sumP + *(f32*)((u8*)tbl->jointRadii + off);
                    v = *(f32*)((u8*)tbl->jointCullDistances + off);
                    pv = *(f32*)((u8*)tbl->jointCullDistances + parent * 4);
                    *(f32*)((u8*)tbl->jointCullDistances + off) = (v > pv) ? v : pv;
                }
            }
        }
    }
}

int objGetTotalDataSize(void* tmpl, u8* def, s16* data, int flags)
{
    ObjModelInstance* modelDef;
    int size;
    int r;
    int extra;
    int (*cb)(void*, int);

    modelDef = (ObjModelInstance*)def;
    size = modelDef->modelCount * sizeof(ObjModel*) + sizeof(GameObject);
    switch (((GameObject*)tmpl)->anim.romDefNo)
    {
    case 0:
    case 0x1f:
        extra = 0x8e0;
        break;
    default:
        if (((GameObject*)tmpl)->anim.dll != 0 &&
            (cb = (int (*)(void*, int))((ObjectInterface*)*((GameObject*)tmpl)->anim.dll)->getExtraSize) != 0)
        {
            extra = cb(tmpl, size);
        }
        else
        {
            extra = 0;
        }
        break;
    }
    size += extra;
    if ((flags & 0x40) || (modelDef->flags & OBJDEF_FLAG_HAS_EVENT))
    {
        size = roundUpTo8(roundUpTo4(size) + sizeof(ObjAnimEventTable)) + 0x50;
    }
    if (flags & OBJLOAD_FLAG_WEAPON_DA)
    {
        size = roundUpTo8(roundUpTo4(size) + sizeof(ObjWeaponDaTable)) + 0x800;
    }
    if ((flags & 2) && modelDef->shadowType != OBJ_SHADOW_TYPE_NONE)
    {
        size = roundUpTo4(size) + 0x44;
    }
    if (modelDef->hitboxStateCount != 0)
    {
        size = roundUpTo4(size) + sizeof(ObjHitsPriorityState);
        if ((s8)modelDef->primaryHitboxShapeFlags & 8)
        {
            size += sizeof(ObjHitboxTransformState);
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
    if (modelDef->hitboxStateCount != 0 && modelDef->hitReactStateCount != 0)
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

void Obj_RegisterObject(GameObject* obj, int flags)
{
    ObjAnimComponent* object;
    int id;
    int prev;
    int cur;
    int off;

    object = &obj->anim;
    if (object->parent != NULL)
    {
        Obj_TransformLocalPointToWorld(object->localPosX, object->localPosY, object->localPosZ, &object->worldPosX,
                                       &object->worldPosY, &object->worldPosZ, object->parent);
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
    Obj_RunInitCallback(obj, object->placementData, 0);
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
    if (object->modelInstance->flags & OBJDEF_FLAG_HITBOX_GROUP)
    {
        objAddObjectType(obj, OBJECT_OBJGROUP_HITBOX);
        if (object->activeHitboxMode != 0x5a && (object->modelInstance->flags & OBJDEF_FLAG_HITBOX_GROUP))
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
        obj->objectFlags |= OBJECT_FLAG_IN_UPDATE_LIST;
        gObjList[gObjCount++] = obj;
        if (obj->objectFlags & OBJECT_FLAG_IN_UPDATE_LIST)
        {
            prev = 0;
            cur = gObjUpdateList.head;
            off = gObjUpdateList.nextOffset;
            while (cur != 0 && object->activeHitboxMode < ((GameObject*)cur)->anim.activeHitboxMode)
            {
                prev = cur;
                cur = *(int*)(cur + off);
            }
            objListAdd(&gObjUpdateList, prev, (int)obj);
        }
    }
    if (object->modelInstance->group8RegistrationCount > 0)
    {
        objAddObjectType(obj, OBJECT_OBJGROUP_GROUP8);
    }
    if (object->modelInstance->flags & 1)
    {
        gObjPartitionPivot = 0;
    }
}

void* loadCharacter(s16* data, int flags, int arg2, int arg3, void* parent, int unused)
{
    int id;
    int offsets[20];
    void* models[20];
    GameObject tmpl;
    GameObject* tp;
    s16 seq;
    int modelPtr;
    u8* def;
    int fnFlags;
    int (*fp)(void*);
    int (*fp2)(void*, int);
    int loadFlags;
    int idx;
    int i;
    int count;
    int total;
    ObjModelInstance* modelDef;
    GameObject* obj;
    int base;
    int allocSize;
    int cursor;
    u8 n;
    u16 modelFlags;
    u8 renderFlags;
    f32 max;
    s16 seq2[1];
    u32 cullScale;
    int size;
    int dllStateSize;
    int alignedCursor;
    int j;

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
    memset(&tmpl, 0, sizeof(GameObject));
    tp = &tmpl;
    def = loadObjectFile(id);
    tmpl.anim.modelInstance = (ObjModelInstance*)def;
    if (def == NULL || (int)def == -1)
    {
        debugPrintf(sObjUnknownTypeUsingDummyObjectWarning, id, *data, tmpl.anim.romDefNo);
        return NULL;
    }
    modelDef = (ObjModelInstance*)def;
    tmpl.anim.classId = modelDef->category;
    tmpl.anim.rootMotionScale = modelDef->rootMotionScaleBase;
    tmpl.anim.flags = 2;
    if (modelDef->flags & OBJDEF_FLAG_TRANSLUCENT)
    {
        tmpl.anim.flags = tmpl.anim.flags | 0x80;
    }
    if (modelDef->flags & OBJDEF_FLAG_FORCE_ALPHA_SORT)
    {
        tmpl.objectFlags = tmpl.objectFlags | 0x80;
    }
    if (flags & 4)
    {
        tmpl.anim.flags = tmpl.anim.flags | 0x2000;
    }
    tmpl.anim.localPosX = ((ObjPlacement*)data)->posX;
    tmpl.anim.localPosY = ((ObjPlacement*)data)->posY;
    tmpl.anim.localPosZ = ((ObjPlacement*)data)->posZ;
    tmpl.anim.defId = id;
    tmpl.anim.placementData = data;
    tmpl.anim.romDefNo = seq;
    tmpl.romListBit = arg3;
    tmpl.anim.mapEventSlot = arg2;
    tmpl.anim.activeMove = -1;
    tmpl.seqIndex = -1;
    tmpl.anim.alpha = 0xff;
    tmpl.msgQueue = NULL;
    tmpl.sphereMapIntensity = 0xff;
    tmpl.anim.loadDistance = (f32)(int)(((ObjPlacement*)data)->loadRange << 3);
    tmpl.anim.cullDistance2 = (f32)(int)(((ObjPlacement*)data)->unk07 << 3);
    n = (((ObjPlacement*)data)->mapActFlagsHi & 0x18) >> 3;
    tmpl.lightColorSlot = n;
    if (n == 0)
    {
        tmpl.lightColorSlot = tmpl.anim.modelInstance->defaultModelVariant;
    }
    else
    {
        n -= 1;
        tmpl.lightColorSlot = n;
    }
    tmpl.anim.dll = NULL;
    if ((int)modelDef->dllId != -1)
    {
        tmpl.anim.dll = Resource_Acquire(modelDef->dllId & 0xffff, 6);
    }
    switch (tmpl.anim.romDefNo)
    {
    case OBJECT_SEQID_SABRE:
    case OBJECT_SEQID_KRYSTAL:
        fnFlags = 0x1cb;
        break;
    default:
        if (tmpl.anim.dll != NULL && (int)(fp = *(int (**)(void*))((char*)*tmpl.anim.dll + 0x18)) != -1 &&
            fp != NULL)
        {
            fnFlags = fp(tp);
        }
        else
        {
            fnFlags = 0;
        }
        break;
    }
    if (modelDef->flags & OBJDEF_FLAG_RELATED_TO_MODELS)
    {
        loadFlags = fnFlags & ~1;
    }
    else
    {
        loadFlags = fnFlags | 1;
    }
    if (modelDef->shadowType != OBJ_SHADOW_TYPE_NONE)
    {
        loadFlags |= OBJLOAD_FLAG_HAS_SHADOW;
    }
    else
    {
        loadFlags &= ~OBJLOAD_FLAG_HAS_SHADOW;
    }
    if (modelDef->shadowType == OBJ_SHADOW_TYPE_CRASH)
    {
        loadFlags |= OBJLOAD_FLAG_SHADOW_TYPE3;
    }
    if (modelDef->flags & 1)
    {
        loadFlags |= OBJLOAD_FLAG_SINGLE_MODEL;
    }
    total = 0;
    i = 0;
    count = modelDef->modelCount;
    if (loadFlags & OBJLOAD_FLAG_INDEXED_MODEL)
    {
        i = (loadFlags >> 0xb) & 0xf;
        if (i < count)
        {
            models[i] = ObjModel_Load(-modelDef->modelFileIds[i], loadFlags, &size);
            offsets[i] = total;
            total += size;
        }
    }
    else if (!(loadFlags & OBJLOAD_FLAG_SINGLE_MODEL))
    {
        for (; i < count; i++)
        {
            models[i] = ObjModel_Load(-modelDef->modelFileIds[i], loadFlags, &size);
            offsets[i] = total;
            total += size;
        }
    }
    base = objGetTotalDataSize(tp, def, data, loadFlags);
    allocSize = base + total;
    obj = mmAlloc(allocSize, 0xe, 0);
    memcpy(obj, &tmpl, sizeof(GameObject));
    memset((u8*)obj + sizeof(GameObject), 0, allocSize - sizeof(GameObject));
    obj->anim.modelBanks = (ObjModel**)(obj + 1);
    obj->anim.modelInstance->flags |= 0x800000LL;
    i = 0;
    obj->afterBonesCallback = NULL;
    if (loadFlags & OBJLOAD_FLAG_INDEXED_MODEL)
    {
        idx = (loadFlags >> 0xb) & 0xf;
        if (idx < count)
        {
            obj->anim.modelBanks[idx] = (ObjModel*)((u8*)obj + base + offsets[idx]);
            ObjModel_LoadAnimData(models[idx], loadFlags, (u8*)obj->anim.modelBanks[idx]);
            if (!(obj->anim.modelBanks[idx]->file->flags & 0x8000))
            {
                obj->anim.modelInstance->flags &= ~0x800000LL;
            }
            ObjModel_LoadRenderOpTextures((u8*)obj->anim.modelBanks[idx], obj);
            modelInitBones(obj->anim.rootMotionScale, obj->anim.modelBanks[idx]);
            if (obj->anim.modelInstance->flags & OBJDEF_FLAG_DEFERRED_RENDER)
            {
                ObjModel_SetRenderCallback((u8*)obj->anim.modelBanks[idx], objCausticReflectionRenderCb);
            }
            else
            {
                renderFlags = obj->anim.modelInstance->renderFlags;
                if (renderFlags & 1)
                {
                    ObjModel_SetRenderCallback((u8*)obj->anim.modelBanks[idx], objModelNormalDiskRenderCb);
                }
                else if (renderFlags & 0x80)
                {
                    ObjModel_SetRenderCallback((u8*)obj->anim.modelBanks[idx], objModelProjectedIndirectRenderCb);
                }
            }
        }
    }
    else if (!(loadFlags & OBJLOAD_FLAG_SINGLE_MODEL))
    {
        for (; i < count; i++)
        {
            obj->anim.modelBanks[i] = (ObjModel*)((u8*)obj + base + offsets[i]);
            ObjModel_LoadAnimData(models[i], loadFlags, (u8*)obj->anim.modelBanks[i]);
            modelFlags = obj->anim.modelBanks[i]->file->flags;
            if (!(modelFlags & 0x8000) && !(modelFlags & 0x4000))
            {
                obj->anim.modelInstance->flags &= ~0x800000LL;
            }
            ObjModel_LoadRenderOpTextures((u8*)obj->anim.modelBanks[i], obj);
            modelInitBones(obj->anim.rootMotionScale, obj->anim.modelBanks[i]);
            if (obj->anim.modelInstance->flags & OBJDEF_FLAG_DEFERRED_RENDER)
            {
                ObjModel_SetRenderCallback((u8*)obj->anim.modelBanks[i], objCausticReflectionRenderCb);
            }
            else
            {
                renderFlags = obj->anim.modelInstance->renderFlags;
                if (renderFlags & 1)
                {
                    ObjModel_SetRenderCallback((u8*)obj->anim.modelBanks[i], objModelNormalDiskRenderCb);
                }
                else if (renderFlags & 0x80)
                {
                    ObjModel_SetRenderCallback((u8*)obj->anim.modelBanks[i], objModelProjectedIndirectRenderCb);
                }
            }
        }
    }
    cursor = roundUpTo4((int)obj->anim.modelBanks + modelDef->modelCount * sizeof(ObjModel*));
    switch (obj->anim.romDefNo)
    {
    case OBJECT_SEQID_SABRE:
    case OBJECT_SEQID_KRYSTAL:
        dllStateSize = 0x8e0;
        break;
    default:
        if (obj->anim.dll != NULL && (fp2 = *(int (**)(void*, int))((char*)*obj->anim.dll + 0x1c)) != NULL)
        {
            dllStateSize = fp2(obj, cursor);
        }
        else
        {
            dllStateSize = 0;
        }
        break;
    }
    if (dllStateSize != 0)
    {
        obj->extra = (void*)cursor;
        cursor += dllStateSize;
    }
    else
    {
        obj->extra = NULL;
    }
    if ((loadFlags & OBJLOAD_FLAG_ANIM_EVENTS) || (obj->anim.modelInstance->flags & OBJDEF_FLAG_HAS_EVENT))
    {
        seq2[0] = obj->anim.romDefNo;
        alignedCursor = roundUpTo4(cursor);
        obj->anim.eventTable = (ObjAnimEventTable*)alignedCursor;
        cursor = roundUpTo8(alignedCursor + 8);
        obj->anim.eventTable->entries = (s16*)cursor;
        ObjAnim_LoadMoveEvents((u8*)obj, seq2[0], obj->anim.eventTable, 0, 1);
        cursor += 0x50;
    }
    if (!(loadFlags & OBJLOAD_FLAG_WEAPON_DA) || obj->anim.modelBanks[0] == NULL)
    {
        alignedCursor = cursor;
    }
    else
    {
        alignedCursor = roundUpTo4(cursor);
        obj->anim.weaponDaTable = (ObjWeaponDaTable*)alignedCursor;
        alignedCursor = roundUpTo8(alignedCursor + 8);
        obj->anim.weaponDaTable->entries = (s16*)alignedCursor;
        alignedCursor += 0x800;
    }
    cursor = alignedCursor;
    if ((loadFlags & OBJLOAD_FLAG_HAS_SHADOW) && modelDef->shadowType != OBJ_SHADOW_TYPE_NONE)
    {
        cursor = shadowInit(obj, cursor, 0);
    }
    max = 10.0f;
    i = 0;
    for (; i < obj->anim.modelInstance->modelCount; i++)
    {
        modelPtr = (int)obj->anim.modelBanks[i];
        if (modelPtr != 0)
        {
            if ((f32)modelFileHeaderGetCullDistance(*(ModelFileHeader**)modelPtr) > max)
            {
                max = modelFileHeaderGetCullDistance(*(ModelFileHeader**)modelPtr);
            }
        }
    }
    cullScale = obj->anim.modelInstance->cullDistScale;
    if (cullScale != 0)
    {
        max = max * ((10.0f * cullScale) / 255.0f);
    }
    obj->anim.hitboxScale = max;
    if (modelDef->hitboxStateCount != 0)
    {
        cursor = ObjHits_AllocObjectState(obj, cursor);
        if ((s8)modelDef->primaryHitboxShapeFlags & 8)
        {
            cursor = ObjHitbox_AllocRotatedBounds((ObjHitbox*)obj, cursor);
        }
    }
    if (modelDef->jointCount != 0)
    {
        alignedCursor = roundUpTo4(cursor);
        obj->anim.jointPoseData = (u8*)alignedCursor;
        cursor = alignedCursor + modelDef->jointCount * 0x12;
    }
    if (modelDef->textureSlotCount != 0)
    {
        alignedCursor = roundUpTo4(cursor);
        obj->anim.textureSlots = (ObjTextureRuntimeSlot*)alignedCursor;
        cursor = alignedCursor + modelDef->textureSlotCount * sizeof(ObjTextureRuntimeSlot);
    }
    if (modelDef->hitVolumeCount != 0)
    {
        alignedCursor = roundUpTo4(cursor);
        obj->anim.hitVolumeTransforms = (ObjHitVolumeRuntimeTransform*)alignedCursor;
        cursor = alignedCursor + modelDef->hitVolumeCount * 0x18;
    }
    if (modelDef->hitboxStateCount != 0 && modelDef->hitReactStateCount != 0)
    {
        alignedCursor = roundUpTo4(cursor);
        cursor = ObjHitReact_InitState(obj->anim.romDefNo, (ObjAnimBank*)obj->anim.modelBanks[0],
                                       obj->anim.hitReactState, alignedCursor, &obj->anim);
    }
    if (modelDef->hitVolumeCount != 0)
    {
        obj->anim.hitVolumeBounds = (ObjHitVolumeRuntimeBounds*)roundUpTo4(cursor);
        j = 0;
        for (; j < modelDef->hitVolumeCount; j++)
        {
            obj->anim.hitVolumeBounds[j].flags = modelDef->hitVolumes[j].flags;
            obj->anim.hitVolumeBounds[j].bounds[0] = modelDef->hitVolumes[j].bounds[0];
            obj->anim.hitVolumeBounds[j].bounds[3] = modelDef->hitVolumes[j].bounds[3];
            obj->anim.hitVolumeBounds[j].bounds[1] = modelDef->hitVolumes[j].bounds[1];
            obj->anim.hitVolumeBounds[j].bounds[2] = modelDef->hitVolumes[j].bounds[2];
        }
    }
    obj->anim.parent = parent;
    return obj;
}

GameObject* objSetupObject(ObjPlacement* data, int flags, int mapLayer, int objIndex, void* parent)
{
    GameObject* obj;
    if (getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED)
    {
        OSReport(sObjSetupObjectLoadingLockedWarning, objIndex);
        return NULL;
    }
    obj = loadCharacter((s16*)data, flags, mapLayer, objIndex, parent, 0);
    if (obj != NULL)
    {
        Obj_RegisterObject(obj, flags);
        OSReport(sObjDebugStrings, obj->anim.modelInstance->name);
    }
    return obj;
}

int Obj_CanSetupObject(void) {
    return (getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) == 0;
}
void* getTablesBinEntry(int i)
{
    if (i < 0 || i >= gObjTablesBinCount)
    {
        return gObjTablesBinData;
    }
    return gObjTablesBinData + gObjTablesBinIndex[i] * 4;
}

GameObject* ObjList_FindObjectById(u32 objectId)
{
    ObjListObjectDef* def;
    GameObject* obj;
    int i;
    int count = gObjCount;
    GameObject** arr = gObjList;
    for (i = 0; i < count; i++)
    {
        obj = arr[i];
        def = (ObjListObjectDef*)obj->anim.placementData;
        if (def != NULL && def->objectId == objectId)
        {
            return obj;
        }
    }
    return NULL;
}

GameObject** ObjList_GetObjects(int* outA, int* outB)
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

void Obj_ApplyPendingParentLinks(void)
{
    int i;
    for (i = 0; i < gObjCount; i++)
    {
        GameObject* obj = gObjList[i];
        obj->anim.resetHitboxFlags &= ~7;
        if (obj->pendingParentObj != NULL)
        {
            if (obj->anim.parent == NULL && ((GameObject*)obj->pendingParentObj)->anim.parent != NULL)
            {
                obj->anim.parent = ((GameObject*)obj->pendingParentObj)->anim.parent;
            }
            obj->pendingParentObj = NULL;
        }
    }
}

int ObjList_PartitionForRender(int* out)
{
    void* swapObj;
    int i;
    int j;
    int hi;

    *out = gObjCount;
    i = gObjPartitionPivot;
    if (i != 0) {
        return i;
    }
    i = 0;
    j = gObjCount - 1;
    hi = j;
    while (i <= j) {
        int stop;

        stop = 0;
        while (i <= hi && stop == 0) {
            if (((ObjAnimComponent*)gObjList[i])->modelInstance->flags & OBJDEF_FLAG_HAS_MODELS) {
                i++;
            } else {
                stop = -1;
            }
        }
        stop = 0;
        while (j >= 0 && stop == 0) {
            if (!(((ObjAnimComponent*)gObjList[j])->modelInstance->flags & OBJDEF_FLAG_HAS_MODELS)) {
                j--;
            } else {
                stop = -1;
            }
        }
        if (i < j) {
            swapObj = gObjList[i];
            gObjList[i] = gObjList[j];
            gObjList[j] = swapObj;
            i++;
            j--;
        }
    }
    gObjPartitionPivot = i;
    return i;
}

void Obj_ResetObjectSystem(void) {
    int i;

    Obj_FreeDeferredObjects();
    gObjDeferredFreeCount = 0;
    gObjDefCaptureMode = 0;
    i = gObjCount - 1;
    for (; i >= 0; i--) {
        Obj_FreeObject(gObjList[i]);
    }
    Obj_FreeDeferredObjects();
    gObjDefCaptureMode = 2;
    gObjDeferredFreeCount = 0;
    gObjPendingDefFreeCount = 0;
    gObjCount = 0;
    objListInit(&gObjUpdateList, offsetof(GameObject, anim.next));
    gObjDeferredFreeCount = 0;
    gObjPendingDefFreeCount = 0;
    lbl_803DCB70 = 0;
    gObjCount = 0;
    objListInit(&gObjUpdateList, offsetof(GameObject, anim.next));
    gObjPartitionPivot = 0;
    objTypeInit();
    ObjHits_ResetWorkBuffers();
    (*gCameraInterface)->setFocus(NULL, 0);
    AudioStream_StopAll();
}

void Obj_FlushDeferredFreeList(void)
{
    int i;
    for (i = 0; i < gObjDeferredFreeCount; i++)
    {
        void* p = gObjDeferredFreeList[i];
        if (p != NULL)
        {
            objFreeObjdef(p, 0);
            gObjDeferredFreeList[i] = NULL;
        }
    }
    gObjDeferredFreeCount = 0;
}

void Obj_UpdateModelBlendStates(void)
{
    ObjAnimComponent* childAnim;
    ObjAnimComponent* objAnim;
    int k;
    int i;
    int j;
    GameObject* obj;
    GameObject* child;
    ObjModel* m;
    GameObject* c0;
    u8* bp;
    ObjModelState* modelState;

    i = 0;
    for (; i < gObjCount; i++)
    {
        obj = gObjList[i];
        objAnim = (ObjAnimComponent*)obj;
        if (obj != 0 && objAnim->modelInstance != NULL)
        {
            modelState = objAnim->modelState;
            if (modelState != NULL)
            {
                modelState->shadowCastSlot = NULL;
            }
            k = 0;
            for (; k < objAnim->modelInstance->modelCount; k++)
            {
                m = objAnim->modelBanks[k];
                if (m != 0)
                {
                    m->bufferFlags &= ~8;
                    if (m->file->morphTargetCount != 0)
                    {
                        ObjModel_AdvanceBlendChannels((u8*)m, timeDelta);
                    }
                }
            }
            j = 0;
            for (; j < obj->childCount; j++)
            {
                child = obj->childObjs[j];
                childAnim = (ObjAnimComponent*)child;
                if (child != 0 && childAnim->modelInstance != NULL)
                {
                    k = 0;
                    for (; k < childAnim->modelInstance->modelCount; k++)
                    {
                        m = childAnim->modelBanks[k];
                        if (m != 0)
                        {
                            m->bufferFlags &= ~8;
                            if (m->file->morphTargetCount != 0)
                            {
                                c0 = (GameObject*)(child->pendingParentObj);
                                if (c0 != 0)
                                {
                                    bp = (u8*)c0->extra;
                                }
                                else
                                {
                                    bp = 0;
                                }
                                if (c0 == 0 || (bp != 0 && ((ObjSeqState*)bp)->movementState == 0))
                                {
                                    ObjModel_AdvanceBlendChannels((u8*)m, timeDelta);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

void Obj_UpdateAllObjects(u8 flags)
{
    int updateFlags;
    int off;
    int timeStop;
    u8* obj2;
    int child;
    int obj;
    int obj3;
    int count1;
    int count2;
    ObjHitsPriorityState* t;
    void (*cb)(int);

    updateFlags = flags;
    gObjUpdateFlags = updateFlags;
    off = gObjUpdateList.nextOffset;
    timeStop = updateFlags & 1;
    if (timeStop == 0)
    {
        trackTickDynamicSlotCooldowns();
    }
    Obj_UpdateModelBlendStates();
    ObjHitReact_ResetActiveObjects(gObjCount);
    obj = gObjUpdateList.head;
    while (obj != 0 && ((ObjAnimComponent*)obj)->activeHitboxMode == 0x64)
    {
        Obj_UpdateObject((GameObject*)obj);
        obj = *(int*)(obj + off);
    }
    while (obj != 0 && (((ObjAnimComponent*)obj)->modelInstance->flags & OBJDEF_FLAG_HITBOX_GROUP))
    {
        Obj_UpdateObject((GameObject*)obj);
        ((GameObject*)obj)->anim.transformMatrixIndex = Obj_BuildTransformMatrixSlot((GameObject*)obj);
        obj = *(int*)(obj + off);
    }
    if (timeStop == 0)
    {
        ObjHitReact_UpdateResetObjects();
    }
    for (; obj != 0; obj = *(int*)(obj + off))
    {
        t = (ObjHitsPriorityState*)((void*)((GameObject*)obj)->anim.hitReactState);
        if (t != 0)
        {
            if ((t->shapeFlags & 8) == 0 || (t->flags & 1) == 0)
            {
                Obj_UpdateObject((GameObject*)obj);
            }
        }
        else
        {
            Obj_UpdateObject((GameObject*)obj);
        }
    }
    obj2 = (u8*)objGetAllOfType(0, &count1);
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
        ((GameObject*)child)->anim.parent = ((GameObject*)obj2)->anim.parent;
        Obj_UpdateObject(((GameObject*)obj2)->childObjs[0]);
    }
    if (timeStop == 0)
    {
        ObjHits_Update(gObjCount);
        obj3 = gObjUpdateList.head;
        for (; obj3 != 0; obj3 = *(int*)(obj3 + off))
        {
            if ((((GameObject*)obj3)->objectFlags & OBJECT_OBJFLAG_HITDETECT_DISABLED) == 0)
            {
                switch (((GameObject*)obj3)->anim.romDefNo)
                {
                case 0:
                case 0x1f:
                    playerDoHitDetection((GameObject*)obj3);
                    break;
                default:
                    if (((GameObject*)obj3)->anim.dll == 0)
                    {
                        continue;
                    }
                    cb = (void (*)(int))((ObjectInterface*)*((GameObject*)obj3)->anim.dll)->hitDetect;
                    if (cb == 0)
                    {
                        continue;
                    }
                    cb(obj3);
                    break;
                }
                Obj_GetWorldPosition((GameObject*)obj3, &((GameObject*)obj3)->anim.worldPosX,
                                     &((GameObject*)obj3)->anim.worldPosY, &((GameObject*)obj3)->anim.worldPosZ);
            }
        }
        obj2 = (u8*)objGetAllOfType(0, &count2);
        obj2 = (count2 != 0) ? *(u8**)obj2 : 0;
        if (obj2 != 0 && ((GameObject*)obj2)->childObjs[0] != 0)
        {
            ((GameObject*)((GameObject*)obj2)->childObjs[0])->anim.parent =
                ((GameObject*)obj2)->anim.parent;
            child = *(int*)&((GameObject*)obj2)->childObjs[0];
            if ((((GameObject*)child)->objectFlags & OBJECT_OBJFLAG_HITDETECT_DISABLED) == 0)
            {
                do
                {
                    switch (((GameObject*)child)->anim.romDefNo)
                    {
                    case 0:
                    case 0x1f:
                        playerDoHitDetection((GameObject*)child);
                        break;
                    default:
                        if (((GameObject*)child)->anim.dll == 0)
                        {
                            continue;
                        }
                        cb = (void (*)(int))((ObjectInterface*)*((GameObject*)child)->anim.dll)->hitDetect;
                        if (cb == 0)
                        {
                            continue;
                        }
                        cb(child);
                        break;
                    }
                    Obj_GetWorldPosition((GameObject*)child, &((GameObject*)child)->anim.worldPosX,
                                         &((GameObject*)child)->anim.worldPosY, &((GameObject*)child)->anim.worldPosZ);
                } while (0);
            }
        }
        (*gWaterfxInterface)->runFrame(framesThisStep);
    }
    if ((updateFlags & 2) == 0)
    {
        (*gModgfxInterface)->updateActiveEffects(0, 0, 0);
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

void Obj_InitObjectSystem(void)
{
    s16* p;
    int* q;
    int i;

    gObjDeferredFreeList = mmAlloc(OBJ_DEFERRED_FREE_CAPACITY * sizeof(*gObjDeferredFreeList), 0xe, 0);
    gObjPendingDefFreeList = mmAlloc(OBJ_PENDING_DEF_FREE_CAPACITY * sizeof(*gObjPendingDefFreeList), 0xe, 0);
    lbl_803DCBC0 = mmAlloc(0x10, 0xe, 0);
    loadAssetFileById(&gObjSeqToObjIdTable, MLDF_FILEID_OBJINDEX_BIN);
    gObjSeqToObjIdMax = (getDataFileSize(MLDF_FILEID_OBJINDEX_BIN) >> 1) - 1;
    for (p = gObjSeqToObjIdTable + gObjSeqToObjIdMax; *p == 0;)
    {
        p--;
        gObjSeqToObjIdMax--;
    }
    loadAssetFileById(&gObjFileOffsetTable, MLDF_FILEID_OBJECTS_TAB);
    gObjFileCount = 0;
    for (q = gObjFileOffsetTable; *q != -1;)
    {
        q++;
        gObjFileCount++;
    }
    gObjFileCount--;
    gObjFileBufferTable = mmAlloc(gObjFileCount * sizeof(*gObjFileBufferTable), 0xe, 0);
    gObjFileRefCount = mmAlloc(gObjFileCount * sizeof(*gObjFileRefCount), 0xe, 0);
    for (i = 0; i < gObjFileCount; i++)
    {
        gObjFileRefCount[i] = 0;
    }
    loadAssetFileById(&gObjTablesBinData, MLDF_FILEID_TABLES_BIN);
    loadAssetFileById(&gObjTablesBinIndex, MLDF_FILEID_TABLES_TAB);
    gObjTablesBinCount = 0;
    for (q = gObjTablesBinIndex; *q != -1;)
    {
        q++;
        gObjTablesBinCount++;
    }
    gObjList = mmAlloc(OBJ_LIST_CAPACITY * sizeof(*gObjList), 0xe, 0);
    ObjHits_InitWorkBuffers();
    gObjDeferredFreeCount = 0;
    gObjPendingDefFreeCount = 0;
    lbl_803DCB70 = 0;
    gObjCount = 0;
    objListInit(&gObjUpdateList, offsetof(GameObject, anim.next));
    gObjPartitionPivot = 0;
    objTypeInit();
    ObjHits_ResetWorkBuffers();
}
