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

extern s16 gObjPartitionPivot;
extern void* lbl_803DCBC0;
extern int* gObjFileOffsetTable;
extern int gObjFileCount;
extern u8* gObjTablesBinData;
extern int* gObjTablesBinIndex;
extern int gObjTablesBinCount;
extern u8** gObjFileBufferTable;
extern u8* gObjFileRefCount;
extern s16* gObjSeqToObjIdTable;
extern int gObjSeqToObjIdMax;
extern GameObject** gObjDeferredFreeList;
extern int gObjDeferredFreeCount;
extern GameObject** lbl_803DCB90;
extern int lbl_803DCB8C;
extern GameObject** gObjList;
extern int gObjCount;
extern ObjLinkedList gObjUpdateList;
extern u32 gObjUpdateFlags;
extern s8 gEffectBoxObjectCount;
extern int lbl_803DCB70;

extern int gObjDefCaptureMode;
extern s16 gObjPlayerSpawnIdTable[2];

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
extern GameObject* gEffectBoxObjects[20];
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

extern char sObjUnknownTypeUsingDummyObjectWarning[];

extern char sObjFreeObjdefError[];

extern u8 gObjCameraSetupBlock[32];

extern char sObjFreeNonExistentObjectWarning[];
void Obj_RunInitCallback(u8* obj, int cb, int unused);
void ObjAnim_LoadMoveEvents(u8* obj, int dummy, ObjAnimEventTable* eventTable, u32 moveId, u8 load);

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


u8* loadObjectFile(int id)
{
    int size;
    int base;
    u8* buf;
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
    buf = mmAlloc(size, 0xe, 0);
    if (buf != 0)
    {
        fileLoadToBufferOffset(MLDF_FILEID_OBJECTS_BIN, buf, base, size);
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
            intersectModLineBuild((IntersectModLineObject*)buf);
        }
        gObjFileBufferTable[id] = buf;
        gObjFileRefCount[id] = 1;
    }
    else
    {
        return 0;
    }
    return buf;
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

void Obj_UpdateObject(GameObject* obj)
{
    ObjAnimComponent* object;
    ObjHitsPriorityState* hitState;
    ObjHitsPriorityState* childHitState;
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
        switch (object->seqId)
        {
        case OBJECT_SEQID_SABRE:
        case OBJECT_SEQID_KRYSTAL:
            playerUpdateWhileTimeStopped((int)obj);
            break;
        case OBJECT_SEQID_STAFF:
            playerRenderQuakeSpell(obj);
            break;
        case OBJECT_SEQID_DIE_DUSTER:
        case OBJECT_SEQID_DIE_FOX:
        case OBJECT_SEQID_DIE_KRYSTAL:
            cb2 = (void (*)(GameObject*)) * (int*)((u8*)*object->dll + 8);
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
            ObjModel_ClearRenderAttachment((ObjModel*)object->banks[object->bankIndex]);
            cb = (*gBoneParticleEffectInterface)->spawnEffect;
            cb(obj, 0x7fb, NULL, 0x50, NULL);
            cb = (*gBoneParticleEffectInterface)->spawnEffect;
            cb(obj, 0x7fc, NULL, 0x32, NULL);
            Sfx_PlayFromObject((u32)obj, SFXTRIG_barrel_bounce1);
        }
    }
    if ((obj->objectFlags & OBJECT_OBJFLAG_UPDATE_DISABLED) == 0)
    {
        do
        {
            switch (object->seqId)
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
                cb2 = (void (*)(GameObject*)) * (int*)((u8*)*object->dll + 8);
                if (cb2 != 0)
                {
                    cb2(obj);
                }
                break;
            }
            Obj_GetWorldPosition((u32)obj, &object->worldPosX, &object->worldPosY, &object->worldPosZ);
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
    if (*(void**)((u8*)obj + 0x58) != NULL)
    {
        *(u8*)(*(u8**)((u8*)obj + 0x58) + 0x10f) = 0;
    }
}

void Obj_FreeObject(GameObject* obj)
{
    u8** p;
    int n;
    int i;
    GameObject** base;
    int off;
    u8* q;

    if (obj->objectFlags & OBJECT_FLAG_FREED)
    {
        return;
    }
    Sfx_RemoveLoopedObjectSoundForObject((u32)obj);
    Sfx_StopObjectChannel((u32)obj, 0x7f);
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
            if (lbl_803DCB8C < OBJ_PENDING_DEF_FREE_CAPACITY)
            {
                lbl_803DCB90[lbl_803DCB8C] = obj;
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
        objFreeObjDef((u8*)obj, !gObjDefCaptureMode);
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
    if ((!((ModelFileHeader*)hdr)->flags & 0x1000) || (((ModelFileHeader*)hdr)->jointCount == 0))
    {
        return;
    }
    {
        if ((src = *(f32**)(hdr + 0x18)) != NULL && (tbl = ((ObjModel*)m)->jointWorkspace) != NULL)
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
            for (; i < ((ObjModel*)m)->file->jointCount; srcP++, off += 4, boneOff += 0x1c, sumP++, i++)
            {
                *(f32*)(*(u8**)(tbl + 4) + off) = sc * *srcP;
                *(f32*)(*(u8**)(tbl + 8) + off) = *(f32*)(*(u8**)(tbl + 4) + off) * *(f32*)(*(u8**)(tbl + 4) + off);
                bone = ((ModelFileHeader*)hdr)->jointData + boneOff;
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

int objGetTotalDataSize(void* tmpl, u8* def, s16* data, int flags)
{
    ObjModelInstance* modelDef;
    int size;
    int r;
    int extra;
    int (*cb)(void*, int);

    modelDef = (ObjModelInstance*)def;
    size = modelDef->modelCount * 4 + 0x10c;
    switch (((GameObject*)tmpl)->anim.seqId)
    {
    case 0:
    case 0x1f:
        extra = 0x8e0;
        break;
    default:
        if (((GameObject*)tmpl)->anim.dll != 0 &&
            (cb = (int (*)(void*, int)) * (int*)(*(int*)((GameObject*)tmpl)->anim.dll + 0x1c)) != 0)
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
    if ((flags & 0x40) || (modelDef->flags & 0x400000))
    {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x50;
    }
    if (flags & OBJLOAD_FLAG_WEAPON_DA)
    {
        size = roundUpTo8(roundUpTo4(size) + 8) + 0x800;
    }
    if ((flags & 2) && modelDef->shadowType != OBJ_SHADOW_TYPE_NONE)
    {
        size = roundUpTo4(size) + 0x44;
    }
    if (modelDef->hitboxStateCount != 0)
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


void* loadCharacter(s16* data, int flags, int arg2, int arg3, void* parent, int unused)
{
    int id;
    int offsets[20];
    void* models[20];
    LoadedObj tmpl;
    LoadedObj* tp;
    s16 seq;
    int modelPtr;
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
    u16 modelFlags;
    u8 renderFlags;
    f32 max;
    s16 seq2;
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
    tmpl.f44 = modelDef->category;
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
        tmpl.ff2 = ((ObjModelInstance*)tmpl.def)->defaultModelVariant;
    }
    else
    {
        n -= 1;
        tmpl.ff2 = n;
    }
    tmpl.dll = NULL;
    if ((int)modelDef->dllId != -1)
    {
        tmpl.dll = Resource_Acquire(modelDef->dllId & 0xffff, 6);
    }
    switch (tmpl.seqId)
    {
    case OBJECT_SEQID_SABRE:
    case OBJECT_SEQID_KRYSTAL:
        fnFlags = 0x1cb;
        break;
    default:
        if (tmpl.dll != NULL && (int)(fp = *(int (**)(void*))((char*)*tmpl.dll + 0x18)) != -1 && fp != NULL)
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
    if (modelDef->shadowType != OBJ_SHADOW_TYPE_NONE)
    {
        flags29 |= OBJLOAD_FLAG_HAS_SHADOW;
    }
    else
    {
        flags29 &= ~OBJLOAD_FLAG_HAS_SHADOW;
    }
    if (modelDef->shadowType == OBJ_SHADOW_TYPE_CRASH)
    {
        flags29 |= OBJLOAD_FLAG_SHADOW_TYPE3;
    }
    if (modelDef->flags & 1)
    {
        flags29 |= OBJLOAD_FLAG_SINGLE_MODEL;
    }
    total = 0;
    i = 0;
    count = modelDef->modelCount;
    if (flags29 & OBJLOAD_FLAG_INDEXED_MODEL)
    {
        i = (flags29 >> 0xb) & 0xf;
        if (i < count)
        {
            models[i] = ObjModel_Load(-modelDef->modelFileIds[i], flags29, &size);
            offsets[i] = total;
            total += size;
        }
    }
    else if (!(flags29 & OBJLOAD_FLAG_SINGLE_MODEL))
    {
        for (; i < count; i++)
        {
            models[i] = ObjModel_Load(-modelDef->modelFileIds[i], flags29, &size);
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
    if (flags29 & OBJLOAD_FLAG_INDEXED_MODEL)
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
            ObjModel_LoadRenderOpTextures(obj->models[idx], (GameObject*)obj);
            modelInitBones(obj->scale, obj->models[idx]);
            if (((ObjModelInstance*)obj->def)->flags & OBJDEF_FLAG_DEFERRED_RENDER)
            {
                ObjModel_SetRenderCallback(obj->models[idx], objCallback_80074d04);
            }
            else
            {
                renderFlags = ((ObjModelInstance*)obj->def)->renderFlags;
                if (renderFlags & 1)
                {
                    ObjModel_SetRenderCallback(obj->models[idx], modelCb_80073d04);
                }
                else if (renderFlags & 0x80)
                {
                    ObjModel_SetRenderCallback(obj->models[idx], modelCb_80074518);
                }
            }
        }
    }
    else if (!(flags29 & OBJLOAD_FLAG_SINGLE_MODEL))
    {
        for (; i < count; i++)
        {
            obj->models[i] = (u8*)obj + base + offsets[i];
            ObjModel_LoadAnimData(models[i], flags29, (int)obj->models[i]);
            modelFlags = *(u16*)(*(u8**)obj->models[i] + 2);
            if (!(modelFlags & 0x8000) && !(modelFlags & 0x4000))
            {
                ((ObjModelInstance*)obj->def)->flags &= ~0x800000LL;
            }
            ObjModel_LoadRenderOpTextures(obj->models[i], (GameObject*)obj);
            modelInitBones(obj->scale, obj->models[i]);
            if (((ObjModelInstance*)obj->def)->flags & OBJDEF_FLAG_DEFERRED_RENDER)
            {
                ObjModel_SetRenderCallback(obj->models[i], objCallback_80074d04);
            }
            else
            {
                renderFlags = ((ObjModelInstance*)obj->def)->renderFlags;
                if (renderFlags & 1)
                {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80073d04);
                }
                else if (renderFlags & 0x80)
                {
                    ObjModel_SetRenderCallback(obj->models[i], modelCb_80074518);
                }
            }
        }
    }
    cursor = roundUpTo4((int)obj->models + modelDef->modelCount * 4);
    switch (obj->seqId)
    {
    case OBJECT_SEQID_SABRE:
    case OBJECT_SEQID_KRYSTAL:
        dllStateSize = 0x8e0;
        break;
    default:
        if (obj->dll != NULL && (fp2 = *(int (**)(void*, int))((char*)*obj->dll + 0x1c)) != NULL)
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
        obj->fb8 = cursor;
        cursor += dllStateSize;
    }
    else
    {
        obj->fb8 = 0;
    }
    if ((flags29 & OBJLOAD_FLAG_ANIM_EVENTS) || (((ObjModelInstance*)obj->def)->flags & 0x400000))
    {
        seq2 = obj->seqId;
        alignedCursor = roundUpTo4(cursor);
        obj->objAnimEventTable = (ObjAnimEventTable*)alignedCursor;
        cursor = roundUpTo8(alignedCursor + 8);
        obj->objAnimEventTable->entries = (s16*)cursor;
        ObjAnim_LoadMoveEvents((u8*)obj, seq2, obj->objAnimEventTable, 0, 1);
        cursor += 0x50;
    }
    if ((flags29 & OBJLOAD_FLAG_WEAPON_DA) && *(void**)obj->models != NULL)
    {
        alignedCursor = roundUpTo4(cursor);
        obj->weaponDaTable = (ObjWeaponDaTable*)alignedCursor;
        cursor = roundUpTo8(alignedCursor + 8);
        obj->weaponDaTable->entries = (s16*)cursor;
        cursor += 0x800;
    }
    if ((flags29 & OBJLOAD_FLAG_HAS_SHADOW) && modelDef->shadowType != OBJ_SHADOW_TYPE_NONE)
    {
        cursor = shadowInit(obj, cursor, 0);
    }
    max = lbl_803DE8CC;
    i = 0;
    for (; i < ((ObjModelInstance*)obj->def)->modelCount; i++)
    {
        modelPtr = *(int*)((u8*)obj->models + i * 4);
        if (modelPtr != 0)
        {
            if ((f32)modelFileHeaderGetCullDistance(*(ModelFileHeader**)modelPtr) > max)
            {
                max = modelFileHeaderGetCullDistance(*(ModelFileHeader**)modelPtr);
            }
        }
    }
    cullScale = ((ObjModelInstance*)obj->def)->cullDistScale;
    if (cullScale != 0)
    {
        max = max * ((lbl_803DE8CC * cullScale) / lbl_803DE8D0);
    }
    obj->cullDist = max;
    if (modelDef->hitboxStateCount != 0)
    {
        cursor = ObjHits_AllocObjectState((GameObject*)obj, cursor);
        if ((s8)modelDef->primaryHitboxShapeFlags & 8)
        {
            cursor = ObjHitbox_AllocRotatedBounds((ObjHitbox*)obj, cursor);
        }
    }
    if (modelDef->jointCount != 0)
    {
        alignedCursor = roundUpTo4(cursor);
        obj->f6c = alignedCursor;
        cursor = alignedCursor + modelDef->jointCount * 0x12;
    }
    if (modelDef->textureSlotCount != 0)
    {
        alignedCursor = roundUpTo4(cursor);
        obj->textureSlots = (ObjTextureRuntimeSlot*)alignedCursor;
        cursor = alignedCursor + modelDef->textureSlotCount * sizeof(ObjTextureRuntimeSlot);
    }
    if (modelDef->hitVolumeCount != 0)
    {
        alignedCursor = roundUpTo4(cursor);
        obj->hitVolumeTransforms = (ObjHitVolumeRuntimeTransform*)alignedCursor;
        cursor = alignedCursor + modelDef->hitVolumeCount * 0x18;
    }
    if (modelDef->hitboxStateCount != 0 && modelDef->hitReactStateCount != 0)
    {
        alignedCursor = roundUpTo4(cursor);
        cursor = ObjHitReact_InitState(obj->seqId, (ObjAnimBank*)*(u8**)obj->models, obj->hitReactState, alignedCursor,
                                       (ObjAnimComponent*)obj);
    }
    if (modelDef->hitVolumeCount != 0)
    {
        obj->hitVolumeBounds = (ObjHitVolumeRuntimeBounds*)roundUpTo4(cursor);
        j = 0;
        for (; j < modelDef->hitVolumeCount; j++)
        {
            obj->hitVolumeBounds[j].flags = modelDef->hitVolumes[j].flags;
            obj->hitVolumeBounds[j].bounds[0] = modelDef->hitVolumes[j].bounds[0];
            obj->hitVolumeBounds[j].bounds[3] = modelDef->hitVolumes[j].bounds[3];
            obj->hitVolumeBounds[j].bounds[1] = modelDef->hitVolumes[j].bounds[1];
            obj->hitVolumeBounds[j].bounds[2] = modelDef->hitVolumes[j].bounds[2];
        }
    }
    obj->parent = parent;
    return obj;
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

GameObject* Obj_SetupObject(ObjPlacement* data, int flags, int mapLayer, int objIndex, void* parent)
{
    GameObject* obj;
    if (getLoadedFileFlags(0) & 0x100000)
    {
        OSReport(sObjSetupObjectLoadingLockedWarning, objIndex);
        return NULL;
    }
    obj = loadCharacter((s16*)data, flags, mapLayer, objIndex, parent, 0);
    if (obj != NULL)
    {
        Obj_RegisterObject(obj, flags);
        OSReport(sObjDebugStrings, *(int*)&obj->anim.modelInstance + 0x91);
    }
    return obj;
}

asm u8 Obj_IsLoadingLocked(void)
{
    nofralloc
    stwu r1, -0x10(r1)
    mflr r0
    stw r0, 0x14(r1)
    li r3, 0
    bl getLoadedFileFlags
    rlwinm r0, r3, 0, 11, 11
    cntlzw r0, r0
    srwi r3, r0, 5
    lwz r0, 0x14(r1)
    mtlr r0
    addi r1, r1, 0x10
    blr
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


void Obj_ApplyPendingParentLinks(void)
{
    int i;
    for (i = 0; i < gObjCount; i++)
    {
        u8* obj = (u8*)gObjList[i];
        ((GameObject*)obj)->anim.resetHitboxFlags &= ~7;
        if (((GameObject*)obj)->pendingParentObj != NULL)
        {
            if (((GameObject*)obj)->anim.parent == NULL &&
                ((GameObject*)((GameObject*)obj)->pendingParentObj)->anim.parent != NULL)
            {
                ((GameObject*)obj)->anim.parent =
                    ((GameObject*)((GameObject*)obj)->pendingParentObj)->anim.parent;
            }
            ((GameObject*)obj)->pendingParentObj = NULL;
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
            if (((ObjAnimComponent*)gObjList[i])->modelInstance->flags & 1)
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
            if (!(((ObjAnimComponent*)gObjList[j])->modelInstance->flags & 1))
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
        Obj_FreeObject(*(GameObject**)((int)gObjList + off));
        off -= 4;
    }
    Obj_FreeDeferredObjects();
    gObjDefCaptureMode = 2;
    gObjDeferredFreeCount = 0;
    lbl_803DCB8C = 0;
    gObjCount = 0;
    objListInit(&gObjUpdateList, 0x38);
    gObjDeferredFreeCount = 0;
    lbl_803DCB8C = 0;
    lbl_803DCB70 = 0;
    gObjCount = 0;
    objListInit(&gObjUpdateList, 0x38);
    gObjPartitionPivot = 0;
    ObjGroup_ClearAll();
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
            objFreeObjDef(p, 0);
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
    u8* obj;
    u8* child;
    u8* m;
    u8* c0;
    u8* bp;
    ObjModelState* modelState;

    i = 0;
    for (; i < gObjCount; i++)
    {
        obj = (u8*)gObjList[i];
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
                m = (u8*)objAnim->banks[k];
                if (m != 0)
                {
                    ((ObjModel*)m)->bufferFlags &= ~8;
                    if (((ObjModel*)m)->file->morphTargetCount != 0)
                    {
                        ObjModel_AdvanceBlendChannels(m, timeDelta);
                    }
                }
            }
            j = 0;
            for (; j < ((GameObject*)obj)->childCount; j++)
            {
                child = (u8*)((GameObject*)obj)->childObjs[j];
                childAnim = (ObjAnimComponent*)child;
                if (child != 0 && childAnim->modelInstance != NULL)
                {
                    k = 0;
                    for (; k < childAnim->modelInstance->modelCount; k++)
                    {
                        m = (u8*)childAnim->banks[k];
                        if (m != 0)
                        {
                            ((ObjModel*)m)->bufferFlags &= ~8;
                            if (((ObjModel*)m)->file->morphTargetCount != 0)
                            {
                                c0 = ((GameObject*)child)->pendingParentObj;
                                if (c0 != 0)
                                {
                                    bp = (u8*)((GameObject*)c0)->extra;
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
    u8* t;
    void (*cb)(int);

    updateFlags = flags;
    gObjUpdateFlags = updateFlags;
    off = gObjUpdateList.nextOffset;
    timeStop = updateFlags & 1;
    if (timeStop == 0)
    {
        objFn_80065604();
    }
    Obj_UpdateModelBlendStates();
    ObjHitReact_ResetActiveObjects(gObjCount);
    obj = gObjUpdateList.head;
    while (obj != 0 && ((ObjAnimComponent*)obj)->activeHitboxMode == 0x64)
    {
        Obj_UpdateObject((GameObject*)obj);
        obj = *(int*)(obj + off);
    }
    while (obj != 0 && (((ObjAnimComponent*)obj)->modelInstance->flags & OBJMODEL_FLAG_SKIP_RESET_UPDATE))
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
        t = (void*)((GameObject*)obj)->anim.hitReactState;
        if (t != 0)
        {
            if ((((ObjHitsPriorityState*)t)->shapeFlags & 8) == 0 || (((ObjHitsPriorityState*)t)->flags & 1) == 0)
            {
                Obj_UpdateObject((GameObject*)obj);
            }
        }
        else
        {
            Obj_UpdateObject((GameObject*)obj);
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
        *(int*)&((GameObject*)child)->anim.parent = *(int*)&((GameObject*)obj2)->anim.parent;
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
                switch (((GameObject*)obj3)->anim.seqId)
                {
                case 0:
                case 0x1f:
                    playerDoHitDetection(obj3);
                    break;
                default:
                    if (((GameObject*)obj3)->anim.dll == 0)
                    {
                        continue;
                    }
                    cb = (void (*)(int)) * (int*)((u8*)*((GameObject*)obj3)->anim.dll + 0xc);
                    if (cb == 0)
                    {
                        continue;
                    }
                    cb(obj3);
                    break;
                }
                Obj_GetWorldPosition((u32)obj3, &((GameObject*)obj3)->anim.worldPosX,
                                     &((GameObject*)obj3)->anim.worldPosY, &((GameObject*)obj3)->anim.worldPosZ);
            }
        }
        obj2 = (u8*)ObjGroup_GetObjects(0, &count2);
        obj2 = (count2 != 0) ? *(u8**)obj2 : 0;
        if (obj2 != 0 && ((GameObject*)obj2)->childObjs[0] != 0)
        {
            *(int*)&((GameObject*)((GameObject*)obj2)->childObjs[0])->anim.parent =
                *(int*)&((GameObject*)obj2)->anim.parent;
            child = *(int*)&((GameObject*)obj2)->childObjs[0];
            if ((((GameObject*)child)->objectFlags & OBJECT_OBJFLAG_HITDETECT_DISABLED) == 0)
            {
                do
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
                            continue;
                        }
                        cb = (void (*)(int)) * (int*)((u8*)*((GameObject*)child)->anim.dll + 0xc);
                        if (cb == 0)
                        {
                            continue;
                        }
                        cb(child);
                        break;
                    }
                    Obj_GetWorldPosition((u32)child, &((GameObject*)child)->anim.worldPosX,
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
    lbl_803DCB90 = mmAlloc(OBJ_PENDING_DEF_FREE_CAPACITY * sizeof(*lbl_803DCB90), 0xe, 0);
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
    gObjFileBufferTable = mmAlloc(gObjFileCount * 4, 0xe, 0);
    gObjFileRefCount = mmAlloc(gObjFileCount, 0xe, 0);
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
    lbl_803DCB8C = 0;
    lbl_803DCB70 = 0;
    gObjCount = 0;
    objListInit(&gObjUpdateList, 0x38);
    gObjPartitionPivot = 0;
    ObjGroup_ClearAll();
    ObjHits_ResetWorkBuffers();
}

int loadModLines(int idx, s16* outCount)
{
    int result;
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
        result = (int)mmAlloc(size, 5, 0);
        fileLoadToBufferOffset(MLDF_FILEID_MODLINES_BIN, (void*)result, start, size);
    }
    mm_free(hdr);
    *outCount = (u32)size / 20;
    return result;
}

void Obj_RegisterObject(GameObject* obj, int flags)
{
    ObjAnimComponent* object;
    ObjHitsPriorityState* hitState;
    int id;
    int prev;
    int cur;
    int off;

    object = &obj->anim;
    if (object->parent != NULL)
    {
        Obj_TransformLocalPointToWorld(object->localPosX, object->localPosY, object->localPosZ, &object->worldPosX,
                                       &object->worldPosY, &object->worldPosZ, (u32)object->parent);
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
    Obj_RunInitCallback((u8*)obj, (int)object->placementData, 0);
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
        ObjGroup_AddObject((u32)obj, OBJECT_OBJGROUP_HITBOX);
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
        ObjGroup_AddObject((u32)obj, OBJECT_OBJGROUP_GROUP8);
    }
    if (object->modelInstance->flags & 1)
    {
        gObjPartitionPivot = 0;
    }
}

void Obj_RunInitCallback(u8* obj, int cb, int unused)
{
    s16 mode = ((GameObject*)obj)->anim.seqId;
    switch (mode)
    {
    case 0x1f:
    case 0:
        objLoadPlayerFromSave((int)obj);
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
        f32 zero;
        ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
        ((GameObject*)obj)->anim.previousWorldPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.previousWorldPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.previousWorldPosZ = ((GameObject*)obj)->anim.localPosZ;
        zero = lbl_803DE88C;
        ((GameObject*)obj)->externalVelX = zero;
        ((GameObject*)obj)->externalVelY = zero;
        ((GameObject*)obj)->externalVelZ = zero;
    }
}
