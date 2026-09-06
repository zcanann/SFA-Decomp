#define OBJHITS_SETTERS_S16
#define OBJHITS_STATE_INDEX_S8
#include <string.h>
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/model.h"
#include "main/obj_contact.h"
#include "main/obj_list.h"
#include "main/objhits.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "main/track_dolphin_api.h"
#include "dolphin/os.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/mm.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/objHitReact_types.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/resource.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/mtx.h"
#include "main/dll/objpathtransform_struct.h"
#include "main/game_ui_interface.h"
#include "main/lightmap_api.h"
#include "main/dll/player_api.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/objtype.h"
#include "main/obj_hit_region.h"
#include "main/obj_link.h"
#include "main/objlib_api.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/obj_trigger.h"
#include "main/player_eye_anim.h"
#include "main/pad_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "main/texture.h"
#include "main/objprint_dolphin_api.h"
#include "main/curve_eval.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/newshadows.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/dll/modgfx.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "main/acosf.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "track/intersect_api.h"
#include "main/objprint_internal.h"

#define OBJTYPE_COUNT                 0x54
#define OBJTYPE_INDEX_COUNT           (OBJTYPE_COUNT + 1)
#define OBJTYPE_LIST_MAX              0x100
#define OBJLIB_PRIMARY_ROM_PAGE_COUNT 0x50
#define OBJHITREGION_ROM_ENTRY_TYPE   0x130

typedef struct ObjectTypeIndexTable {
    u8 offsets[OBJTYPE_INDEX_COUNT];
    u8 reserved[3];
} ObjectTypeIndexTable;

STATIC_ASSERT(sizeof(ObjectTypeIndexTable) == 0x58);

GameObject* gObjectTypeList[OBJTYPE_LIST_MAX];
extern ObjectTypeIndexTable gObjectTypeIndices;

typedef struct ObjContactCallbackEntry {
    GameObject* objA;
    GameObject* objB;
    ObjContactCallback callback;
} ObjContactCallbackEntry;

typedef struct ObjHitRegionPlacement {
    ObjPlacement base;
    u16 id;
    u16 halfX;
    u16 halfY;
    u16 halfZ;
    u8 yaw;
    u8 pitch;
} ObjHitRegionPlacement;

STATIC_ASSERT(offsetof(ObjHitRegionPlacement, id) == 0x18);
STATIC_ASSERT(offsetof(ObjHitRegionPlacement, yaw) == 0x20);

extern ObjContactCallbackEntry gObjContactCallbacks[0xC0 / sizeof(ObjContactCallbackEntry)];
extern u8 gObjectTypeListCount;
extern int gObjContactCallbackCount;
#define OBJMSG_QUEUE_OFFSET        0xdc
#define OBJMSG_SEND_INCLUDE_SENDER 0x1
#define OBJMSG_SEND_MATCH_ANY      0x2
#define OBJMSG_SEND_MATCH_OBJTYPE  0x4

#define OBJCONTACT_CALLBACK_CAPACITY    0x10
#define OBJCONTACT_CALLBACK_LAST_INDEX  (OBJCONTACT_CALLBACK_CAPACITY - 1)
#define OBJTRIGGER_FLAGS_OFFSET         0xaf
#define OBJTRIGGER_CURRENT_ENABLE_FLAG  0x01
#define OBJTRIGGER_CURRENT_BLOCK_FLAG   0x08
#define OBJTRIGGER_ID_ENABLE_FLAG       0x04
#define OBJTRIGGER_ID_BLOCK_FLAG        0x10
#define OBJTRIGGER_BUTTON_DISABLE_INDEX 0
#define OBJTRIGGER_BUTTON_DISABLE_FLAG  0x100
#define OBJTRIGGER_PLAYER_STATE_NONE    -1
#define OBJTRIGGER_PLAYER_STATE_CLEAR   0x40

#define OBJLINK_PARENT_OFFSET      0xc4
#define OBJLINK_CHILD_LIST_OFFSET  0xc8
#define OBJLINK_CHILD_COUNT_OFFSET 0xeb
#define OBJLINK_FLAGS_OFFSET       0xb0
#define OBJLINK_FLAGS_MODE_MASK    0x0007
#define OBJLINK_FLAGS_DEAD         0x0040

#define OBJ_MODEL_INSTANCE_OFFSET     0x50
#define OBJ_ACTIVE_MODEL_INDEX_OFFSET 0xad
#define OBJ_POSITION_X_OFFSET         0x0c
#define OBJ_POSITION_Y_OFFSET         0x10
#define OBJ_POSITION_Z_OFFSET         0x14

#define OBJ_MODEL_JOINT_COUNT_OFFSET 0xf3

/* hit-object romDefNo that triggers the staff-impact sfx (retail OBJECTS.bin). */
#define OBJLIB_HITOBJ_SEQID_STAFF  0x69 /* "staff" (DLL 0xE2) */
#define OBJPATH_POINTS_OFFSET      0x2c
#define OBJPATH_POINT_COUNT_OFFSET 0x58
#define OBJPATH_ROOT_JOINT_INDEX   -1
typedef struct ObjMsgEntry {
    u32 message;
    u32 sender;
    u32 param;
} ObjMsgEntry;

typedef struct ObjMsgQueue {
    u32 count;
    u32 capacity;
    ObjMsgEntry entries[1];
} ObjMsgQueue;

STATIC_ASSERT(sizeof(ObjMsgEntry) == 0xC);
STATIC_ASSERT(offsetof(ObjMsgQueue, entries) == 0x8);

typedef struct ObjMsgQueueCursor {
    u32 count;
    u32 capacity;
    ObjMsgEntry entry;
    ObjMsgEntry nextEntry;
} ObjMsgQueueCursor;

STATIC_ASSERT(offsetof(ObjMsgQueueCursor, entry) == 0x8);
STATIC_ASSERT(offsetof(ObjMsgQueueCursor, nextEntry) == 0x14);
STATIC_ASSERT(sizeof(ObjMsgQueueCursor) == 0x20);

typedef struct ObjPathPoint {
    f32 x;
    f32 y;
    f32 z;
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s8 modelIndex[6];
} ObjPathPoint;

int objIsObjectType(GameObject* obj, int group) {
    GameObject** entry;
    u32 index;
    u32 limit;
    u32 limitXorIndex;
    int halfDiff;

    if ((group < 0) || (group >= OBJTYPE_COUNT)) {
        return 0;
    }
    index = gObjectTypeIndices.offsets[group];
    limit = gObjectTypeIndices.offsets[group + 1];
    for (entry = gObjectTypeList + index; ((int)index < (int)limit && (obj != *entry));
         entry = entry + 1, index = index + 1) {
    }
    limitXorIndex = limit ^ index;
    halfDiff = (int)limitXorIndex >> 1;
    limitXorIndex = limitXorIndex & limit;
    return (u32)(halfDiff - limitXorIndex) >> 0x1f;
}

GameObject* objGetNearestType(int group, float* point, float* maxDistance) {
    GameObject** entry;
    GameObject* nearest;
    int index;
    int limit;
    float distanceSq;
    float bestDistanceSq;

    nearest = 0;
    bestDistanceSq = *maxDistance * *maxDistance;
    if ((group < 0) || (group >= OBJTYPE_COUNT)) {
        return 0;
    }
    index = gObjectTypeIndices.offsets[group];
    limit = gObjectTypeIndices.offsets[group + 1];
    entry = gObjectTypeList + index;
    while (index < limit) {
        if (*entry != 0) {
            distanceSq = PSVECSquareDistance((Vec*)point, &((GameObject*)*entry)->anim.worldPos);
            if (distanceSq < bestDistanceSq) {
                bestDistanceSq = distanceSq;
                nearest = *entry;
            }
            entry++;
            index++;
        }
    }
    if (nearest != 0) {
        *maxDistance = sqrtf(bestDistanceSq);
    }
    return nearest;
}

GameObject* objGetNearestTypeToExcludingSelf(int group, GameObject* obj, float* maxDistance) {
    GameObject** entry;
    GameObject* nearest;
    int index;
    int limit;
    float distanceSq;
    float bestDistanceSq;

    nearest = 0;
    if ((group < 0) || (group >= OBJTYPE_COUNT)) {
        return 0;
    }
    if (maxDistance != (float*)0x0) {
        bestDistanceSq = *maxDistance * *maxDistance;
    } else {
        bestDistanceSq = 3.4028235e38f;
    }
    index = gObjectTypeIndices.offsets[group];
    limit = gObjectTypeIndices.offsets[group + 1];
    entry = gObjectTypeList + index;
    while (index < limit) {
        if ((GameObject*)*entry != obj) {
            distanceSq = vec3f_distanceSquared(&obj->anim.worldPosX, &((GameObject*)*entry)->anim.worldPosX);
            if (distanceSq < bestDistanceSq) {
                bestDistanceSq = distanceSq;
                nearest = (GameObject*)*entry;
            }
        }
        entry++;
        index++;
    }
    if ((nearest != 0) && (maxDistance != (float*)0x0)) {
        *maxDistance = sqrtf(bestDistanceSq);
    }
    return nearest;
}

GameObject* objGetNearestTypeTo(int group, GameObject* obj, float* maxDistance) {
    GameObject** entry;
    GameObject* nearest;
    GameObject* o;
    int index;
    int limit;
    float distanceSq;
    float bestDistanceSq;

    nearest = 0;
    if ((group < 0) || (group >= OBJTYPE_COUNT)) {
        return 0;
    }
    if (maxDistance != (float*)0x0) {
        bestDistanceSq = *maxDistance * *maxDistance;
    } else {
        bestDistanceSq = 3.4028235e38f;
    }
    o = obj;
    index = gObjectTypeIndices.offsets[group];
    limit = gObjectTypeIndices.offsets[group + 1];
    entry = gObjectTypeList + index;
    while (index < limit) {
        if ((GameObject*)*entry != o) {
            distanceSq = vec3f_distanceSquared(&o->anim.worldPosX, &((GameObject*)*entry)->anim.worldPosX);
            if (distanceSq < bestDistanceSq) {
                bestDistanceSq = distanceSq;
                nearest = (GameObject*)*entry;
            }
        }
        entry++;
        index++;
    }
    if ((nearest != 0) && (maxDistance != (float*)0x0)) {
        *maxDistance = sqrtf(bestDistanceSq);
    }
    return nearest;
}

const f32 gObjLibZero = 0.0f;

GameObject** objGetAllOfType(int group, int* countOut) {
    if (group < 0 || group >= OBJTYPE_COUNT) {
        *countOut = 0;
        return 0x0;
    }
    *countOut = gObjectTypeIndices.offsets[group + 1] - gObjectTypeIndices.offsets[group];
    return gObjectTypeList + gObjectTypeIndices.offsets[group];
}

void objFreeObjectType(GameObject* obj, int group) {
    u8* offset;
    u8 count;
    int index;
    int limit;
    GameObject** entries;

    if ((group < 0) || (group >= OBJTYPE_COUNT)) {
        return;
    }
    offset = gObjectTypeIndices.offsets;
    index = offset[group];
    offset += group;
    limit = offset[1];
    entries = gObjectTypeList + index;
    while ((index < limit) && (*entries != obj)) {
        entries++;
        index++;
    }
    if (index >= limit) {
        return;
    }
    count = (gObjectTypeListCount -= 1);
    entries = gObjectTypeList + index;
    while (index < count) {
        *entries = entries[1];
        entries++;
        index++;
    }
    group++;
    offset = gObjectTypeIndices.offsets + group;
    while (group <= OBJTYPE_COUNT) {
        (*offset)--;
        offset++;
        group++;
    }
}

int objGetObjectType(GameObject* obj) {
    int group;
    int objectIndex;

    for (objectIndex = 0; objectIndex < (int)(u32)gObjectTypeListCount; objectIndex++) {
        GameObject* entryObj = gObjectTypeList[objectIndex];
        if (entryObj == obj) {
            group = 0;
            while (((int)(u32)gObjectTypeIndices.offsets[group] <= objectIndex) && (group < OBJTYPE_INDEX_COUNT)) {
                group++;
            }
            return group;
        }
    }
    return 0;
}

char sObjAddObjectTypeReachedMaxTypes[38] = "objAddObjectType: Reached MAXTYPES!!\n\000";

void objAddObjectType(GameObject* obj, int group) {
    u8* offset;
    int count;
    int index;
    int limit;
    int insertIndex;
    GameObject** entries;

    if ((group < 0) || (group >= OBJTYPE_COUNT)) {
        return;
    }
    if ((int)(u32)gObjectTypeListCount >= OBJTYPE_LIST_MAX) {
        OSReport(sObjAddObjectTypeReachedMaxTypes);
        return;
    }
    offset = gObjectTypeIndices.offsets;
    insertIndex = offset[group];
    offset += group;
    limit = offset[1];
    entries = gObjectTypeList + insertIndex;
    for (index = insertIndex; index < limit; index++) {
        if (*entries == obj) {
            return;
        }
        entries++;
    }
    insertIndex = (limit - insertIndex == 0) ? insertIndex : (limit - 1);
    gObjectTypeListCount++;
    count = (int)(u32)gObjectTypeListCount;
    count--;
    entries = gObjectTypeList + count;
    for (index = count; insertIndex < index; index--) {
        *entries = entries[-1];
        entries--;
    }
    gObjectTypeList[insertIndex] = obj;
    group++;
    offset = gObjectTypeIndices.offsets + group;
    while (group <= OBJTYPE_COUNT) {
        (*offset)++;
        offset++;
        group++;
    }
}

void objTypeInit(void) {
    memset(gObjectTypeIndices.offsets, 0, sizeof(gObjectTypeIndices.offsets));
    gObjectTypeListCount = 0;
    return;
}

int ObjMsg_Peek(GameObject* obj, u32* outMessage, u32* outSender, u32* outParam) {
    ObjMsgQueue* queue;

    if (obj == 0x0) {
        return 0;
    }
    queue = obj->msgQueue;
    if ((queue != (ObjMsgQueue*)0x0) && (queue->count != 0)) {
        if (outMessage != 0x0) {
            *outMessage = queue->entries[0].message;
        }
        if (outSender != 0x0) {
            *outSender = queue->entries[0].sender;
        }
        if (outParam != 0x0) {
            *outParam = queue->entries[0].param;
        }
        return 1;
    }
    return 0;
}

int ObjMsg_Pop(GameObject* obj, u32* outMessage, u32* outSender, u32* outParam) {
    ObjMsgQueue* queue;
    ObjMsgQueueCursor* slot;
    u32 i;

    if (obj == 0x0) {
        return 0;
    }
    queue = obj->msgQueue;
    if ((queue != (ObjMsgQueue*)0x0) && (queue->count != 0)) {
        queue->count = queue->count - 1;
        if (outMessage != 0x0) {
            *outMessage = queue->entries[0].message;
        }
        if (outSender != 0x0) {
            *outSender = queue->entries[0].sender;
        }
        if (outParam != 0x0) {
            *outParam = queue->entries[0].param;
        }
        for (i = 0; i < queue->count; i = i + 1) {
            slot = (ObjMsgQueueCursor*)((u8*)queue + ((i + i + i) << 2));
            slot->entry.message = slot->nextEntry.message;
            slot->entry.sender = slot->nextEntry.sender;
            slot->entry.param = slot->nextEntry.param;
        }
        return 1;
    }
    return 0;
}

char sObjMsgOverflowInObjectWarning[64] = "objmsg (%x): overflow in object %d defno=%d FROM: defno %d\n";

void ObjMsg_SendToNearbyObjects(int targetId, float radius, u32 flags, void* sender, u32 message, u32 param) {
    GameObject** objects;
    u32 count;
    int maskedFlags;
    ObjMsgQueue* queue;
    ObjMsgQueueCursor* slot;
    int objectIndex;
    int objectCount;
    GameObject* obj;
    int includeSender;
    int matchAny;
    GameObject* senderObj;

    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    maskedFlags = flags & 0xffff;
    includeSender = maskedFlags & OBJMSG_SEND_INCLUDE_SENDER;
    matchAny = maskedFlags & OBJMSG_SEND_MATCH_ANY;
    senderObj = (GameObject*)sender;
    for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
        obj = objects[objectIndex];
        if (((obj != sender) || (includeSender == 0)) && ((obj->anim.romDefNo == (s16)targetId || (matchAny != 0))) &&
            ((Vec_distance(&senderObj->anim.worldPosX, &obj->anim.worldPosX) < radius && (obj != 0x0)) &&
             (queue = obj->msgQueue, queue != (ObjMsgQueue*)0x0))) {
            count = queue->count;
            if (count < queue->capacity) {
                slot = (ObjMsgQueueCursor*)((u8*)queue + ((count + count + count) << 2));
                slot->entry.message = message;
                slot->entry.sender = (u32)sender;
                slot->entry.param = param;
                queue->count = queue->count + 1;
            } else {
                debugPrintf(sObjMsgOverflowInObjectWarning, message, (int)obj->anim.classId, (int)obj->anim.romDefNo,
                            (int)senderObj->anim.romDefNo);
            }
        }
    }
    return;
}

void ObjMsg_SendToObjects(int targetId, u32 flags, void* sender, u32 message, u32 param) {
    GameObject** objects;
    u32 count;
    int maskedFlags;
    ObjMsgQueue* queue;
    ObjMsgQueueCursor* slot;
    int objectIndex;
    int objectCount;
    GameObject* obj;

    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    maskedFlags = flags & 0xffff;
    if ((maskedFlags & OBJMSG_SEND_MATCH_OBJTYPE) != 0) {
        for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
            obj = objects[objectIndex];
            if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
                (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 || (targetId == obj->anim.romDefNo))) &&
                ((obj != 0x0 && (queue = obj->msgQueue, queue != (ObjMsgQueue*)0x0)))) {
                count = queue->count;
                if (count < queue->capacity) {
                    slot = (ObjMsgQueueCursor*)((u8*)queue + ((count + count + count) << 2));
                    slot->entry.message = message;
                    slot->entry.sender = (u32)sender;
                    slot->entry.param = param;
                    queue->count = queue->count + 1;
                } else {
                    debugPrintf(sObjMsgOverflowInObjectWarning, message, (int)obj->anim.classId,
                                (int)obj->anim.romDefNo, (int)((GameObject*)sender)->anim.romDefNo);
                }
            }
        }
    } else {
        for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
            obj = objects[objectIndex];
            if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_INCLUDE_SENDER) == 0)) &&
                (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 || (targetId == obj->anim.classId))) &&
                ((obj != 0x0 && (queue = obj->msgQueue, queue != (ObjMsgQueue*)0x0)))) {
                count = queue->count;
                if (count < queue->capacity) {
                    slot = (ObjMsgQueueCursor*)((u8*)queue + ((count + count + count) << 2));
                    slot->entry.message = message;
                    slot->entry.sender = (u32)sender;
                    slot->entry.param = param;
                    queue->count = queue->count + 1;
                } else {
                    debugPrintf(sObjMsgOverflowInObjectWarning, message, (int)obj->anim.classId,
                                (int)obj->anim.romDefNo, (int)((GameObject*)sender)->anim.romDefNo);
                }
            }
        }
    }
    return;
}

u32 ObjMsg_SendToObject(GameObject* obj, u32 message, void* sender, u32 param) {
    u32 count;
    GameObject* senderObj;
    ObjMsgQueue* queue;
    ObjMsgQueueCursor* slot;

    senderObj = sender;
    if (obj == NULL) {
        return 0;
    }
    queue = obj->msgQueue;
    if (queue != (ObjMsgQueue*)0x0) {
        count = queue->count;
        if (count < queue->capacity) {
            slot = (ObjMsgQueueCursor*)((u8*)queue + ((count + count + count) << 2));
            slot->entry.message = message;
            slot->entry.sender = (u32)senderObj;
            slot->entry.param = param;
            queue->count = queue->count + 1;
            return queue->count;
        }
        debugPrintf(sObjMsgOverflowInObjectWarning, message, (int)obj->anim.classId, (int)obj->anim.romDefNo,
                    (int)senderObj->anim.romDefNo);
    }
    return 0;
}

void ObjMsg_AllocQueue(GameObject* obj, int capacity) {
    int queueBytes;
    ObjMsgQueue* queue;

    if (((capacity != 0) && (obj != 0x0)) && (obj->msgQueue == (ObjMsgQueue*)0x0)) {
        queueBytes = (capacity * 3 + 2) * 4;
        queue = (ObjMsgQueue*)mmAlloc(queueBytes, 0xe, 0);
        queue->count = 0;
        queue->capacity = capacity;
        obj->msgQueue = queue;
    }
    return;
}

int Obj_IsObjectAlive(GameObject* objArg) {
    u32 alive;
    GameObject* obj = objArg;

    alive = 0;
    if ((obj != NULL) && ((obj->objectFlags & OBJLINK_FLAGS_DEAD) == 0)) {
        alive = 1;
    }
    return alive;
}

bool ObjTrigger_UpdateIdBlockFlag(GameObject* obj) {
    int disguised;
    u8 flags;

    disguised = (int)Obj_GetPlayerObject();
    disguised = playerIsDisguised((GameObject*)disguised);
    if (disguised != 0) {
        flags = obj->anim.resetHitboxFlags | OBJTRIGGER_ID_BLOCK_FLAG;
        obj->anim.resetHitboxFlags = flags;
        return false;
    }
    flags = obj->anim.resetHitboxFlags & ~OBJTRIGGER_ID_BLOCK_FLAG;
    obj->anim.resetHitboxFlags = flags;
    return true;
}

int ObjHits_PollPriorityHitWithCooldown(GameObject* obj, float* cooldown, GameObject** outHitObject, float* outHitPos) {
    int collisionType;

    collisionType = 0;
    *cooldown = *cooldown - timeDelta;
    if (*cooldown <= 0.0f) {
        if (outHitPos != (float*)0x0) {
            collisionType = ObjHits_GetPriorityHitWithPosition(obj, outHitObject, 0x0, 0x0, outHitPos, outHitPos + 1,
                                                               outHitPos + 2);
            if (collisionType != 0) {
                ObjHits_ConvertHitPositionToWorld(obj, outHitPos);
            }
        } else {
            collisionType = ObjHits_GetPriorityHit(obj, outHitObject, 0x0, 0x0);
        }
        if (collisionType != 0) {
            *cooldown = 30.0f;
        }
    }
    return collisionType;
}

int ObjHits_PollPriorityHitEffectWithCooldown(GameObject* obj, u32 hitFxMode, u32 colorR, u32 colorG, u32 colorB,
                                              u16 sfxId, float* cooldown) {
    int collisionType;
    StaffCollisionInterface** effectResource;
    PartFxSpawnParams effectParams;
    StaffCollisionColorArgs effectArgs;
    GameObject* hitObject;

    *cooldown = *cooldown - timeDelta;
    collisionType = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, 0x0, 0x0, &effectParams.posX,
                                                       &effectParams.posY, &effectParams.posZ);
    if ((*cooldown <= 0.0f) && (collisionType != 0)) {
        *cooldown = 45.0f;
        if ((collisionType != 0x1a) && (collisionType != 5)) {
            effectParams.posX = effectParams.posX + playerMapOffsetX;
            effectParams.posZ = effectParams.posZ + playerMapOffsetZ;
            effectParams.scale = 1.0f;
            effectParams.rotZ = 0;
            effectParams.rotY = 0;
            effectParams.rotX = 0;
            effectResource = Resource_Acquire(OBJHITREACT_HIT_EFFECT_ID, OBJHITREACT_HIT_EFFECT_RESOURCE_COUNT);
            effectArgs.count = hitFxMode & 0xff;
            effectArgs.red = colorR & 0xff;
            effectArgs.green = colorG & 0xff;
            effectArgs.blue = colorB & 0xff;
            (*effectResource)
                ->spawn(OBJHITREACT_HIT_EFFECT_PARENT_NONE, OBJHITREACT_HIT_EFFECT_MODE, &effectParams,
                        OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS, OBJHITREACT_HIT_EFFECT_NO_SOURCE, &effectArgs);
            if (((sfxId != 0) && (hitObject != 0)) && (hitObject->anim.romDefNo == OBJLIB_HITOBJ_SEQID_STAFF)) {
                Sfx_PlayFromObject(obj, sfxId);
            }
        }
    }
    return collisionType;
}

void ObjLink_DetachChild(GameObject* obj, GameObject* child) {
    int dst;
    int slot;
    int i;

    i = 0;
    for (slot = (int)obj; i < (int)obj->childCount; i++) {
        if (*(GameObject**)(slot + OBJLINK_CHILD_LIST_OFFSET) == child) {
            break;
        }
        slot += 4;
    }
    dst = (int)obj + i * 4;
    while (i < (int)obj->childCount - 1) {
        *(int*)(dst + OBJLINK_CHILD_LIST_OFFSET) = *(int*)(dst + OBJLINK_CHILD_LIST_OFFSET + sizeof(int));
        dst += 4;
        i++;
    }
    obj->childCount--;
    obj->childObjs[obj->childCount] = NULL;
    child->ownerObj = (void*)0;
    return;
}

void ObjLink_AttachChild(GameObject* parent, GameObject* child, int linkMode) {
    int childIndex;
    GameObject* parentObj;
    GameObject* childObj;

    parentObj = parent;
    childObj = child;
    childIndex = (int)parentObj->childCount;
    parentObj->childCount += 1;
    parentObj->childObjs[childIndex] = child;
    childObj->ownerObj = parent;
    childObj->objectFlags = (u16)(childObj->objectFlags & ~OBJLINK_FLAGS_MODE_MASK);
    childObj->objectFlags = (u16)(childObj->objectFlags | linkMode);
    childObj->colorFadeFlags = 0;
    return;
}

void ObjContact_DispatchCallbacks(GameObject* objA, GameObject* objB) {
    int objARefCount;
    int objBRefCount;
    int count;
    ObjContactCallbackEntry* entry;

    objARefCount = objA->contactRefCount;
    objBRefCount = objB->contactRefCount;
    entry = gObjContactCallbacks;
    count = gObjContactCallbackCount;
    while ((objARefCount != 0) && (objBRefCount != 0) && (count-- != 0)) {
        if ((entry->objA == objA) && (entry->objB == objB)) {
            objARefCount = objARefCount - 1;
            entry->callback(objA, objB);
        }
        if ((entry->objA == objB) && (entry->objB == objA)) {
            objBRefCount = objBRefCount - 1;
            entry->callback(objB, objA);
        }
        entry++;
    }
    return;
}

void ObjContact_RemoveObjectCallbacks(GameObject* obj) {
    int count;
    ObjContactCallbackEntry* entry;

    entry = gObjContactCallbacks;
    count = gObjContactCallbackCount;
    while (count-- > 0) {
        if ((entry->objA == obj) || (entry->objB == obj)) {
            gObjContactCallbackCount--;
            count--;
            entry->objA->contactRefCount--;
            entry->objB->contactRefCount--;
            if ((gObjContactCallbackCount != OBJCONTACT_CALLBACK_LAST_INDEX) && (gObjContactCallbackCount != 0)) {
                *entry = gObjContactCallbacks[gObjContactCallbackCount];
            }
        }
        entry++;
    }
    return;
}

int ObjContact_AddCallback(GameObject* obj, GameObject* otherObj, ObjContactCallback callback) {
    int count;
    ObjContactCallbackEntry* entry;
    int i;

    if ((obj == NULL) || (otherObj == NULL)) {
        return 0;
    }
    entry = gObjContactCallbacks;
    count = gObjContactCallbackCount;
    for (i = 0; i != count; i++) {
        if ((entry->objA == obj) && (entry->objB == otherObj)) {
            return 0;
        }
        entry++;
    }
    if (count >= OBJCONTACT_CALLBACK_CAPACITY) {
        return 0;
    }
    entry = &gObjContactCallbacks[count];
    entry->objA = obj;
    entry->objB = otherObj;
    entry->callback = callback;
    obj->contactRefCount += 1;
    otherObj->contactRefCount += 1;
    gObjContactCallbackCount = gObjContactCallbackCount + 1;
    return 1;
}

int ObjTrigger_IsSetById(GameObject* obj, int eventId) {
    int playerState;
    int triggerFlags;
    int flagEnabled;
    int flagBlocked;

    triggerFlags = obj->anim.resetHitboxFlags;
    flagEnabled = triggerFlags & OBJTRIGGER_ID_ENABLE_FLAG;
    if (flagEnabled != 0) {
        flagBlocked = triggerFlags & OBJTRIGGER_ID_BLOCK_FLAG;
        if ((flagBlocked == 0) &&
            (playerState = (*gGameUIInterface)->isItemBeingUsed((int)(short)eventId), playerState != 0)) {
            playerState = objGetAnimState80A((GameObject*)(Obj_GetPlayerObject()));
            if (playerState == OBJTRIGGER_PLAYER_STATE_NONE) {
                buttonDisable(OBJTRIGGER_BUTTON_DISABLE_INDEX, OBJTRIGGER_BUTTON_DISABLE_FLAG);
                return 1;
            }
        }
    }
    return 0;
}

int ObjTrigger_IsSet(GameObject* obj) {
    u32 flags;
    int playerState;
    int triggerFlags;
    int flagEnabled;
    int flagBlocked;

    if (obj->anim.modelInstance->hitVolumes == NULL) {
        return 0;
    }
    flags = buttonGetDisabled(0);
    if ((flags & OBJTRIGGER_BUTTON_DISABLE_FLAG) == 0) {
        triggerFlags = obj->anim.resetHitboxFlags;
        flagEnabled = triggerFlags & OBJTRIGGER_CURRENT_ENABLE_FLAG;
        if (flagEnabled != 0) {
            flagBlocked = triggerFlags & OBJTRIGGER_CURRENT_BLOCK_FLAG;
            if ((flagBlocked == 0) && (playerState = (*gGameUIInterface)->isAnyItemBeingUsed(), playerState == 0)) {
                playerState = objGetAnimState80A((GameObject*)(Obj_GetPlayerObject()));
                if ((playerState == OBJTRIGGER_PLAYER_STATE_NONE) || (playerState == OBJTRIGGER_PLAYER_STATE_CLEAR)) {
                    buttonDisable(OBJTRIGGER_BUTTON_DISABLE_INDEX, OBJTRIGGER_BUTTON_DISABLE_FLAG);
                    return 1;
                }
            }
        }
    }
    return 0;
}

GameObject* ObjList_FindNearestObjectByDefNo(GameObject* obj, int defNo, float* maxDistanceSq) {
    int startIndex;
    int objectCount;
    float invalidDistance;
    float distanceSq;
    GameObject* otherObj;
    int objectIndex;
    GameObject** objects;
    GameObject* foundObj;

    objects = ObjList_GetObjects(&startIndex, &objectCount);
    foundObj = 0;
    *maxDistanceSq = *maxDistanceSq * *maxDistanceSq;

    if (defNo != -1) {
        objectIndex = startIndex;

        while (objectIndex < objectCount) {
            otherObj = objects[objectIndex];
            if (((defNo == otherObj->anim.romDefNo) && (obj != otherObj)) &&
                (distanceSq = vec3f_distanceSquared(&obj->anim.worldPosX, &otherObj->anim.worldPosX),
                 distanceSq < *maxDistanceSq)) {
                *maxDistanceSq = distanceSq;
                foundObj = objects[objectIndex];
            }
            objectIndex++;
        }
    } else {
        objectIndex = startIndex;
        invalidDistance = 0.0f;

        while (objectIndex < objectCount) {
            distanceSq = vec3f_distanceSquared(&obj->anim.worldPosX, &objects[objectIndex]->anim.worldPosX);
            if ((distanceSq != invalidDistance) && (distanceSq < *maxDistanceSq)) {
                *maxDistanceSq = distanceSq;
                foundObj = objects[objectIndex];
            }
            objectIndex++;
        }
    }

    return foundObj;
}

int ObjList_ContainsObject(GameObject* obj) {
    GameObject** entry;
    int i;
    int count;

    entry = ObjList_GetObjects(&i, &count);
    i = 0;
    while (i < count) {
        if (entry[i] == obj) {
            return 1;
        }
        i = i + 1;
    }
    return 0;
}

void ObjPath_GetPointWorldPositionArray(GameObject* obj, int pointIndex, int count, float* positions) {
    float* position;
    int i;

    i = 0;
    position = positions;
    while (i < count) {
        ObjPath_GetPointWorldPosition(obj, pointIndex + i, position, position + 1, position + 2, 0);
        position = position + 3;
        i++;
    }
}

void ObjPath_GetPointLocalPosition(GameObject* obj, int pointIndex, float* xOut, float* yOut, float* zOut) {
    *xOut = ((ObjPathPoint*)(*(int*)((int)obj->anim.modelInstance + OBJPATH_POINTS_OFFSET) +
                             pointIndex * sizeof(ObjPathPoint)))
                ->x;
    *yOut =
        *(f32*)(*(int*)((int)obj->anim.modelInstance + OBJPATH_POINTS_OFFSET) + 4 + pointIndex * sizeof(ObjPathPoint));
    *zOut =
        *(f32*)(*(int*)((int)obj->anim.modelInstance + OBJPATH_POINTS_OFFSET) + 8 + pointIndex * sizeof(ObjPathPoint));
    return;
}

void ObjPath_GetPointLocalMtx(GameObject* obj, int pointIndex, float* mtxOut) {
    ObjPathPoint* pathPoint;
    ObjPathTransform transform;

    pathPoint = (ObjPathPoint*)obj->anim.modelInstance->attachPoints;
    transform.x = pathPoint[pointIndex].x;
    pathPoint += pointIndex;
    transform.y = pathPoint->y;
    transform.z = pathPoint->z;
    transform.rotX = pathPoint->rotX;
    transform.rotY = pathPoint->rotY;
    transform.rotZ = pathPoint->rotZ;
    transform.scale = 1.0f;
    setMatrixFromObjectTransposed(&transform, mtxOut);
    return;
}

ObjModelJointMatrix* ObjPath_GetPointModelMtx(GameObject* obj, int pointIndex) {
    ObjModel* model;
    ObjPathPoint* pathPoint;
    int jointIndex;

    model = Obj_GetActiveModel(obj);
    pathPoint = (ObjPathPoint*)obj->anim.modelInstance->attachPoints;
    pathPoint += pointIndex;
    jointIndex = pathPoint->modelIndex[obj->anim.bankIndex];
    if ((jointIndex >= 0) && (jointIndex < (int)(u32)model->file->jointCount)) {
        return ObjModel_GetJointMatrix((u8*)model, jointIndex);
    } else {
        return ObjModel_GetJointMatrix((u8*)model, 0);
    }
}

void ObjPath_GetPointWorldPosition(GameObject* obj, int pointIndex, float* outX, float* outY, float* outZ,
                                   int useInputPosition) {
    int pointOffset;
    ObjPathPoint* pathPoint;
    int* model;
    float* jointMtx;
    int jointIndex;
    ObjPathTransform transform;
    float rootMtx[16];
    float transposedMtx[12];
    float concatMtx[12];
    float rotMtx[16];

    if ((pointIndex < 0) ||
        (pointIndex >= (int)(u32) * (u8*)((int)obj->anim.modelInstance + OBJPATH_POINT_COUNT_OFFSET))) {
        *outX = obj->anim.localPosX;
        *outY = obj->anim.localPosY;
        *outZ = obj->anim.localPosZ;
    } else {
        model = (int*)Obj_GetActiveModel(obj);
        pathPoint = (ObjPathPoint*)(*(int*)((int)obj->anim.modelInstance + OBJPATH_POINTS_OFFSET));
        pointOffset = pointIndex * sizeof(ObjPathPoint);
        pathPoint = (ObjPathPoint*)((int)pathPoint + pointOffset);
        jointIndex = pathPoint->modelIndex[(int)*(char*)((int)obj + OBJ_ACTIVE_MODEL_INDEX_OFFSET)];
        if ((jointIndex < OBJPATH_ROOT_JOINT_INDEX) ||
            (jointIndex >= (int)(u32) * (u8*)(*model + OBJ_MODEL_JOINT_COUNT_OFFSET))) {
            *outX = obj->anim.localPosX;
            *outY = obj->anim.localPosY;
            *outZ = obj->anim.localPosZ;
        } else {
            if (jointIndex == OBJPATH_ROOT_JOINT_INDEX) {
                Obj_BuildWorldTransformMatrix(obj, rootMtx, 0);
                jointMtx = rootMtx;
            } else {
                jointMtx = (f32*)ObjModel_GetJointMatrix((u8*)model, jointIndex);
            }
            if (useInputPosition != 0) {
                transform.x = *outX;
                transform.y = *outY;
                transform.z = *outZ;
                transform.rotX = 0;
                transform.rotY = 0;
                transform.rotZ = 0;
            } else {
                transform.x = *(f32*)(*(int*)((int)obj->anim.modelInstance + OBJPATH_POINTS_OFFSET) + pointOffset);
                pathPoint =
                    (ObjPathPoint*)(*(int*)((int)obj->anim.modelInstance + OBJPATH_POINTS_OFFSET) + pointOffset);
                transform.y = pathPoint->y;
                transform.z = pathPoint->z;
                transform.rotX = pathPoint->rotX;
                transform.rotY = pathPoint->rotY;
                transform.rotZ = pathPoint->rotZ;
            }
            mtxRotateByVec3s(rotMtx, &transform);
            mtx44Transpose(rotMtx, transposedMtx);
            PSMTXConcat((MtxPtr)jointMtx, (MtxPtr)transposedMtx, (MtxPtr)concatMtx);
            *outX = concatMtx[3] + playerMapOffsetX;
            *outY = concatMtx[7];
            *outZ = concatMtx[11] + playerMapOffsetZ;
        }
    }
}

s16 Obj_GetYawDeltaToObject(GameObject* obj, GameObject* target, float* distOut) {
    int yawDelta;
    float dx;
    float dz;

    dx = obj->anim.localPosX - target->anim.localPosX;
    dz = obj->anim.localPosZ - target->anim.localPosZ;
    yawDelta = (s16)getAngle(dx, dz);
    if (distOut != (float*)0x0) {
        *distOut = sqrtf(dx * dx + dz * dz);
    }
    yawDelta = (int)(short)yawDelta - (u32)(u16) * (s16*)obj;
    if (yawDelta > 0x8000) {
        yawDelta = yawDelta + -0xffff;
    }
    if (yawDelta < -0x8000) {
        yawDelta = yawDelta + 0xffff;
    }
    return (int)(short)yawDelta;
}

u32 ObjHitRegion_FindContainingId(f32 x, f32 y, f32 z) {
    MapRomListPage** lists;
    MapRomListPage* list;
    ObjHitRegionPlacement* entry;
    int listIndex;
    int entryOffset;
    int hitId;

    hitId = -1;
    lists = RomList_GetLoadedPages();
    for (listIndex = 0; listIndex < OBJLIB_PRIMARY_ROM_PAGE_COUNT; listIndex++) {
        list = lists[listIndex];
        if (list != 0) {
            entry = (ObjHitRegionPlacement*)list->objects;
            entryOffset = 0;
            while (entryOffset < (int)(u32)list->objectDataSize) {
                if (entry->base.objectId == OBJHITREGION_ROM_ENTRY_TYPE) {
                    f32 yawSin = mathSinf(3.1415927f * (f32) - (s32)((u32)entry->yaw << 8) / 32768.0f);
                    f32 yawCos = mathCosf(3.1415927f * (f32) - (s32)((u32)entry->yaw << 8) / 32768.0f);
                    f32 pitchSin = mathSinf(3.1415927f * (f32) - (s32)((u32)entry->pitch << 8) / 32768.0f);
                    f32 pitchCos = mathCosf(3.1415927f * (f32) - (s32)((u32)entry->pitch << 8) / 32768.0f);
                    f32 deltaZ;
                    f32 deltaY;
                    f32 deltaX;
                    f32 localX;
                    f32 yawZ;
                    f32 localY;
                    f32 localZ;
                    deltaX = x - entry->base.posX;
                    deltaY = y - entry->base.posY;
                    deltaZ = z - entry->base.posZ;
                    localX = deltaX * yawCos - deltaZ * yawSin;
                    yawZ = deltaX * yawSin + deltaZ * yawCos;
                    localY = deltaY * pitchCos - yawZ * pitchSin;
                    localZ = deltaY * pitchSin + yawZ * pitchCos;

                    if (localX < 0.0f) {
                        localX = -localX;
                    }
                    if (localY < 0.0f) {
                        localY = -localY;
                    }
                    if (localZ < 0.0f) {
                        localZ = -localZ;
                    }
                    if ((localX <= (f32)(u32)entry->halfX) && (localY <= (f32)(u32)entry->halfY) &&
                        (localZ <= (f32)(u32)entry->halfZ)) {
                        hitId = entry->id;
                    }
                }
                entryOffset += entry->base.size * 4;
                entry = (ObjHitRegionPlacement*)((u8*)entry + entry->base.size * 4);
            }
        }
    }
    return hitId & 0xffff;
}

ObjContactCallbackEntry gObjContactCallbacks[0xC0 / sizeof(ObjContactCallbackEntry)];
ObjectTypeIndexTable gObjectTypeIndices;
