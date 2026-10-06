#define OBJHITS_SETTERS_S16
#include "main/obj_message.h"
#include <string.h>
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "MSL_C/PPCEABI/bare/H/math_api.h"
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
#include "MSL_C/PPCEABI/bare/H/inverse_trig.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "track/intersect_api.h"
#include "main/objprint_internal.h"

#define OBJLIB_PRIMARY_ROM_PAGE_COUNT 0x50
#define OBJHITREGION_ROM_ENTRY_TYPE   0x130

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
int gObjContactCallbackCount;
#define OBJMSG_SEND_IGNORE_SENDER 0x1
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

#define OBJLINK_CHILD_LIST_OFFSET 0xc8
#define OBJLINK_FLAGS_MODE_MASK   0x0007
#define OBJLINK_FLAGS_DEAD        0x0040

/* hit-object romDefNo that triggers the staff-impact sfx (retail OBJECTS.bin). */
#define OBJLIB_HITOBJ_SEQID_STAFF 0x69 /* "staff" (DLL 0xE2) */
#define OBJPATH_ROOT_JOINT_INDEX  -1
/* A two-word header is followed by three-word messages (id, sender, argument).
 * Keep the retail word indexing, with pointer members for the two pointer slots.
 * This also gives each slot the correct width in native builds. */
typedef union ObjMsgWord {
    u32 value;
    GameObject* sender;
    void* param;
} ObjMsgWord;

struct ObjMsgQueue {
    ObjMsgWord words[1];
};

enum {
    OBJMSG_COUNT = 0,
    OBJMSG_CAPACITY = 1,
    OBJMSG_HEADER_WORDS = 2,
    OBJMSG_MESSAGE = OBJMSG_HEADER_WORDS,
    OBJMSG_SENDER = 3,
    OBJMSG_PARAM = 4,
    OBJMSG_WORDS_PER_MESSAGE = 3
};

STATIC_ASSERT(sizeof(ObjMsgWord) == 4);

int ObjMsg_Peek(GameObject* obj, u32* outMessage, GameObject** outSender, void** outParam) {
    ObjMsgQueue* queue;

    if (obj == 0x0) {
        return 0;
    }
    queue = obj->msgQueue;
    if ((queue != (ObjMsgQueue*)0x0) && (queue->words[OBJMSG_COUNT].value != 0)) {
        if (outMessage != 0x0) {
            *outMessage = queue->words[OBJMSG_MESSAGE].value;
        }
        if (outSender != 0x0) {
            *outSender = queue->words[OBJMSG_SENDER].sender;
        }
        if (outParam != 0x0) {
            *outParam = queue->words[OBJMSG_PARAM].param;
        }
        return 1;
    }
    return 0;
}

int ObjMsg_Pop(GameObject* obj, u32* outMessage, GameObject** outSender, void** outParam) {
    ObjMsgQueue* queue;
    ObjMsgWord* slot;
    u32 i;

    if (obj == 0x0) {
        return 0;
    }
    queue = obj->msgQueue;
    if ((queue != (ObjMsgQueue*)0x0) && (queue->words[OBJMSG_COUNT].value != 0)) {
        queue->words[OBJMSG_COUNT].value -= 1;
        if (outMessage != 0x0) {
            *outMessage = queue->words[OBJMSG_MESSAGE].value;
        }
        if (outSender != 0x0) {
            *outSender = queue->words[OBJMSG_SENDER].sender;
        }
        if (outParam != 0x0) {
            *outParam = queue->words[OBJMSG_PARAM].param;
        }
        for (i = 0; i < queue->words[OBJMSG_COUNT].value; i = i + 1) {
            slot = queue->words + (i + i + i);
            slot[OBJMSG_MESSAGE].value = slot[OBJMSG_MESSAGE + OBJMSG_WORDS_PER_MESSAGE].value;
            slot[OBJMSG_SENDER].sender = slot[OBJMSG_SENDER + OBJMSG_WORDS_PER_MESSAGE].sender;
            slot[OBJMSG_PARAM].param = slot[OBJMSG_PARAM + OBJMSG_WORDS_PER_MESSAGE].param;
        }
        return 1;
    }
    return 0;
}

char sObjMsgOverflowInObjectWarning[64] = "objmsg (%x): overflow in object %d defno=%d FROM: defno %d\n";

void ObjMsg_SendToNearbyObjects(int targetId, float radius, u32 flags, GameObject* sender, u32 message, void* param) {
    GameObject** objects;
    u32 count;
    int maskedFlags;
    ObjMsgQueue* queue;
    ObjMsgWord* slot;
    int objectIndex;
    int objectCount;
    GameObject* obj;
    int ignoreSender;
    int matchAny;
    GameObject* senderObj;

    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    maskedFlags = flags & 0xffff;
    ignoreSender = maskedFlags & OBJMSG_SEND_IGNORE_SENDER;
    matchAny = maskedFlags & OBJMSG_SEND_MATCH_ANY;
    senderObj = (GameObject*)sender;
    for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
        obj = objects[objectIndex];
        if (((obj != sender) || (ignoreSender == 0)) && ((obj->anim.romDefNo == (s16)targetId || (matchAny != 0))) &&
            ((Vec_distance(&senderObj->anim.worldPosX, &obj->anim.worldPosX) < radius && (obj != 0x0)) &&
             (queue = obj->msgQueue, queue != (ObjMsgQueue*)0x0))) {
            count = queue->words[OBJMSG_COUNT].value;
            if (count < queue->words[OBJMSG_CAPACITY].value) {
                slot = queue->words + (count + count + count);
                slot[OBJMSG_MESSAGE].value = message;
                slot[OBJMSG_SENDER].sender = sender;
                slot[OBJMSG_PARAM].param = param;
                queue->words[OBJMSG_COUNT].value += 1;
            } else {
                debugPrintf(sObjMsgOverflowInObjectWarning, message, (int)obj->anim.classId, (int)obj->anim.romDefNo,
                            (int)senderObj->anim.romDefNo);
            }
        }
    }
    return;
}

void ObjMsg_SendToObjects(int targetId, u32 flags, GameObject* sender, u32 message, void* param) {
    GameObject** objects;
    u32 count;
    int maskedFlags;
    ObjMsgQueue* queue;
    ObjMsgWord* slot;
    int objectIndex;
    int objectCount;
    GameObject* obj;

    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    maskedFlags = flags & 0xffff;
    if ((maskedFlags & OBJMSG_SEND_MATCH_OBJTYPE) != 0) {
        for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
            obj = objects[objectIndex];
            if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_IGNORE_SENDER) == 0)) &&
                (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 || (targetId == obj->anim.romDefNo))) &&
                ((obj != 0x0 && (queue = obj->msgQueue, queue != (ObjMsgQueue*)0x0)))) {
                count = queue->words[OBJMSG_COUNT].value;
                if (count < queue->words[OBJMSG_CAPACITY].value) {
                    slot = queue->words + (count + count + count);
                    slot[OBJMSG_MESSAGE].value = message;
                    slot[OBJMSG_SENDER].sender = sender;
                    slot[OBJMSG_PARAM].param = param;
                    queue->words[OBJMSG_COUNT].value += 1;
                } else {
                    debugPrintf(sObjMsgOverflowInObjectWarning, message, (int)obj->anim.classId,
                                (int)obj->anim.romDefNo, (int)((GameObject*)sender)->anim.romDefNo);
                }
            }
        }
    } else {
        for (; objectIndex < objectCount; objectIndex = objectIndex + 1) {
            obj = objects[objectIndex];
            if (((obj != sender) || ((maskedFlags & OBJMSG_SEND_IGNORE_SENDER) == 0)) &&
                (((maskedFlags & OBJMSG_SEND_MATCH_ANY) != 0 || (targetId == obj->anim.classId))) &&
                ((obj != 0x0 && (queue = obj->msgQueue, queue != (ObjMsgQueue*)0x0)))) {
                count = queue->words[OBJMSG_COUNT].value;
                if (count < queue->words[OBJMSG_CAPACITY].value) {
                    slot = queue->words + (count + count + count);
                    slot[OBJMSG_MESSAGE].value = message;
                    slot[OBJMSG_SENDER].sender = sender;
                    slot[OBJMSG_PARAM].param = param;
                    queue->words[OBJMSG_COUNT].value += 1;
                } else {
                    debugPrintf(sObjMsgOverflowInObjectWarning, message, (int)obj->anim.classId,
                                (int)obj->anim.romDefNo, (int)((GameObject*)sender)->anim.romDefNo);
                }
            }
        }
    }
    return;
}

u32 ObjMsg_SendToObject(GameObject* obj, u32 message, GameObject* sender, void* param) {
    u32 count;
    GameObject* senderObj;
    ObjMsgQueue* queue;
    ObjMsgWord* slot;

    senderObj = sender;
    if (obj == NULL) {
        return 0;
    }
    queue = obj->msgQueue;
    if (queue != (ObjMsgQueue*)0x0) {
        count = queue->words[OBJMSG_COUNT].value;
        if (count < queue->words[OBJMSG_CAPACITY].value) {
            slot = queue->words + (count + count + count);
            slot[OBJMSG_MESSAGE].value = message;
            slot[OBJMSG_SENDER].sender = senderObj;
            slot[OBJMSG_PARAM].param = param;
            queue->words[OBJMSG_COUNT].value += 1;
            return queue->words[OBJMSG_COUNT].value;
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
        queueBytes = (capacity * OBJMSG_WORDS_PER_MESSAGE + OBJMSG_HEADER_WORDS) * sizeof(ObjMsgWord);
        queue = (ObjMsgQueue*)mmAlloc(queueBytes, 0xe, 0);
        queue->words[OBJMSG_COUNT].value = 0;
        queue->words[OBJMSG_CAPACITY].value = capacity;
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
            effectParams.posX += playerMapOffsetX;
            effectParams.posZ += playerMapOffsetZ;
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
            objARefCount -= 1;
            entry->callback(objA, objB);
        }
        if ((entry->objA == objB) && (entry->objB == objA)) {
            objBRefCount -= 1;
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
    gObjContactCallbackCount += 1;
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
        i += 1;
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
        position += 3;
        i++;
    }
}

void ObjPath_GetPointLocalPosition(GameObject* obj, int pointIndex, float* xOut, float* yOut, float* zOut) {
    *xOut = obj->anim.modelInstance->attachPoints[pointIndex].pos[0];
    *yOut = obj->anim.modelInstance->attachPoints[pointIndex].pos[1];
    *zOut = obj->anim.modelInstance->attachPoints[pointIndex].pos[2];
    return;
}

void ObjPath_GetPointLocalMtx(GameObject* obj, int pointIndex, float* mtxOut) {
    ObjAttachPoint* pathPoint;
    ObjPathTransform transform;

    pathPoint = obj->anim.modelInstance->attachPoints;
    transform.x = pathPoint[pointIndex].pos[0];
    pathPoint += pointIndex;
    transform.y = pathPoint->pos[1];
    transform.z = pathPoint->pos[2];
    transform.rotX = pathPoint->rot[0];
    transform.rotY = pathPoint->rot[1];
    transform.rotZ = pathPoint->rot[2];
    transform.scale = 1.0f;
    setMatrixFromObjectTransposed(&transform, mtxOut);
    return;
}

ObjModelJointMatrix* ObjPath_GetPointModelMtx(GameObject* obj, int pointIndex) {
    ObjModel* model;
    ObjAttachPoint* pathPoint;
    int jointIndex;

    model = Obj_GetActiveModel(obj);
    pathPoint = obj->anim.modelInstance->attachPoints;
    pathPoint += pointIndex;
    jointIndex = pathPoint->joints[obj->anim.bankIndex];
    if ((jointIndex >= 0) && (jointIndex < (int)(u32)model->file->jointCount)) {
        return ObjModel_GetJointMatrix((u8*)model, jointIndex);
    } else {
        return ObjModel_GetJointMatrix((u8*)model, 0);
    }
}

void ObjPath_GetPointWorldPosition(GameObject* obj, int pointIndex, float* outX, float* outY, float* outZ,
                                   int useInputPosition) {
    ObjAttachPoint* pathPoint;
    ObjModel* model;
    float* jointMtx;
    int jointIndex;
    ObjPathTransform transform;
    float rootMtx[16];
    float transposedMtx[12];
    float concatMtx[12];
    float rotMtx[16];

    if ((pointIndex < 0) || (pointIndex >= (int)obj->anim.modelInstance->attachPointCount)) {
        *outX = obj->anim.localPosX;
        *outY = obj->anim.localPosY;
        *outZ = obj->anim.localPosZ;
    } else {
        model = Obj_GetActiveModel(obj);
        pathPoint = &obj->anim.modelInstance->attachPoints[pointIndex];
        jointIndex = pathPoint->joints[obj->anim.bankIndex];
        if ((jointIndex < OBJPATH_ROOT_JOINT_INDEX) || (jointIndex >= (int)model->file->jointCount)) {
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
                transform.x = obj->anim.modelInstance->attachPoints[pointIndex].pos[0];
                pathPoint = &obj->anim.modelInstance->attachPoints[pointIndex];
                transform.y = pathPoint->pos[1];
                transform.z = pathPoint->pos[2];
                transform.rotX = pathPoint->rot[0];
                transform.rotY = pathPoint->rot[1];
                transform.rotZ = pathPoint->rot[2];
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
        yawDelta += -0xffff;
    }
    if (yawDelta < -0x8000) {
        yawDelta += 0xffff;
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
