#include "dlls/objects/325_CloudPrison.h"

#include "main/dll/rom_curve_interface.h"
#include "main/obj_message.h"
#include "main/object_render.h"

#define CLOUD_PRISON_CONTROL_CURVE_ACTION                 8
#define CLOUD_PRISON_CONTROL_MESSAGE_QUEUE_CAPACITY       10
#define CLOUD_PRISON_CONTROL_TARGET_CAPACITY              20
#define CLOUD_PRISON_CONTROL_DEFERRED_STORAGE_WORD_COUNT  0x22
#define CLOUD_PRISON_CONTROL_DEFERRED_MESSAGE_RECORD_SIZE 0x0C

typedef struct CloudPrisonTarget {
    GameObject* object;
    s16 value;
    u8 flags;
    u8 padding;
} CloudPrisonTarget;

typedef struct CloudPrisonDeferredMessage {
    int messageId;
    GameObject* sender;
    int data;
} CloudPrisonDeferredMessage;

typedef enum CloudPrisonControlMessage {
    CLOUD_PRISON_CONTROL_MESSAGE_REGISTERED = 0xF0003,
    CLOUD_PRISON_CONTROL_MESSAGE_REGISTER = 0xF0004,
    CLOUD_PRISON_CONTROL_MESSAGE_IGNORED_5 = 0xF0005,
    CLOUD_PRISON_CONTROL_MESSAGE_IGNORED_6 = 0xF0006,
    CLOUD_PRISON_CONTROL_MESSAGE_IGNORED_7 = 0xF0007,
    CLOUD_PRISON_CONTROL_MESSAGE_UNREGISTER = 0xF0008,
} CloudPrisonControlMessage;

STATIC_ASSERT(sizeof(CloudPrisonTarget) == 0x08);
STATIC_ASSERT(offsetof(CloudPrisonTarget, object) == 0x00);
STATIC_ASSERT(offsetof(CloudPrisonTarget, value) == 0x04);
STATIC_ASSERT(offsetof(CloudPrisonTarget, flags) == 0x06);
STATIC_ASSERT(sizeof(CloudPrisonDeferredMessage) == CLOUD_PRISON_CONTROL_DEFERRED_MESSAGE_RECORD_SIZE);
STATIC_ASSERT(offsetof(CloudPrisonDeferredMessage, messageId) == 0x00);
STATIC_ASSERT(offsetof(CloudPrisonDeferredMessage, sender) == 0x04);
STATIC_ASSERT(offsetof(CloudPrisonDeferredMessage, data) == 0x08);

s8 gCloudPrisonControlNeedsCurveLookup = 1;

int gCloudPrisonCurveId;
s8 gCloudPrisonTargetCount;
s8 gCloudPrisonDeferredMessageCount;

CloudPrisonTarget gCloudPrisonTargets[CLOUD_PRISON_CONTROL_TARGET_CAPACITY];
/* The retail 0x88-byte extent is not an integral number of message records. */
u32 gCloudPrisonDeferredMessageStorage[CLOUD_PRISON_CONTROL_DEFERRED_STORAGE_WORD_COUNT];

int CloudPrisonControl_getExtraSize(void) {
    return 0;
}

int CloudPrisonControl_getObjectTypeId(void) {
    return 0;
}

void CloudPrisonControl_free(void) {
}

void CloudPrisonControl_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                               s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void CloudPrisonControl_hitDetect(void) {
}

void CloudPrisonControl_update(GameObject* obj) {
    GameObject* sender;
    int data;
    int message[2];
    int targetIndex;
    int targetCount;
    int deferredOffset;
    int targetValue;
    int messageId;
    CloudPrisonTarget* targetEntry[1];
    CloudPrisonTarget* targetSearch[1];
    int targetFound;
    u32 targetAddress;

    data = 0;
    if (gCloudPrisonControlNeedsCurveLookup != 0) {
        gCloudPrisonCurveId = (*gRomCurveInterface)->findByAction(CLOUD_PRISON_CONTROL_CURVE_ACTION);
        gCloudPrisonControlNeedsCurveLookup = 0;
    }
    gCloudPrisonDeferredMessageCount = 0;
    while (ObjMsg_Pop(obj, (u32*)message, (u32*)&sender, (u32*)&data) != 0) {
        messageId = message[0];
        switch (messageId) {
        case CLOUD_PRISON_CONTROL_MESSAGE_REGISTER:
            if (sender->anim.mapEventSlot == obj->anim.mapEventSlot) {
                targetFound = 0;
                targetAddress = (int)sender;
                targetEntry[0] = gCloudPrisonTargets;
                targetValue = data;
                targetCount = gCloudPrisonTargetCount;
                for (targetIndex = 0; targetIndex < targetCount; targetIndex++) {
                    if ((u32)targetEntry[0]->object == targetAddress) {
                        targetEntry[0]->value = targetValue;
                        targetFound = 1;
                    }
                    targetEntry[0]++;
                }
                if (!targetFound) {
                    gCloudPrisonTargets[gCloudPrisonTargetCount].object = sender;
                    gCloudPrisonTargets[gCloudPrisonTargetCount].flags = 0;
                    gCloudPrisonTargets[gCloudPrisonTargetCount++].value = data;
                }
                ObjMsg_SendToObject((void*)sender, CLOUD_PRISON_CONTROL_MESSAGE_REGISTERED, obj, 0);
            }
            break;
        case CLOUD_PRISON_CONTROL_MESSAGE_IGNORED_5:
        case CLOUD_PRISON_CONTROL_MESSAGE_IGNORED_6:
        case CLOUD_PRISON_CONTROL_MESSAGE_IGNORED_7:
            break;
        case CLOUD_PRISON_CONTROL_MESSAGE_UNREGISTER:
            targetIndex = 0;
            targetSearch[0] = gCloudPrisonTargets;
            while (targetIndex < gCloudPrisonTargetCount && targetSearch[0]->object != sender) {
                targetSearch[0]++;
                targetIndex++;
            }
            gCloudPrisonTargetCount--;
            targetCount = gCloudPrisonTargetCount;
            targetEntry[0] = &gCloudPrisonTargets[targetCount];
            while (targetCount > targetIndex) {
                targetEntry[0][-1].object = targetEntry[0][0].object;
                targetEntry[0][-1].value = targetEntry[0][0].value;
                targetEntry[0][-1].flags = targetEntry[0][0].flags;
                targetEntry[0]--;
                targetCount--;
            }
            break;
        default:
            deferredOffset = gCloudPrisonDeferredMessageCount * CLOUD_PRISON_CONTROL_DEFERRED_MESSAGE_RECORD_SIZE;
            ((CloudPrisonDeferredMessage*)((char*)gCloudPrisonDeferredMessageStorage + deferredOffset))->sender =
                sender;
            ((CloudPrisonDeferredMessage*)((char*)gCloudPrisonDeferredMessageStorage + deferredOffset))->messageId =
                messageId;
            ((CloudPrisonDeferredMessage*)((char*)gCloudPrisonDeferredMessageStorage + deferredOffset))->data = data;
            gCloudPrisonDeferredMessageCount++;
            break;
        }
    }
}

void CloudPrisonControl_init(GameObject* obj) {
    ObjMsg_AllocQueue(obj, CLOUD_PRISON_CONTROL_MESSAGE_QUEUE_CAPACITY);
}

void CloudPrisonControl_release(void) {
}

void CloudPrisonControl_initialise(void) {
    gCloudPrisonControlNeedsCurveLookup = 1;
}

CloudPrisonControlDescriptor gCloudPrisonControlObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        CloudPrisonControl_initialise,
        CloudPrisonControl_release,
        0,
        (ObjectDescriptorCallback)CloudPrisonControl_init,
        (ObjectDescriptorCallback)CloudPrisonControl_update,
        CloudPrisonControl_hitDetect,
        (ObjectDescriptorCallback)CloudPrisonControl_render,
        CloudPrisonControl_free,
        (ObjectDescriptorCallback)CloudPrisonControl_getObjectTypeId,
        CloudPrisonControl_getExtraSize,
    },
    {
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x41B00000,
        0x00000000,
        0x00000000,
        0x41C00000,
        0x41C80000,
        0x00000000,
        0x41F00000,
        0xC1C80000,
        0x00000000,
        0x41B80000,
        0x41A00000,
        0x41800000,
    },
};
