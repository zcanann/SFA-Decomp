/* Drives a sequence-controlled prop and relays its queued messages. */
#include "dlls/objects/323_FEseqobject.h"

#include "main/dll/partfx_interface.h"
#include "main/gamebits.h"
#include "main/obj_message.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/objtype.h"

/* Animation-event opcodes consumed by FEseqobject_SeqFn. */
typedef enum FEseqobjectEvent {
    FESEQOBJECT_EVENT_SET_GAME_BIT = 1,
    FESEQOBJECT_EVENT_PARTICLE_VARIANT_0 = 2,
    FESEQOBJECT_EVENT_PARTICLE_VARIANT_1 = 3,
    FESEQOBJECT_EVENT_PARTICLE_VARIANT_2 = 4,
    FESEQOBJECT_EVENT_PARTICLE_VARIANT_3 = 5,
    FESEQOBJECT_EVENT_PARTICLE_VARIANT_4 = 6,
} FEseqobjectEvent;

/* Object messages relayed to the romDefNo-0xF7 receiver. */
typedef enum FEseqobjectMessage {
    FESEQOBJECT_MESSAGE_IN_1 = 0xF000B,
    FESEQOBJECT_MESSAGE_IN_2 = 0xF000C,
    FESEQOBJECT_MESSAGE_IN_3 = 0xF000D,
    FESEQOBJECT_MESSAGE_OUT_1 = 0x130001,
    FESEQOBJECT_MESSAGE_OUT_2 = 0x130002,
    FESEQOBJECT_MESSAGE_OUT_3 = 0x130003,
} FEseqobjectMessage;

#define FESEQOBJECT_MESSAGE_QUEUE_CAPACITY 10
#define FESEQOBJECT_PARTICLE_EFFECT_ID     0x85
#define FESEQOBJECT_PARTICLE_MODEL_NONE    -1
#define FESEQOBJECT_PARTICLE_SPAWN_MODE    1
#define FESEQOBJECT_RECEIVER_OBJECT_GROUP  3
#define FESEQOBJECT_RECEIVER_SEQ_ID        0xF7
#define FESEQOBJECT_SEQUENCE_INDEX         0
#define FESEQOBJECT_SEQUENCE_ROTATION      0x2000

static inline void FEseqobject_spawnEffect(GameObject* obj, PartFxSpawnParams* params) {
    (*gPartfxInterface)
        ->spawnObject(obj, FESEQOBJECT_PARTICLE_EFFECT_ID, params, FESEQOBJECT_PARTICLE_SPAWN_MODE,
                      FESEQOBJECT_PARTICLE_MODEL_NONE, NULL);
}

int FEseqobject_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    PartFxSpawnParams effect;
    register GameObject* self = obj;
    int receiver;
    int i;
    GameObject* sender;
    int message;
    void* param;
    int receiverCount;
    int* receivers;
    f32 effectScale;
    f32 effectOrigin;

    receiver = 0;
    i = 0;
    effectOrigin = 0.0f;
    effectScale = 1.0f;
    for (; i < animUpdate->eventCount; i++) {
        effect.posX = effectOrigin;
        effect.posY = effectOrigin;
        effect.posZ = effectOrigin;
        effect.scale = effectScale;
        effect.rotY = 0;
        effect.rotX = 0;
        effect.rotZ = 0;

        switch (animUpdate->eventIds[i]) {
        case FESEQOBJECT_EVENT_SET_GAME_BIT:
            mainSetBits(GAMEBIT_ITEM_Staff_Got, 1);
            break;
        case FESEQOBJECT_EVENT_PARTICLE_VARIANT_0:
            effect.rotZ = 0;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case FESEQOBJECT_EVENT_PARTICLE_VARIANT_1:
            effect.rotZ = 1;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case FESEQOBJECT_EVENT_PARTICLE_VARIANT_2:
            effect.rotZ = 2;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case FESEQOBJECT_EVENT_PARTICLE_VARIANT_3:
            effect.rotZ = 3;
            FEseqobject_spawnEffect(self, &effect);
            break;
        case FESEQOBJECT_EVENT_PARTICLE_VARIANT_4:
            effect.rotZ = 4;
            FEseqobject_spawnEffect(self, &effect);
            break;
        }
    }

    while (ObjMsg_Pop(self, (u32*)&message, &sender, &param) != 0) {
        if ((animUpdate->sequenceControlFlags & OBJSEQ_CONTROL_SUPPRESS_MESSAGES) == 0) {
            switch (message) {
            case FESEQOBJECT_MESSAGE_IN_1:
                receivers = (int*)objGetAllOfType(FESEQOBJECT_RECEIVER_OBJECT_GROUP, &receiverCount);
                for (i = 0; i < receiverCount; i++) {
                    if (((GameObject*)receivers[i])->anim.romDefNo == FESEQOBJECT_RECEIVER_SEQ_ID) {
                        receiver = receivers[i];
                        i = receiverCount;
                    }
                }
                if ((GameObject*)receiver != NULL) {
                    ObjMsg_SendToObject((GameObject*)receiver, FESEQOBJECT_MESSAGE_OUT_1, self, 0);
                }
                break;
            case FESEQOBJECT_MESSAGE_IN_2:
                receivers = (int*)objGetAllOfType(FESEQOBJECT_RECEIVER_OBJECT_GROUP, &receiverCount);
                for (i = 0; i < receiverCount; i++) {
                    if (((GameObject*)receivers[i])->anim.romDefNo == FESEQOBJECT_RECEIVER_SEQ_ID) {
                        receiver = receivers[i];
                        i = receiverCount;
                    }
                }
                if ((GameObject*)receiver != NULL) {
                    ObjMsg_SendToObject((GameObject*)receiver, FESEQOBJECT_MESSAGE_OUT_2, self, 0);
                }
                break;
            case FESEQOBJECT_MESSAGE_IN_3:
                receivers = (int*)objGetAllOfType(FESEQOBJECT_RECEIVER_OBJECT_GROUP, &receiverCount);
                for (i = 0; i < receiverCount; i++) {
                    if (((GameObject*)receivers[i])->anim.romDefNo == FESEQOBJECT_RECEIVER_SEQ_ID) {
                        receiver = receivers[i];
                        i = receiverCount;
                    }
                }
                if ((GameObject*)receiver != NULL) {
                    ObjMsg_SendToObject((GameObject*)receiver, FESEQOBJECT_MESSAGE_OUT_3, self, 0);
                }
                break;
            }
        }
    }
    animUpdate->movementState = 0;
    return 0;
}

int FEseqobject_getExtraSize(void) {
    return sizeof(FEseqobjectState);
}

int FEseqobject_getObjectTypeId(void) {
    return 0;
}

void FEseqobject_free(void) {
}

void FEseqobject_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void FEseqobject_hitDetect(void) {
}

void FEseqobject_update(GameObject* obj) {
    register GameObject* self = obj;

    self->anim.rotX = FESEQOBJECT_SEQUENCE_ROTATION;
    if (mainGetBit(GAMEBIT_ITEM_Staff_Got) == 0) {
        (*gObjectTriggerInterface)->runSequence(FESEQOBJECT_SEQUENCE_INDEX, self, -1);
    }
}

void FEseqobject_init(GameObject* obj) {
    obj->anim.rotX = 0;
    obj->animEventCallback = FEseqobject_SeqFn;
    ObjMsg_AllocQueue(obj, FESEQOBJECT_MESSAGE_QUEUE_CAPACITY);
}

void FEseqobject_release(void) {
}

void FEseqobject_initialise(void) {
}

ObjectDescriptor gFEseqobjectObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FEseqobject_initialise,
    (ObjectDescriptorCallback)FEseqobject_release,
    0,
    (ObjectDescriptorCallback)FEseqobject_init,
    (ObjectDescriptorCallback)FEseqobject_update,
    (ObjectDescriptorCallback)FEseqobject_hitDetect,
    (ObjectDescriptorCallback)FEseqobject_render,
    (ObjectDescriptorCallback)FEseqobject_free,
    (ObjectDescriptorCallback)FEseqobject_getObjectTypeId,
    FEseqobject_getExtraSize,
};
