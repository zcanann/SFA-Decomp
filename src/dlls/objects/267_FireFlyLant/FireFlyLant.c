/* FireFlyLant (DLL 0x10B) - container and release point for lantern fireflies. */
#include "dlls/objects/267_FireFlyLant.h"

#include "dlls/objects/268_LanternFire.h"
#include "main/dll/dll_80136a40.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define FIREFLY_LANTERN_OBJECT_TYPE_ID 8
#define FIREFLY_LANTERN_OBJECT_GROUP   0xF

#define FIREFLY_LANTERN_SEQ_EVENT_RELEASE 1

/* Runtime object ID 1084 resolves through OBJINDEX.bin to retail definition
   0x049B "LanternFire" (DLL 0x10C). */
#define LANTERN_FIRE_OBJECT_ID              1084
#define LANTERN_FIRE_SETUP_SIZE_WORDS       (sizeof(LanternFireFlyPlacement) / sizeof(u32))
#define LANTERN_FIRE_SETUP_LOAD_FLAGS       2
#define LANTERN_FIRE_SETUP_MAP_ACT_FLAGS_HI 4
#define LANTERN_FIRE_SETUP_LOAD_RANGE       0xFF
#define LANTERN_FIRE_SETUP_UNK07            8
#define LANTERN_FIRE_INITIAL_STATE_ID       4
#define LANTERN_FIRE_LIFETIME               0x514
#define LANTERN_FIRE_DRIFT_RANGE_Z          40
#define LANTERN_FIRE_WANDER_RANGE           30

static const f32 sFireFlyLanternSpawnHeightOffset = 2.0f;
static const f32 sFireFlyLanternAnchorHeightOffset = 5.0f;
static const f32 sFireFlyLanternModelScale = 1.0f;

static GameObject* FireFlyLantern_spawnFireFly(GameObject* obj) {
    LanternFireFlyPlacement* setup;

    if (Obj_IsLoadingLocked() == 0) {
        return NULL;
    }
    setup = (LanternFireFlyPlacement*)Obj_AllocObjectSetup(sizeof(LanternFireFlyPlacement), LANTERN_FIRE_OBJECT_ID);
    setup->base.objectId = LANTERN_FIRE_OBJECT_ID;
    setup->base.size = LANTERN_FIRE_SETUP_SIZE_WORDS;
    setup->base.loadFlags = LANTERN_FIRE_SETUP_LOAD_FLAGS;
    setup->base.loadRange = LANTERN_FIRE_SETUP_LOAD_RANGE;
    setup->base.mapActFlagsHi = LANTERN_FIRE_SETUP_MAP_ACT_FLAGS_HI;
    setup->base.unk07 = LANTERN_FIRE_SETUP_UNK07;
    setup->base.posX = obj->anim.localPosX;
    setup->base.posY = sFireFlyLanternSpawnHeightOffset + obj->anim.localPosY;
    setup->base.posZ = obj->anim.localPosZ;
    setup->stateId = LANTERN_FIRE_INITIAL_STATE_ID;
    setup->timer = LANTERN_FIRE_LIFETIME;
    setup->driftRangeZ = LANTERN_FIRE_DRIFT_RANGE_Z;
    setup->wanderRange = LANTERN_FIRE_WANDER_RANGE;
    return loadObjectAtObject(obj, &setup->base);
}

static int FireFlyLantern_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    FireFlyLanternState* state;
    GameObject* child;
    int eventIndex;

    (void)unused;
    state = obj->extra;
    eventIndex = 0;
    while (eventIndex < animUpdate->eventCount) {
        switch (animUpdate->eventIds[eventIndex]) {
        case FIREFLY_LANTERN_SEQ_EVENT_RELEASE:
            if (state->fireflyCount != 0) {
                child = state->fireflies[state->fireflyCount - 1];
                if (child != NULL) {
                    ((LanternFireFlyRuntimeInterface*)*child->anim.dll)->releaseFromLantern(child);
                }
                --state->fireflyCount;
                --state->remainingCount;
                mainSetBits(state->countGameBit, state->remainingCount);
            }
            break;
        }
        eventIndex++;
    }

    state->flags.sequenceFinished = TRUE;
    eventIndex = 0;
    while (eventIndex < state->fireflyCount) {
        child = state->fireflies[eventIndex];
        ((LanternFireFlyRuntimeInterface*)*child->anim.dll)
            ->setAnchor(child, obj->anim.localPosX, sFireFlyLanternAnchorHeightOffset + obj->anim.localPosY,
                        obj->anim.localPosZ);
        eventIndex++;
    }

    return 0;
}

int FireFlyLantern_getExtraSize(void) {
    return sizeof(FireFlyLanternState);
}

int FireFlyLantern_getObjectTypeId(void) {
    return FIREFLY_LANTERN_OBJECT_TYPE_ID;
}

void FireFlyLantern_free(GameObject* obj) {
    GameObject* tricky = getTrickyObject();

    if (tricky != NULL) {
        trickyImpress(tricky);
    }
    objFreeObjectType(obj, FIREFLY_LANTERN_OBJECT_GROUP);
}

void FireFlyLantern_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                           s8 visible) {
    (void)visible;
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, sFireFlyLanternModelScale);
}

void FireFlyLantern_update(GameObject* obj) {
    GameObject** childSlot;
    FireFlyLanternState* state;
    FireFlyLanternPlacement* placement;
    GameObject* child;
    int childIndex;
    int shouldFree;

    state = obj->extra;
    placement = (FireFlyLanternPlacement*)obj->anim.placementData;
    shouldFree = 0;

    if (placement->mode == FIREFLY_LANTERN_MODE_SINGLE) {
        if (state->fireflyCount != 0) {
            child = state->fireflies[0];
            if (child != NULL) {
                ((LanternFireFlyRuntimeInterface*)*child->anim.dll)->releaseFromLantern(child);
            }
            gameBitDecrement(state->countGameBit);
        }
        shouldFree = 1;
    } else if (state->flags.sequenceFinished != 0) {
        childIndex = 0;
        childSlot = state->fireflies;
        while (childIndex < state->fireflyCount) {
            Obj_FreeObject(*childSlot);
            childSlot++;
            childIndex++;
        }
        shouldFree = 1;
    }

    if (shouldFree != 0) {
        Obj_FreeObject(obj);
    }
}

void FireFlyLantern_init(GameObject* obj, FireFlyLanternPlacement* placement) {
    GameObject* player;
    GameObject** childSlot;
    FireFlyLanternState* state;
    int childIndex;

    state = obj->extra;
    obj->animEventCallback = FireFlyLantern_SeqFn;
    player = Obj_GetPlayerObject();
    if (player->anim.romDefNo != 0) {
        state->countGameBit = GAMEBIT_ITEM_Firefly_Count;
    } else {
        state->countGameBit = GAMEBIT_ITEM_FireflyNotShown_Count;
    }

    state->fireflyCount = 0;
    state->remainingCount = mainGetBit(state->countGameBit);

    if (placement->mode == FIREFLY_LANTERN_MODE_SINGLE) {
        if (state->remainingCount != 0) {
            state->fireflyCount = 1;
            state->fireflies[0] = FireFlyLantern_spawnFireFly(obj);
        }
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    } else {
        state->fireflyCount = (state->remainingCount < FIREFLY_LANTERN_CHILD_CAPACITY) ? state->remainingCount
                                                                                       : FIREFLY_LANTERN_CHILD_CAPACITY;

        childIndex = 0;
        childSlot = state->fireflies;
        while (childIndex < state->fireflyCount) {
            *childSlot = FireFlyLantern_spawnFireFly(obj);
            childSlot++;
            childIndex++;
        }
    }
}

ObjectDescriptor gFireFlyLanternObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)FireFlyLantern_init,
    (ObjectDescriptorCallback)FireFlyLantern_update,
    0,
    (ObjectDescriptorCallback)FireFlyLantern_render,
    (ObjectDescriptorCallback)FireFlyLantern_free,
    (ObjectDescriptorCallback)FireFlyLantern_getObjectTypeId,
    FireFlyLantern_getExtraSize,
};
