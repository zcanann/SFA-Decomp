/*
 * PortalSpell (DLL 0x10D, descriptor gPortalSpellDoorObjDescriptor).
 */
#include "dlls/objects/269_PortalSpell.h"

#include "main/dll/dll_80136a40.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define PORTAL_SPELL_INDEX_OPEN_PORTAL      3
#define PORTAL_SPELL_DOOR_OPEN_SEQUENCE     0
#define PORTAL_SPELL_DOOR_TIMER_INACTIVE    -1
#define PORTAL_SPELL_DOOR_ROTATION_SHIFT    8
#define PORTAL_SPELL_DOOR_CANCEL_ANY_SPELL  -1
#define PORTAL_SPELL_DOOR_SEQUENCE_ARG_NONE -1

const f32 gPortalSpellDoorModelScale[] = {1.0f};
const f32 gPortalSpellDoorRootMotionScale[] = {3.1499999f};
const f32 gPortalSpellDoorOpenAmountScale[] = {0.5f};

#define PORTAL_SPELL_DOOR_MODEL_SCALE       (gPortalSpellDoorModelScale[0])
#define PORTAL_SPELL_DOOR_ROOT_MOTION_SCALE (gPortalSpellDoorRootMotionScale[0])
#define PORTAL_SPELL_DOOR_OPEN_AMOUNT_SCALE (gPortalSpellDoorOpenAmountScale[0])

int PortalSpellDoor_getExtraSize(void) {
    return sizeof(PortalSpellDoorState);
}

int PortalSpellDoor_getObjectTypeId(void) {
    return 0;
}

void PortalSpellDoor_free(GameObject* obj) {
    (void)obj;
}

void PortalSpellDoor_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    s32 visibleValue = visible;
    if (visibleValue != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, PORTAL_SPELL_DOOR_MODEL_SCALE);
    }
}

void PortalSpellDoor_hitDetect(void) {
}

void PortalSpellDoor_update(GameObject* obj) {
    PortalSpellDoorState* state;
    GameObject* player;
    PortalSpellDoorPlacement* placement;
    int nextTimer;

    player = Obj_GetPlayerObject();
    state = obj->extra;
    placement = (PortalSpellDoorPlacement*)obj->anim.placementData;
    if (playerHasSpell(player, PORTAL_SPELL_INDEX_OPEN_PORTAL) != 0) {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    if (state->flags.open) {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        if (objGetAnimState80A(player) == GAMEBIT_STAFF_ABILITY_OPEN_PORTAL) {
            playerCancelSpell(player, PORTAL_SPELL_DOOR_CANCEL_ANY_SPELL);
        }
        mainSetBits(placement->openedGameBit, TRUE);
    } else if (objGetAnimState80A(player) == GAMEBIT_STAFF_ABILITY_OPEN_PORTAL &&
               state->openTimer == PORTAL_SPELL_DOOR_TIMER_INACTIVE) {
        state->openTimer = 0;
    }
    if (state->openTimer != PORTAL_SPELL_DOOR_TIMER_INACTIVE) {
        nextTimer = state->openTimer - framesThisStep;
        state->openTimer = nextTimer;
        if (nextTimer < 0) {
            GameObject* tricky;

            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            (*gObjectTriggerInterface)
                ->runSequence(PORTAL_SPELL_DOOR_OPEN_SEQUENCE, (void*)obj, PORTAL_SPELL_DOOR_SEQUENCE_ARG_NONE);
            tricky = getTrickyObject();
            if (tricky != NULL) {
                trickyImpress(tricky);
            }
            state->flags.open = TRUE;
            state->openTimer = PORTAL_SPELL_DOOR_TIMER_INACTIVE;
        }
    }
}

void PortalSpellDoor_init(GameObject* obj, PortalSpellDoorPlacement* placement) {
    PortalSpellDoorState* state = obj->extra;
    f32 scaledHitbox;

    obj->anim.rotX = (s16)((s32)placement->rotXByte << PORTAL_SPELL_DOOR_ROTATION_SHIFT);
    obj->anim.rotY = (s16)((s32)placement->rotY << PORTAL_SPELL_DOOR_ROTATION_SHIFT);
    obj->anim.rootMotionScale = PORTAL_SPELL_DOOR_ROOT_MOTION_SCALE;
    scaledHitbox = obj->anim.hitboxScale * obj->anim.rootMotionScale;
    state->openAmount = scaledHitbox * PORTAL_SPELL_DOOR_OPEN_AMOUNT_SCALE;
    if (mainGetBit(placement->openedGameBit) != 0) {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED | OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
    }
    state->openTimer = PORTAL_SPELL_DOOR_TIMER_INACTIVE;
}

void PortalSpellDoor_release(void) {
}

void PortalSpellDoor_initialise(void) {
}

ObjectDescriptor gPortalSpellDoorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)PortalSpellDoor_initialise,
    (ObjectDescriptorCallback)PortalSpellDoor_release,
    0,
    (ObjectDescriptorCallback)PortalSpellDoor_init,
    (ObjectDescriptorCallback)PortalSpellDoor_update,
    (ObjectDescriptorCallback)PortalSpellDoor_hitDetect,
    (ObjectDescriptorCallback)PortalSpellDoor_render,
    (ObjectDescriptorCallback)PortalSpellDoor_free,
    (ObjectDescriptorCallback)PortalSpellDoor_getObjectTypeId,
    PortalSpellDoor_getExtraSize,
};
