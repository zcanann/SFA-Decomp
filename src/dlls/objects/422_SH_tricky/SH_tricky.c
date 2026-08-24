/*
 * SH_tricky (DLL 0x1A6) - SnowHorn-area Tricky controller.
 *
 * Its one-byte state waits for the area's trigger bit, temporarily disables
 * Tricky commands and warping, then asks Tricky to move to this hidden object.
 * The command bits are restored after Tricky returns to the EarthWalker Queen.
 */
#include "dlls/objects/422_SH_tricky.h"

#include "main/dll/dll_00C4_tricky.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "sys/objects/lifecycle.h"

#define SH_TRICKY_TRIGGER_GAMEBIT 0x94

int shTricky_getExtraSize(void) {
    return sizeof(ShTrickyState);
}

void shTricky_update(GameObject* obj) {
    ShTrickyState* state = obj->extra;
    GameObject* tricky = getTrickyObject();
    if (tricky == NULL) {
        return;
    }

    switch (state->phase) {
    case SH_TRICKY_PHASE_WAIT_TRIGGER:
        if (mainGetBit(SH_TRICKY_TRIGGER_GAMEBIT) != 0) {
            mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 0);
            mainSetBits(GAMEBIT_Tricky_Spawns, 0);
            mainSetBits(GAMEBIT_MaybeHaveTricky, 1);
            state->phase = SH_TRICKY_PHASE_REQUEST_DELAY;
        }
        break;
    case SH_TRICKY_PHASE_REQUEST_DELAY:
        state->phase = SH_TRICKY_PHASE_REQUEST_MOVE;
        break;
    case SH_TRICKY_PHASE_REQUEST_MOVE:
        if (TRICKY_INTERFACE(tricky)->requestMoveToObject(tricky, obj) != 0) {
            state->phase = SH_TRICKY_PHASE_WAIT_RETURN_TO_QUEEN;
        }
        break;
    case SH_TRICKY_PHASE_WAIT_RETURN_TO_QUEEN:
        if (mainGetBit(GAMEBIT_SH_ReturnedToQueen) != 0) {
            mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 1);
            mainSetBits(GAMEBIT_Tricky_Spawns, 1);
            mainSetBits(GAMEBIT_MaybeHaveTricky, 0);
        }
        break;
    case SH_TRICKY_PHASE_COMPLETE:
        break;
    }
}

void shTricky_init(GameObject* obj) {
    ShTrickyState* state = obj->extra;
    if (mainGetBit(GAMEBIT_SH_ReturnedToQueen) != 0) {
        state->phase = SH_TRICKY_PHASE_COMPLETE;
    } else {
        state->phase = SH_TRICKY_PHASE_WAIT_TRIGGER;
    }

    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

ObjectDescriptor gSHTrickyObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)shTricky_init,
    (ObjectDescriptorCallback)shTricky_update,
    0,
    0,
    0,
    0,
    shTricky_getExtraSize,
};
