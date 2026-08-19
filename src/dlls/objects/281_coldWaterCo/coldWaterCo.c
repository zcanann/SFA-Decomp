#include "dlls/objects/281_coldWaterCo.h"

#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "sys/objects.h"

#define COLD_WATER_HIT_PRIORITY  0x1C
#define COLD_WATER_TIMER_INITIAL -30.0f
#define COLD_WATER_DAMAGE_PERIOD 240.0f

int ColdWaterControl_getExtraSize(void) {
    return sizeof(ColdWaterControlState);
}

void ColdWaterControl_update(GameObject* obj) {
    ColdWaterControlState* state = obj->extra;
    if (mainGetBit(GAMEBIT_IM_TriggerSlippy) != 0 && mainGetBit(GAMEBIT_IM_SlippyWarnedCold) == 0) {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        mainSetBits(GAMEBIT_IM_SlippyWarnedCold, 1);
        return;
    }

    if (state->cachedPlayer != NULL) {
        if (playerIsInWater(state->cachedPlayer) != 0) {
            if (COLD_WATER_TIMER_INITIAL == state->damageTimer) {
                ObjHits_RecordObjectHit(state->cachedPlayer, obj, COLD_WATER_HIT_PRIORITY, 0, 1);
            }

            state->damageTimer += timeDelta;
            if (state->damageTimer > COLD_WATER_DAMAGE_PERIOD) {
                ObjHits_RecordObjectHit(state->cachedPlayer, obj, COLD_WATER_HIT_PRIORITY, 1, 1);
                state->damageTimer -= COLD_WATER_DAMAGE_PERIOD;
            }
        } else {
            state->damageTimer = COLD_WATER_TIMER_INITIAL;
        }
    } else {
        state->cachedPlayer = Obj_GetPlayerObject();
    }
}

void ColdWaterControl_init(GameObject* obj) {
    ColdWaterControlState* state = obj->extra;
    state->damageTimer = COLD_WATER_TIMER_INITIAL;
    obj->objectFlags |= OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

ObjectDescriptor gColdWaterControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ColdWaterControl_init,
    (ObjectDescriptorCallback)ColdWaterControl_update,
    0,
    0,
    0,
    0,
    ColdWaterControl_getExtraSize,
};
