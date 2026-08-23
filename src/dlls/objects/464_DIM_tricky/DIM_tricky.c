/*
 * DIM_tricky (DLL 0x1D0) - DIM Tricky companion object.
 * A simple 1-byte state machine (states 0-3) that watches game bit 0xA1B to
 * trigger a Tricky companion-pickup sequence: clears the sidekick command and
 * warp-enabled bits, then
 * asks Tricky to move to this object through his export table.
 */
#include "sys/objects/lifecycle.h"
#include "dlls/object_descriptor.h"
#include "main/object_render.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/dll_01D0_dimtricky.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"

enum
{
    DIMTRICKY_STATE_WAIT_TRIGGER = 0,
    DIMTRICKY_STATE_HAND_CONTROL = 1,
    DIMTRICKY_STATE_MOVE_TO_OBJECT = 2,
    DIMTRICKY_STATE_DONE = 3,
};

#define DIMTRICKY_TRIGGER_GAMEBIT 0xA1B

typedef struct DimTrickyState
{
    u8 phase;
} DimTrickyState;

STATIC_ASSERT(sizeof(DimTrickyState) == 0x1);

int dim_tricky_getExtraSize(void)
{
    return sizeof(DimTrickyState);
}

int dim_tricky_getObjectTypeId(void)
{
    return 0x0;
}

void dim_tricky_free(void)
{
}

void dim_tricky_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dim_tricky_hitDetect(void)
{
}

void dim_tricky_update(GameObject* obj)
{
    DimTrickyState* state = obj->extra;
    GameObject* trickyObj = getTrickyObject();
    if (trickyObj == NULL)
    {
        return;
    }
    switch (state->phase)
    {
    case DIMTRICKY_STATE_WAIT_TRIGGER:
        if (mainGetBit(DIMTRICKY_TRIGGER_GAMEBIT) != 0)
        {
            mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 0);
            mainSetBits(GAMEBIT_Tricky_Spawns, 0);
            state->phase = DIMTRICKY_STATE_HAND_CONTROL;
        }
        break;
    case DIMTRICKY_STATE_HAND_CONTROL:
        state->phase = DIMTRICKY_STATE_MOVE_TO_OBJECT;
        break;
    case DIMTRICKY_STATE_MOVE_TO_OBJECT:
        TRICKY_INTERFACE(trickyObj)->requestMoveToObject(trickyObj, obj);
        state->phase = DIMTRICKY_STATE_DONE;
        break;
    case DIMTRICKY_STATE_DONE:
        break;
    }
}

void dim_tricky_init(GameObject* obj) {
    DimTrickyState* state = obj->extra;
    state->phase = DIMTRICKY_STATE_WAIT_TRIGGER;
}

ObjectDescriptor gDIM_trickyObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim_tricky_init,
    (ObjectDescriptorCallback)dim_tricky_update,
    (ObjectDescriptorCallback)dim_tricky_hitDetect,
    (ObjectDescriptorCallback)dim_tricky_render,
    (ObjectDescriptorCallback)dim_tricky_free,
    (ObjectDescriptorCallback)dim_tricky_getObjectTypeId,
    dim_tricky_getExtraSize,
};
