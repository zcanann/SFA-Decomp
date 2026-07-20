/* DLL 0x1D0 - DIM Tricky companion object.
 * A simple 1-byte state machine (states 0-3) that watches game bit 0xA1B to
 * trigger a Tricky companion-pickup sequence: clears bits 0x4E4/0x4E5, then
 * dispatches a vtable call (slot 14 of Tricky's object type at offset
 * 0x68+0x38) to link the companion. */
#include "main/object.h"
#include "main/gamebit_ids.h"
#include "main/object_descriptor.h"
#include "main/object_render.h"
#include "main/game_object.h"
#include "main/gamebits.h"

enum
{
    DIMTRICKY_STATE_WAIT_TRIGGER = 0,
    DIMTRICKY_STATE_HAND_CONTROL = 1,
    DIMTRICKY_STATE_LINK_COMPANION = 2,
    DIMTRICKY_STATE_DONE = 3,
};

#define DIMTRICKY_TRIGGER_GAMEBIT 0xA1B

typedef struct DimTrickyState
{
    u8 phase;
} DimTrickyState;

typedef struct DimTrickyInterfaceVTable
{
    void* pad00[14];
    void (*linkCompanion)(GameObject* tricky, GameObject* controller);
} DimTrickyInterfaceVTable;

STATIC_ASSERT(sizeof(DimTrickyState) == 0x1);
STATIC_ASSERT(offsetof(DimTrickyInterfaceVTable, linkCompanion) == 0x38);

int dim_tricky_getExtraSize(void) { return sizeof(DimTrickyState); }
int dim_tricky_getObjectTypeId(void) { return 0x0; }

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
    if (trickyObj == NULL) return;
    switch (state->phase)
    {
    case DIMTRICKY_STATE_WAIT_TRIGGER:
        if (mainGetBit(DIMTRICKY_TRIGGER_GAMEBIT) != 0)
        {
            mainSetBits(GAMEBIT_Tricky_Usable, 0);
            mainSetBits(GAMEBIT_IM_DoneRace, 0);
            state->phase = DIMTRICKY_STATE_HAND_CONTROL;
        }
        break;
    case DIMTRICKY_STATE_HAND_CONTROL:
        state->phase = DIMTRICKY_STATE_LINK_COMPANION;
        break;
    case DIMTRICKY_STATE_LINK_COMPANION:
        (*(DimTrickyInterfaceVTable**)trickyObj->anim.dll)->linkCompanion(trickyObj, obj);
        state->phase = DIMTRICKY_STATE_DONE;
        break;
    case DIMTRICKY_STATE_DONE:
        break;
    }
}

void dim_tricky_init(GameObject* obj)
{
    u8 v = DIMTRICKY_STATE_WAIT_TRIGGER;
    DimTrickyState* state = obj->extra;
    state->phase = v;
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
    (ObjectDescriptorExtraSizeCallback)dim_tricky_getExtraSize,
};
