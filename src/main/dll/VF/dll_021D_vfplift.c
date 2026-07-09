/*
 * vfplift (DLL 0x21D, VFPLift / VFPLift1 / VFPLift2 / VFPLift3) - the
 * rising/lowering platform lifts in the Volcano Force Point Temple.
 *
 * Three lift variants share this code, dispatched by seq id in
 * VFPLift_update:
 *  - lift 1 (0x3B7): gated behind four "gate" game bits (or map-event
 *    act 2); once all are set it plays its ready trigger, then toggles
 *    raised/lowered on interaction;
 *  - lifts 2/3 (0x3BF / 0x53F): a plain interact-to-toggle platform,
 *    each variant using its own raised height offset.
 * Interacting with a lift disables the A-button prompt, runs the
 * raise/lower trigger sequence, plays the move sfx, and writes the
 * toggle game bit. hitDetect enables/disables the object's hit volume
 * from the hit-disable game bit.
 */
#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/dll/VF/dll_021D_vfplift.h"

#define VFPLIFT1_OBJTYPE             0x3b7
#define VFPLIFT2_OBJTYPE             0x3bf
#define VFPLIFT3_OBJTYPE             0x53f
#define VFPLIFT1_READY_GAMEBIT       0x4ee
#define VFPLIFT1_GATE_GAMEBIT_0      0x507
#define VFPLIFT1_GATE_GAMEBIT_1      0x508
#define VFPLIFT1_GATE_GAMEBIT_2      0x509
#define VFPLIFT1_GATE_GAMEBIT_3      0x50a
#define VFPLIFT_TRIGGER_RAISE        0
#define VFPLIFT_TRIGGER_LOWER        1
#define VFPLIFT1_TRIGGER_READY       4
#define VFPLIFT_INTERACT_BUTTON_MASK 0x100
#define VFPLIFT_SFX_MOVE             0x113
#define VFPLIFT_SFX_CHANNEL_MOVE     8
#define VFPLIFT_STATE_IDLE           0
#define VFPLIFT_STATE_LOWERED        3
#define VFPLIFT_STATE_RAISED         4

extern void buttonDisable(int port, u32 mask);

static const f32 gVfpLift1RaisedHeight = 307.0f;

static inline VfpLiftState* vfplift_getState(GameObject* obj)
{
    return obj->extra;
}

static inline f32 vfplift_getModelY(GameObject* obj)
{
    VfpLiftPlacement* setup = *(VfpLiftPlacement**)&obj->anim.placementData;

    return setup->base.posY;
}

static inline void vfplift_trigger(int triggerId, int obj)
{
    (*gObjectTriggerInterface)->runSequence(triggerId, (void*)obj, -1);
}

static inline void vfplift_setObjectHitEnabled(GameObject* obj)
{
    *(u8*)&obj->anim.resetHitboxMode = (*(u8*)&obj->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
}

static inline f32 vfplift23_getRaisedOffset(int objType)
{
    f32 offset;

    offset = 0.0f;
    if (objType == VFPLIFT3_OBJTYPE)
    {
        offset = 310.0f;
    }
    else if (objType == VFPLIFT2_OBJTYPE)
    {
        offset = 372.5f;
    }
    return offset;
}

int VFPLift_SeqFn(int obj)
{
    vfplift_getState((GameObject*)(obj))->forceRaised = 1;
    return 0;
}

void vfplift23_updateState(int obj)
{
    VfpLiftPlacement* setup;
    VfpLiftState* state;
    f32 raisedOffset;

    setup = (VfpLiftPlacement*)((GameObject*)obj)->anim.placementData;
    state = (VfpLiftState*)((GameObject*)obj)->extra;
    raisedOffset = 0.0f;
    if (((GameObject*)obj)->anim.seqId == VFPLIFT3_OBJTYPE)
    {
        raisedOffset = 310.0f;
    }
    else if (((GameObject*)obj)->anim.seqId == VFPLIFT2_OBJTYPE)
    {
        raisedOffset = 372.5f;
    }
    if (state->applyHeight != 0)
    {
        ((GameObject*)obj)->anim.localPosY = setup->base.posY + raisedOffset;
        state->applyHeight = 0;
    }
    if (state->mode == VFPLIFT_STATE_RAISED || state->mode >= VFPLIFT_STATE_RAISED ||
        state->mode < VFPLIFT_STATE_LOWERED)
    {
        vfplift_setObjectHitEnabled((GameObject*)(obj));
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            buttonDisable(0, VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_LOWER, obj);
            state->mode = VFPLIFT_STATE_LOWERED;
            Sfx_PlayFromObject(obj, VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj, VFPLIFT_SFX_CHANNEL_MOVE);
            mainSetBits(state->toggleGameBit, 0);
        }
        else
        {
            if ((u32)mainGetBit(state->toggleGameBit) == 0)
            {
                state->mode = VFPLIFT_STATE_LOWERED;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY;
            }
        }
    }
    else
    {
        vfplift_setObjectHitEnabled((GameObject*)(obj));
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            buttonDisable(0, VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_RAISE, obj);
            state->mode = VFPLIFT_STATE_RAISED;
            Sfx_PlayFromObject(obj, VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj, VFPLIFT_SFX_CHANNEL_MOVE);
            mainSetBits(state->toggleGameBit, 1);
        }
        else
        {
            if ((u32)mainGetBit(state->toggleGameBit) != 0)
            {
                state->mode = VFPLIFT_STATE_RAISED;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY + raisedOffset;
            }
        }
    }
}

void vfplift1_updateState(int obj)
{
    VfpLiftPlacement* setup;
    VfpLiftState* state;
    void* player;
    s16 gate[4];

    setup = (VfpLiftPlacement*)((GameObject*)obj)->anim.placementData;
    state = (VfpLiftState*)((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    if (player == NULL)
    {
        return;
    }

    gate[0] = mainGetBit(VFPLIFT1_GATE_GAMEBIT_0);
    gate[1] = mainGetBit(VFPLIFT1_GATE_GAMEBIT_1);
    gate[2] = mainGetBit(VFPLIFT1_GATE_GAMEBIT_2);
    gate[3] = mainGetBit(VFPLIFT1_GATE_GAMEBIT_3);
    if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 2)
    {
        gate[0] = 1;
        gate[1] = gate[0];
        gate[2] = gate[0];
        gate[3] = gate[0];
    }
    if (gate[0] != 0 && gate[1] != 0 && gate[2] != 0 && gate[3] != 0 && state->mode == VFPLIFT_STATE_IDLE &&
        mainGetBit(VFPLIFT1_READY_GAMEBIT) == 0)
    {
        vfplift_trigger(VFPLIFT1_TRIGGER_READY, obj);
        mainSetBits(VFPLIFT1_READY_GAMEBIT, 1);
    }
    if (state->applyHeight != 0 || (state->forceRaised != 0 && state->mode == VFPLIFT_STATE_IDLE))
    {
        ((GameObject*)obj)->anim.localPosY = setup->base.posY + *(f32*)&gVfpLift1RaisedHeight;
        state->applyHeight = 0;
        state->forceRaised = 0;
        state->mode = VFPLIFT_STATE_RAISED;
    }
    if (state->mode == VFPLIFT_STATE_IDLE)
    {
        return;
    }
    if (state->mode == VFPLIFT_STATE_RAISED || state->mode >= VFPLIFT_STATE_RAISED ||
        state->mode < VFPLIFT_STATE_LOWERED)
    {
        vfplift_setObjectHitEnabled((GameObject*)(obj));
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            buttonDisable(0, VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_LOWER, obj);
            state->mode = VFPLIFT_STATE_LOWERED;
            Sfx_PlayFromObject(obj, VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj, VFPLIFT_SFX_CHANNEL_MOVE);
            mainSetBits(state->toggleGameBit, 1);
        }
        else
        {
            if ((u32)mainGetBit(state->toggleGameBit) != 0)
            {
                state->mode = VFPLIFT_STATE_LOWERED;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY;
            }
        }
    }
    else
    {
        vfplift_setObjectHitEnabled((GameObject*)(obj));
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            buttonDisable(0, VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_RAISE, obj);
            state->mode = VFPLIFT_STATE_RAISED;
            Sfx_PlayFromObject(obj, VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj, VFPLIFT_SFX_CHANNEL_MOVE);
            mainSetBits(state->toggleGameBit, 0);
        }
        else
        {
            if ((u32)mainGetBit(state->toggleGameBit) == 0)
            {
                state->mode = VFPLIFT_STATE_RAISED;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY + *(f32*)&gVfpLift1RaisedHeight;
            }
        }
    }
}

int VFPLift_getExtraSize(void)
{
    return 0x20;
}

int VFPLift_getObjectTypeId(void)
{
    return 0x0;
}

void VFPLift_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void VFPLift_render(int obj, int p2, int p3, int p4, int p5, s8 vis)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void VFPLift_hitDetect(int obj)
{
    VfpLiftState* state = vfplift_getState((GameObject*)(obj));

    if (state->hitDisableGameBit != -1 && mainGetBit(state->hitDisableGameBit) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_DISABLED) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode ^= INTERACT_FLAG_DISABLED;
    }
}

void VFPLift_update(int obj)
{
    int seqId;
    Obj_GetPlayerObject();
    seqId = ((GameObject*)obj)->anim.seqId;
    if (seqId == VFPLIFT1_OBJTYPE)
    {
        vfplift1_updateState(obj);
    }
    else if (seqId == VFPLIFT2_OBJTYPE)
    {
        vfplift23_updateState(obj);
    }
    else if (seqId == VFPLIFT3_OBJTYPE)
    {
        vfplift23_updateState(obj);
    }
}

void VFPLift_init(int* obj, VfpLiftPlacement* init)
{
    VfpLiftState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = VFPLift_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(init->rotXByte << 8);
    state->mode = VFPLIFT_STATE_IDLE;
    state->hitDisableGameBit = init->hitDisableGameBit;
    state->toggleGameBit = init->toggleGameBit;
    state->travelDistance = (f32)(s32)init->travelDistance;
    state->mapEventNo = init->mapEventNo;
    state->anim[0] = 0;
    state->anim[1] = 0;
    state->anim[2] = 0;
    state->anim[3] = 0;
    if (((GameObject*)obj)->anim.seqId == VFPLIFT2_OBJTYPE)
    {
        if ((u32)mainGetBit(state->toggleGameBit) != 0)
        {
            state->mode = VFPLIFT_STATE_RAISED;
            state->applyHeight = 1;
        }
        else
        {
            state->mode = VFPLIFT_STATE_LOWERED;
        }
    }
    if (((GameObject*)obj)->anim.seqId == VFPLIFT1_OBJTYPE && mainGetBit(VFPLIFT1_READY_GAMEBIT) != 0)
    {
        if ((u32)mainGetBit(state->toggleGameBit) != 0)
        {
            state->mode = VFPLIFT_STATE_LOWERED;
        }
        else
        {
            state->mode = VFPLIFT_STATE_RAISED;
            state->applyHeight = 1;
        }
    }
}

void VFPLift_release(void)
{
}

void VFPLift_initialise(void)
{
}
