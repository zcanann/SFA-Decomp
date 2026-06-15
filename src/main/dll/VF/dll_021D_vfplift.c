#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

#define VFPLIFT1_OBJTYPE 0x3b7
#define VFPLIFT2_OBJTYPE 0x3bf
#define VFPLIFT3_OBJTYPE 0x53f
#define VFPLIFT1_READY_GAMEBIT 0x4ee
#define VFPLIFT1_GATE_GAMEBIT_0 0x507
#define VFPLIFT1_GATE_GAMEBIT_1 0x508
#define VFPLIFT1_GATE_GAMEBIT_2 0x509
#define VFPLIFT1_GATE_GAMEBIT_3 0x50a
#define VFPLIFT_TRIGGER_RAISE 0
#define VFPLIFT_TRIGGER_LOWER 1
#define VFPLIFT1_TRIGGER_READY 4
#define VFPLIFT_INTERACT_BUTTON_MASK 0x100
#define VFPLIFT_SFX_MOVE 0x113
#define VFPLIFT_SFX_CHANNEL_MOVE 8
#define VFPLIFT_STATE_IDLE 0
#define VFPLIFT_STATE_LOWERED 3
#define VFPLIFT_STATE_RAISED 4
#define VFPLIFT_OBJ_FLAG_NO_HIT 0x08
#define VFPLIFT_OBJ_FLAG_INTERACT 0x01

typedef struct VFPLiftState
{
    f32 travelDistance;
    u8 pad04[0x0a - 0x04];
    s16 mode;
    s16 hitDisableGameBit;
    s16 toggleGameBit;
    u8 pad10[0x1a - 0x10];
    u8 mapEventNo;
    u8 pad1b;
    u8 applyHeight : 1;
    u8 forceRaised : 1;
    u8 flagsPad : 6;
} VFPLiftState;

typedef struct VFPLiftPlacement
{
    ObjPlacement base;
    s8 yawByte;
    u8 pad19;
    s16 travelDistance;
    s16 mapEventNo;
    s16 toggleGameBit;
    s16 hitDisableGameBit;
} VFPLiftPlacement;

STATIC_ASSERT(sizeof(VFPLiftState) == 0x20);
STATIC_ASSERT(offsetof(VFPLiftState, travelDistance) == 0x00);
STATIC_ASSERT(offsetof(VFPLiftState, mode) == 0x0A);
STATIC_ASSERT(offsetof(VFPLiftState, hitDisableGameBit) == 0x0C);
STATIC_ASSERT(offsetof(VFPLiftState, toggleGameBit) == 0x0E);
STATIC_ASSERT(offsetof(VFPLiftState, mapEventNo) == 0x1A);
STATIC_ASSERT(sizeof(VFPLiftPlacement) == 0x24);
STATIC_ASSERT(offsetof(VFPLiftPlacement, yawByte) == 0x18);
STATIC_ASSERT(offsetof(VFPLiftPlacement, travelDistance) == 0x1A);
STATIC_ASSERT(offsetof(VFPLiftPlacement, mapEventNo) == 0x1C);
STATIC_ASSERT(offsetof(VFPLiftPlacement, toggleGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VFPLiftPlacement, hitDisableGameBit) == 0x20);

extern void buttonDisable(int index, u32 flags);
extern f32 lbl_803E60E0;
extern f32 lbl_803E60E4;
extern f32 lbl_803E60E8;
extern f32 lbl_803E60EC;

static inline VFPLiftState* vfplift_getState(int obj)
{
    return ((GameObject*)obj)->extra;
}

static inline f32 vfplift_getModelY(int obj)
{
    VFPLiftPlacement* setup = *(VFPLiftPlacement**)&((GameObject*)obj)->anim.placementData;

    return setup->base.posY;
}

static inline void vfplift_trigger(int triggerId, int obj)
{
    (*gObjectTriggerInterface)->runSequence(triggerId, (void*)obj, -1);
}

static inline void vfplift_setObjectHitDisabled(int obj)
{
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~
        VFPLIFT_OBJ_FLAG_NO_HIT);
}

static inline f32 vfplift23_getRaisedOffset(int objType)
{
    f32 offset;

    offset = lbl_803E60E0;
    if (objType == VFPLIFT3_OBJTYPE)
    {
        offset = lbl_803E60E4;
    }
    else if (objType == VFPLIFT2_OBJTYPE)
    {
        offset = lbl_803E60E8;
    }
    return offset;
}

void vfplift23_updateState(int obj)
{
    VFPLiftPlacement* setup;
    VFPLiftState* state;
    f32 raisedOffset;

    setup = *(VFPLiftPlacement**)&((GameObject*)obj)->anim.placementData;
    state = vfplift_getState(obj);
    raisedOffset = vfplift23_getRaisedOffset(((GameObject*)obj)->anim.seqId);
    if (state->applyHeight != 0)
    {
        ((GameObject*)obj)->anim.localPosY = setup->base.posY + raisedOffset;
        state->applyHeight = 0;
    }
    if (state->mode == VFPLIFT_STATE_RAISED || state->mode > VFPLIFT_STATE_RAISED || state->mode < VFPLIFT_STATE_LOWERED)
    {
        vfplift_setObjectHitDisabled(obj);
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & VFPLIFT_OBJ_FLAG_INTERACT) != 0)
        {
            buttonDisable(0,VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_LOWER, obj);
            state->mode = VFPLIFT_STATE_LOWERED;
            Sfx_PlayFromObject(obj,VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj,VFPLIFT_SFX_CHANNEL_MOVE);
            GameBit_Set(state->toggleGameBit, 0);
        }
        else
        {
            if ((u32)GameBit_Get(state->toggleGameBit) == 0)
            {
                state->mode = VFPLIFT_STATE_LOWERED;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY;
            }
        }
    }
    else
    {
        vfplift_setObjectHitDisabled(obj);
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & VFPLIFT_OBJ_FLAG_INTERACT) != 0)
        {
            buttonDisable(0,VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_RAISE, obj);
            state->mode = VFPLIFT_STATE_RAISED;
            Sfx_PlayFromObject(obj,VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj,VFPLIFT_SFX_CHANNEL_MOVE);
            GameBit_Set(state->toggleGameBit, 1);
        }
        else
        {
            if ((u32)GameBit_Get(state->toggleGameBit) != 0)
            {
                state->mode = VFPLIFT_STATE_RAISED;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY + raisedOffset;
            }
        }
    }
}

void vfplift1_updateState(int obj)
{
    VFPLiftState* state;
    VFPLiftPlacement* setup;
    void* player;
    s16 gate0;
    s16 gate1;
    s16 gate2;
    s16 gate3;

    state = vfplift_getState(obj);
    setup = *(VFPLiftPlacement**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= VFPLIFT_OBJ_FLAG_NO_HIT;
    if (player == NULL)
    {
        return;
    }

    gate0 = GameBit_Get(VFPLIFT1_GATE_GAMEBIT_0);
    gate1 = GameBit_Get(VFPLIFT1_GATE_GAMEBIT_1);
    gate2 = GameBit_Get(VFPLIFT1_GATE_GAMEBIT_2);
    gate3 = GameBit_Get(VFPLIFT1_GATE_GAMEBIT_3);
    if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 2)
    {
        gate0 = 1;
        gate3 = gate2 = gate1 = gate0;
    }
    if (gate0 != 0 && gate1 != 0 && gate2 != 0 && gate3 != 0 &&
        state->mode == VFPLIFT_STATE_IDLE && (u32)GameBit_Get(VFPLIFT1_READY_GAMEBIT) == 0)
    {
        vfplift_trigger(VFPLIFT1_TRIGGER_READY, obj);
        GameBit_Set(VFPLIFT1_READY_GAMEBIT, 1);
    }
    if (state->applyHeight != 0 ||
        (state->forceRaised != 0 && state->mode == VFPLIFT_STATE_IDLE))
    {
        ((GameObject*)obj)->anim.localPosY = setup->base.posY + lbl_803E60EC;
        state->applyHeight = 0;
        state->forceRaised = 0;
        state->mode = VFPLIFT_STATE_RAISED;
    }
    if (state->mode == VFPLIFT_STATE_IDLE)
    {
        return;
    }
    if (state->mode == VFPLIFT_STATE_RAISED || state->mode > VFPLIFT_STATE_RAISED || state->mode < VFPLIFT_STATE_LOWERED)
    {
        vfplift_setObjectHitDisabled(obj);
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & VFPLIFT_OBJ_FLAG_INTERACT) != 0)
        {
            buttonDisable(0,VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_LOWER, obj);
            state->mode = VFPLIFT_STATE_LOWERED;
            Sfx_PlayFromObject(obj,VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj,VFPLIFT_SFX_CHANNEL_MOVE);
            GameBit_Set(state->toggleGameBit, 1);
        }
        else
        {
            if ((u32)GameBit_Get(state->toggleGameBit) != 0)
            {
                state->mode = VFPLIFT_STATE_LOWERED;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY;
            }
        }
    }
    else
    {
        vfplift_setObjectHitDisabled(obj);
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & VFPLIFT_OBJ_FLAG_INTERACT) != 0)
        {
            buttonDisable(0,VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_RAISE, obj);
            state->mode = VFPLIFT_STATE_RAISED;
            Sfx_PlayFromObject(obj,VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj,VFPLIFT_SFX_CHANNEL_MOVE);
            GameBit_Set(state->toggleGameBit, 0);
        }
        else
        {
            if ((u32)GameBit_Get(state->toggleGameBit) == 0)
            {
                state->mode = VFPLIFT_STATE_RAISED;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY + lbl_803E60EC;
            }
        }
    }
}

int vfplift_getExtraSize(void) { return 0x20; }

int vfplift_getObjectTypeId(void) { return 0x0; }

void vfplift_release(void)
{
}

void vfplift_initialise(void)
{
}

int vfplift_SeqFn(int obj)
{
    vfplift_getState(obj)->forceRaised = 1;
    return 0;
}

void vfplift_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    objRenderFn_8003b8f4(lbl_803E60F0);
}

void vfplift_update(int obj)
{
    int v;
    Obj_GetPlayerObject();
    v = ((GameObject*)obj)->anim.seqId;
    if (v == VFPLIFT1_OBJTYPE)
    {
        vfplift1_updateState(obj);
    }
    else if (v == VFPLIFT2_OBJTYPE)
    {
        vfplift23_updateState(obj);
    }
    else if (v == VFPLIFT3_OBJTYPE)
    {
        vfplift23_updateState(obj);
    }
}

void vfplift_hitDetect(int obj)
{
    VFPLiftState* state = vfplift_getState(obj);

    if (state->hitDisableGameBit != -1 && (u32)GameBit_Get(state->hitDisableGameBit) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    else if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 8) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode ^= 8;
    }
}

void vfplift_init(int* obj, VFPLiftPlacement* init)
{
    VFPLiftState* st = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)vfplift_SeqFn;
    *(s16*)obj = (s16)(init->yawByte << 8);
    st->mode = 0;
    st->hitDisableGameBit = init->hitDisableGameBit;
    st->toggleGameBit = init->toggleGameBit;
    st->travelDistance = (f32)(s32)
    init->travelDistance;
    st->mapEventNo = init->mapEventNo;
    *(s16*)((char*)st + 0x12) = 0;
    *(s16*)((char*)st + 0x14) = 0;
    *(s16*)((char*)st + 0x16) = 0;
    *(s16*)((char*)st + 0x18) = 0;
    if (((GameObject*)obj)->anim.seqId == 0x3bf)
    {
        if ((u32)GameBit_Get(st->toggleGameBit) != 0)
        {
            st->mode = 4;
            st->applyHeight = 1;
        }
        else
        {
            st->mode = 3;
        }
    }
    if (((GameObject*)obj)->anim.seqId == 0x3b7 && (u32)GameBit_Get(0x4ee) != 0)
    {
        if ((u32)GameBit_Get(st->toggleGameBit) != 0)
        {
            st->mode = 3;
        }
        else
        {
            st->mode = 4;
            st->applyHeight = 1;
        }
    }
}

void vfplift_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}
