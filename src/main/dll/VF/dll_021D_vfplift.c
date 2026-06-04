#include "main/dll/VF/vf_shared.h"

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
#define VFPLIFT_FLAG_APPLY_HEIGHT 0x80
#define VFPLIFT_FLAG_FORCE_RAISED 0x40
#define VFPLIFT_OBJ_FLAG_NO_HIT 0x08
#define VFPLIFT_OBJ_FLAG_INTERACT 0x01

typedef struct VFPLiftState {
    f32 travelDistance;
    u8 pad04[0x0a - 0x04];
    s16 mode;
    s16 hitDisableGameBit;
    s16 toggleGameBit;
    u8 pad10[0x1a - 0x10];
    u8 mapEventNo;
    u8 pad1b;
    u8 flags;
} VFPLiftState;

typedef struct VFPLiftMapEventInterface {
    u8 pad00[0x40];
    u8 (*getMode)(s8 mapEventNo);
} VFPLiftMapEventInterface;

typedef struct VFPLiftObjectTriggerInterface {
    u8 pad00[0x48];
    void (*trigger)(int triggerId,int obj,int arg);
} VFPLiftObjectTriggerInterface;

extern void buttonDisable(int index,u32 flags);
extern void Sfx_StopObjectChannel(int obj,int channel);
extern f32 lbl_803E60E0;
extern f32 lbl_803E60E4;
extern f32 lbl_803E60E8;
extern f32 lbl_803E60EC;

static inline VFPLiftState *vfplift_getState(int obj)
{
    return *(VFPLiftState **)(obj + 0xb8);
}

static inline f32 vfplift_getModelY(int obj)
{
    return *(f32 *)(*(int *)(obj + 0x4c) + 0xc);
}

static inline void vfplift_trigger(int triggerId,int obj)
{
    ((VFPLiftObjectTriggerInterface *)*gObjectTriggerInterface)->trigger(triggerId,obj,-1);
}

static inline void vfplift_setObjectHitDisabled(int obj)
{
    *(u8 *)(obj + 0xaf) = (*(u8 *)(obj + 0xaf) & ~VFPLIFT_OBJ_FLAG_NO_HIT);
}

static inline f32 vfplift23_getRaisedOffset(int objType)
{
    f32 offset;

    offset = lbl_803E60E0;
    if (objType == VFPLIFT3_OBJTYPE) {
        offset = lbl_803E60E4;
    } else if (objType == VFPLIFT2_OBJTYPE) {
        offset = lbl_803E60E8;
    }
    return offset;
}

void vfplift23_updateState(int obj)
{
    VFPLiftState *state;
    f32 raisedOffset;

    state = vfplift_getState(obj);
    raisedOffset = vfplift23_getRaisedOffset(*(s16 *)(obj + 0x46));
    if ((s8)state->flags < 0) {
        *(f32 *)(obj + 0x10) = vfplift_getModelY(obj) + raisedOffset;
        state->flags &= ~VFPLIFT_FLAG_APPLY_HEIGHT;
    }
    if (state->mode < VFPLIFT_STATE_LOWERED || state->mode >= VFPLIFT_STATE_RAISED) {
        vfplift_setObjectHitDisabled(obj);
        if ((*(u8 *)(obj + 0xaf) & VFPLIFT_OBJ_FLAG_INTERACT) == 0) {
            if (GameBit_Get(state->toggleGameBit) == 0) {
                state->mode = VFPLIFT_STATE_LOWERED;
                *(f32 *)(obj + 0x10) = vfplift_getModelY(obj);
            }
        } else {
            buttonDisable(0,VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_LOWER,obj);
            state->mode = VFPLIFT_STATE_LOWERED;
            Sfx_PlayFromObject(obj,VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj,VFPLIFT_SFX_CHANNEL_MOVE);
            GameBit_Set(state->toggleGameBit,0);
        }
    } else {
        vfplift_setObjectHitDisabled(obj);
        if ((*(u8 *)(obj + 0xaf) & VFPLIFT_OBJ_FLAG_INTERACT) == 0) {
            if (GameBit_Get(state->toggleGameBit) != 0) {
                state->mode = VFPLIFT_STATE_RAISED;
                *(f32 *)(obj + 0x10) = vfplift_getModelY(obj) + raisedOffset;
            }
        } else {
            buttonDisable(0,VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_RAISE,obj);
            state->mode = VFPLIFT_STATE_RAISED;
            Sfx_PlayFromObject(obj,VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj,VFPLIFT_SFX_CHANNEL_MOVE);
            GameBit_Set(state->toggleGameBit,1);
        }
    }
}

void vfplift1_updateState(int obj)
{
    VFPLiftState *state;
    s16 gate0;
    s16 gate1;
    s16 gate2;
    s16 gate3;

    state = vfplift_getState(obj);
    if (Obj_GetPlayerObject() == NULL) {
        return;
    }

    *(u8 *)(obj + 0xaf) |= VFPLIFT_OBJ_FLAG_NO_HIT;
    gate0 = GameBit_Get(VFPLIFT1_GATE_GAMEBIT_0);
    gate1 = GameBit_Get(VFPLIFT1_GATE_GAMEBIT_1);
    gate2 = GameBit_Get(VFPLIFT1_GATE_GAMEBIT_2);
    gate3 = GameBit_Get(VFPLIFT1_GATE_GAMEBIT_3);
    if (((VFPLiftMapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac)) == 2) {
        gate0 = 1;
        gate1 = 1;
        gate2 = 1;
        gate3 = 1;
    }
    if (gate0 != 0 && gate1 != 0 && gate2 != 0 && gate3 != 0 &&
        state->mode == VFPLIFT_STATE_IDLE && GameBit_Get(VFPLIFT1_READY_GAMEBIT) == 0) {
        vfplift_trigger(VFPLIFT1_TRIGGER_READY,obj);
        GameBit_Set(VFPLIFT1_READY_GAMEBIT,1);
    }
    if ((s8)state->flags < 0 ||
        ((state->flags & VFPLIFT_FLAG_FORCE_RAISED) != 0 && state->mode == VFPLIFT_STATE_IDLE)) {
        *(f32 *)(obj + 0x10) = vfplift_getModelY(obj) + lbl_803E60EC;
        state->flags &= ~VFPLIFT_FLAG_APPLY_HEIGHT;
        state->flags &= ~VFPLIFT_FLAG_FORCE_RAISED;
        state->mode = VFPLIFT_STATE_RAISED;
    }
    if (state->mode == VFPLIFT_STATE_IDLE) {
        return;
    }
    if (state->mode < VFPLIFT_STATE_LOWERED || state->mode >= VFPLIFT_STATE_RAISED) {
        vfplift_setObjectHitDisabled(obj);
        if ((*(u8 *)(obj + 0xaf) & VFPLIFT_OBJ_FLAG_INTERACT) == 0) {
            if (GameBit_Get(state->toggleGameBit) != 0) {
                state->mode = VFPLIFT_STATE_LOWERED;
                *(f32 *)(obj + 0x10) = vfplift_getModelY(obj);
            }
        } else {
            buttonDisable(0,VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_LOWER,obj);
            state->mode = VFPLIFT_STATE_LOWERED;
            Sfx_PlayFromObject(obj,VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj,VFPLIFT_SFX_CHANNEL_MOVE);
            GameBit_Set(state->toggleGameBit,1);
        }
    } else {
        vfplift_setObjectHitDisabled(obj);
        if ((*(u8 *)(obj + 0xaf) & VFPLIFT_OBJ_FLAG_INTERACT) == 0) {
            if (GameBit_Get(state->toggleGameBit) == 0) {
                state->mode = VFPLIFT_STATE_RAISED;
                *(f32 *)(obj + 0x10) = vfplift_getModelY(obj) + lbl_803E60EC;
            }
        } else {
            buttonDisable(0,VFPLIFT_INTERACT_BUTTON_MASK);
            vfplift_trigger(VFPLIFT_TRIGGER_RAISE,obj);
            state->mode = VFPLIFT_STATE_RAISED;
            Sfx_PlayFromObject(obj,VFPLIFT_SFX_MOVE);
            Sfx_StopObjectChannel(obj,VFPLIFT_SFX_CHANNEL_MOVE);
            GameBit_Set(state->toggleGameBit,0);
        }
    }
}

int vfplift_getExtraSize(void) { return 0x20; }

int vfplift_getObjectTypeId(void) { return 0x0; }

void vfplift_release(void) {}

void vfplift_initialise(void) {}

#pragma peephole off
#pragma scheduling off
int vfplift_SeqFn(int obj) {
    *(u8 *)(*(int *)(obj + 0xb8) + 0x1c) |= 0x40;
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    objRenderFn_8003b8f4(lbl_803E60F0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_update(int obj) {
    int v;
    Obj_GetPlayerObject();
    v = *(s16 *)((char *)obj + 0x46);
    if (v == VFPLIFT1_OBJTYPE) {
        vfplift1_updateState(obj);
    } else if (v == VFPLIFT2_OBJTYPE) {
        vfplift23_updateState(obj);
    } else if (v == VFPLIFT3_OBJTYPE) {
        vfplift23_updateState(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_hitDetect(int obj) {
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(s16 *)((char *)inner + 0xc) != -1 && (u32)GameBit_Get(*(s16 *)((char *)inner + 0xc)) == 0) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
    } else if ((*(u8 *)((char *)obj + 0xaf) & 8) != 0) {
        *(u8 *)((char *)obj + 0xaf) ^= 8;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(void **)((char *)obj + 0xbc) = (void *)vfplift_SeqFn;
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)((char *)inner + 0xa) = 0;
    *(s16 *)((char *)inner + 0xc) = *(s16 *)((char *)init + 0x20);
    *(s16 *)((char *)inner + 0xe) = *(s16 *)((char *)init + 0x1e);
    *(f32 *)inner = (f32)(s32)*(s16 *)((char *)init + 0x1a);
    *(u8 *)((char *)inner + 0x1a) = *(s16 *)((char *)init + 0x1c);
    *(s16 *)((char *)inner + 0x12) = 0;
    *(s16 *)((char *)inner + 0x14) = 0;
    *(s16 *)((char *)inner + 0x16) = 0;
    *(s16 *)((char *)inner + 0x18) = 0;
    if (*(s16 *)((char *)obj + 0x46) == 0x3bf) {
        if (GameBit_Get(*(s16 *)((char *)inner + 0xe)) != 0) {
            *(s16 *)((char *)inner + 0xa) = 4;
            *(u8 *)((char *)inner + 0x1c) |= 0x80;
        } else {
            *(s16 *)((char *)inner + 0xa) = 3;
        }
    }
    if (*(s16 *)((char *)obj + 0x46) == 0x3b7 && GameBit_Get(0x4ee) != 0) {
        if (GameBit_Get(*(s16 *)((char *)inner + 0xe)) != 0) {
            *(s16 *)((char *)inner + 0xa) = 3;
        } else {
            *(s16 *)((char *)inner + 0xa) = 4;
            *(u8 *)((char *)inner + 0x1c) |= 0x80;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplift_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}
#pragma scheduling reset
#pragma peephole reset
