/*
 * DLL 0x00C8 (depthoffieldpoint) — depth-of-field point object
 * [0x8016CD48-0x8016CEE8).
 *
 * A placed point that drives the screen blur (depth-of-field) filter.
 * Its animation-event callback (depthoffieldpoint_SeqFn) toggles the
 * filter: while enabled it feeds the point's world position plus two
 * mode bytes to turnOnBlurFilter every tick; sequence events select the
 * mode (off / default / two variants) and the update handler tears the
 * filter back down. State lives in a 3-byte extra (DofState).
 */
#include "main/dll/dll_00C8_depthoffieldpoint.h"

#define DEPTHOFFIELDPOINT_OBJFLAG_HIDDEN 0x4000

extern void turnOnBlurFilter(f32 a, f32 b, f32 c, int field1, int field2);

int depthoffieldpoint_getExtraSize(void);

typedef struct DofState
{
    u8 enabled : 1; /* 0x00 & 0x01: blur filter currently active */
    u8 unusedPad : 7;
    u8 mode0;       /* 0x01: turnOnBlurFilter mode arg 1 */
    u8 mode1;       /* 0x02: turnOnBlurFilter mode arg 2 */
} DofState;

/* sequence event opcodes consumed by depthoffieldpoint_SeqFn */
enum
{
    DOF_SEQEV_DISABLE = 0,
    DOF_SEQEV_ENABLE = 1,
    DOF_SEQEV_ENABLE_MODE0 = 2,
    DOF_SEQEV_ENABLE_MODE1 = 3
};

ObjectDescriptor gDepthOfFieldPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)depthoffieldpoint_init,
    (ObjectDescriptorCallback)depthoffieldpoint_update,
    0,
    0,
    0,
    0,
    depthoffieldpoint_getExtraSize,
};

u16 lbl_803208A0[] = {
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C2, 0x006F, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

u32 lbl_803208E8[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0x01020000,
    0,
    0,
};

int depthoffieldpoint_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    DofState* state = ((GameObject*)obj)->extra;
    int ev;
    if (state->enabled)
    {
        turnOnBlurFilter(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                         ((GameObject*)obj)->anim.worldPosZ, state->mode0, state->mode1);
    }
    for (ev = 0; ev < animUpdate->eventCount; ev++)
    {
        switch (animUpdate->eventIds[ev])
        {
        case DOF_SEQEV_ENABLE:
            state->enabled = 1;
            state->mode0 = 0;
            break;
        case DOF_SEQEV_DISABLE:
            state->enabled = 0;
            Rcp_DisableBlurFilter();
            break;
        case DOF_SEQEV_ENABLE_MODE0:
            state->enabled = 1;
            state->mode0 = 1;
            state->mode1 = 0;
            break;
        case DOF_SEQEV_ENABLE_MODE1:
            state->enabled = 1;
            state->mode1 = 1;
            state->mode0 = 0;
            break;
        }
    }
    return 0;
}

int depthoffieldpoint_getExtraSize(void) { return 0x3; }

void depthoffieldpoint_update(int* obj)
{
    DofState* state = ((GameObject*)obj)->extra;
    if (state->enabled)
    {
        state->enabled = 0;
        Rcp_DisableBlurFilter();
    }
}

void depthoffieldpoint_init(int* obj)
{
    DofState* state = ((GameObject*)obj)->extra;
    state->enabled = 0;
    ((GameObject*)obj)->animEventCallback = depthoffieldpoint_SeqFn;
    state->mode0 = 0;
    ((GameObject*)obj)->objectFlags |= DEPTHOFFIELDPOINT_OBJFLAG_HIDDEN;
}
