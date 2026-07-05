/*
 * androssligh (DLL 0x2BF) - the lightning beam between Andross's hands in
 * the final boss fight. It locks onto a light-anchor object (0x47dd9),
 * mirroring that object's position each frame, and in its active state
 * (ANDROSSLIGH_ACTIVE) builds a screen-space lightning bolt that arcs
 * across the gap between the two hands. The bolt is rebuilt via
 * lightningCreate the first frame and aged each frame until its phase
 * counter reaches the end, then freed. State is driven externally through
 * androssligh_setState (called by androssbrain on defeat).
 *
 * This DLL has no initialise/release entry points (none exist in the retail
 * symbol table); it is a sub-object whose lifetime is driven externally.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

enum
{
    ANDROSSLIGH_ANCHOR_OBJ_ID = 0x47dd9
};

enum
{
    ANDROSSLIGH_IDLE = 0,
    ANDROSSLIGH_ACTIVE = 1,
    ANDROSSLIGH_DONE = 2
};

typedef struct AndrosslighState
{
    void* anchor;  /* 0x00: light-anchor object (id 0x47dd9), position source */
    void* bolt;    /* 0x04: lightningCreate handle, NULL when not built */
    f32 boltAge;   /* 0x08: phase accumulator advancing the bolt */
    s8 state;      /* 0x0C: ANDROSSLIGH_* */
    u8 prevState;  /* 0x0D: previous frame's state */
    u8 padE[0x10 - 0x0E];
} AndrosslighState;

STATIC_ASSERT(sizeof(AndrosslighState) == 0x10);
STATIC_ASSERT(offsetof(AndrosslighState, bolt) == 0x4);
STATIC_ASSERT(offsetof(AndrosslighState, boltAge) == 0x8);
STATIC_ASSERT(offsetof(AndrosslighState, state) == 0xC);
STATIC_ASSERT(offsetof(AndrosslighState, prevState) == 0xD);

int androssligh_getExtraSize(void) { return sizeof(AndrosslighState); }

int androssligh_getObjectTypeId(void) { return 0; }

void androssligh_free(void)
{
}

void androssligh_render(int obj)
{
    void* bolt = ((AndrosslighState*)((GameObject*)obj)->extra)->bolt;

    if (bolt != NULL)
    {
        lightningRender(bolt);
    }
}

void androssligh_setState(int obj, int newState, u8 force)
{
    AndrosslighState* state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = ((GameObject*)obj)->extra;
    if (state->state == ANDROSSLIGH_DONE)
    {
        if (force == 0)
        {
            return;
        }
    }
    state->state = newState;
}

void androssligh_hitDetect(void)
{
}

void androssligh_init(void)
{
}

void androssligh_update(int obj)
{
    AndrosslighState* state = ((GameObject*)obj)->extra;

    if (state->anchor == NULL)
    {
        state->anchor = (void*)ObjList_FindObjectById(ANDROSSLIGH_ANCHOR_OBJ_ID);
    }
    if (state->anchor != NULL)
    {
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)state->anchor)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)state->anchor)->anim.localPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)state->anchor)->anim.localPosZ;
    }
    state->prevState = state->state;
    switch (state->state)
    {
    case ANDROSSLIGH_IDLE:
        break;
    case ANDROSSLIGH_ACTIVE:
        androssligh_updateBeam(obj, (int)state);
        break;
    case ANDROSSLIGH_DONE:
        break;
    }
}

void androssligh_updateBeam(int obj, int beam)
{
    extern void PSVECAdd(f32* a, f32* b, f32* ab);
    f32 start[3];
    f32 end[3];
    f32 tmp[3];

    start[0] = ((GameObject*)obj)->anim.localPosX - lbl_803DC528;
    start[1] = ((GameObject*)obj)->anim.localPosY;
    start[2] = ((GameObject*)obj)->anim.localPosZ;
    end[0] = ((GameObject*)obj)->anim.localPosX + lbl_803DC528;
    end[1] = start[1];
    end[2] = start[2];
    tmp[0] = start[0] - playerMapOffsetX;
    tmp[1] = start[1];
    tmp[2] = start[0] - playerMapOffsetZ;
    PSMTXMultVec(Camera_GetViewMatrix(), tmp, tmp);
    tmp[0] = -tmp[0];
    tmp[1] = -tmp[1];
    tmp[2] = -tmp[2];
    PSVECScale(tmp, tmp, lbl_803DC52C);
    PSMTXMultVec(Camera_GetInverseViewRotationMatrix(), tmp, tmp);
    PSVECAdd(start, tmp, start);
    tmp[0] = end[0] - playerMapOffsetX;
    tmp[1] = end[1];
    tmp[2] = end[0] - playerMapOffsetZ;
    PSMTXMultVec(Camera_GetViewMatrix(), tmp, tmp);
    tmp[0] = -tmp[0];
    tmp[1] = -tmp[1];
    tmp[2] = -tmp[2];
    PSVECScale(tmp, tmp, lbl_803DC52C);
    PSMTXMultVec(Camera_GetInverseViewRotationMatrix(), tmp, tmp);
    PSVECAdd(end, tmp, end);
    if (*(void**)(beam + 4) == NULL)
    {
        *(int*)(beam + 4) = (int)lightningCreate(start, end, lbl_803DC518, lbl_803DC51C,
                                                 lbl_803DC520, lbl_803DC524, 0);
        *(f32*)(beam + 8) = lbl_803E7608;
    }
    else
    {
        *(f32*)(beam + 8) += timeDelta;
        *(u16*)(*(int*)(beam + 4) + 0x20) = (int)(lbl_803E760C + *(f32*)(beam + 8));
        if (*(u16*)(*(int*)(beam + 4) + 0x20) >= *(u16*)(*(int*)(beam + 4) + 0x22))
        {
            mm_free((void*)*(int*)(beam + 4));
            *(int*)(beam + 4) = 0;
        }
    }
}
