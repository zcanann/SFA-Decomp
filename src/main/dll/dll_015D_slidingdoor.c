/*
 * slidingdoor (DLL 0x15D) - a proximity-triggered sliding door object.
 *
 * The 3-bit door state (top bits of state byte 0) is a 4-state machine:
 *   0 closed, 1 open, 2 opening, 3 closing.
 * slidingdoor_SeqFn (installed as the anim/think callback) opens the door
 * when its openGameBit (gated by gateGameBit) is set AND the player or
 * Tricky is within 130.0f xz-distance, and closes it again when
 * neither is near. The opening/closing transitions complete on the matching
 * trigger command (1=close-done, 2=open-done). SeqFn returns 1 in the steady
 * states and 0 mid-transition.
 *
 * slidingdoor_update fires once (latched via obj->unkF4): it preempts the
 * placement's preemptEvent if the door is already moving and runs the
 * placement's startup sequence (data[0x1e], -1 = none).
 */
#include "main/dll/drexplodable_types.h"
#include "main/obj_placement.h"

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

/* segment pragma-stack balance (re-split): */

#include "main/dll/IM/IMicicle.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/objseq.h"
#include "main/dll/VF/vf_shared.h"

typedef struct SlidingdoorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 openGameBit;    /* 0x18: door opens while this bit is set (gated by gateGameBit) */
    s16 openedGameBit;  /* 0x1A: set to 1 once the door opens */
    s16 preemptEvent;   /* 0x1C: event preempted by slidingdoor_update if already moving */
    s8 startupSequenceId; /* 0x1E: startup sequence id */
    u8 pad1F[0x20 - 0x1F];
    s16 unk20;          /* 0x20 */
    s16 gateGameBit;    /* 0x22: -1 = none; otherwise must also be set to open */
    u8 pad24[0x28 - 0x24];
} SlidingdoorPlacement;

/* 3-bit door state machine (see file header): */
enum SlidingdoorMode
{
    SLIDINGDOOR_MODE_CLOSED = 0,
    SLIDINGDOOR_MODE_OPEN = 1,
    SLIDINGDOOR_MODE_OPENING = 2,
    SLIDINGDOOR_MODE_CLOSING = 3
};

typedef struct SlidingdoorState
{
    u8 mode : 3;
    u8 rest : 5;
} SlidingdoorState;

extern void* getTrickyObject(void);

int slidingdoor_SeqFn(u8* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    register int playerNear;
    register int trickyNear;
    register u8* state;
    u8* params;
    u32 mode;
    int result;
    void* player;
    void* tricky;

    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();

    if (player != NULL)
    {
        playerNear = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            130.0f;
    }
    else
    {
        playerNear = 0;
    }

    if (tricky != NULL)
    {
        trickyNear = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)((u8*)tricky + 0x18)) < 130.0f;
    }
    else
    {
        trickyNear = 0;
    }

    state = ((GameObject*)obj)->extra;
    params = *(u8**)&((GameObject*)obj)->anim.placementData;
    mode = ((u32)state[0] >> 5) & 7;

    if (mode == SLIDINGDOOR_MODE_CLOSED)
    {
        if (GameBit_Get(((SlidingdoorPlacement*)params)->openGameBit) != 0 &&
            (((SlidingdoorPlacement*)params)->gateGameBit == -1 ||
                GameBit_Get(((SlidingdoorPlacement*)params)->gateGameBit) != 0))
        {
            GameBit_Set(((SlidingdoorPlacement*)params)->openedGameBit, 1);
            if (playerNear != 0 || trickyNear != 0)
            {
                ((SlidingdoorState*)state)->mode = SLIDINGDOOR_MODE_OPENING;
            }
        }
    }
    else if (mode == SLIDINGDOOR_MODE_OPEN)
    {
        if ((GameBit_Get(((SlidingdoorPlacement*)params)->openGameBit) != 0 ||
                (((SlidingdoorPlacement*)params)->gateGameBit != -1 &&
                    GameBit_Get(((SlidingdoorPlacement*)params)->gateGameBit) != 0)) &&
            playerNear == 0 && trickyNear == 0)
        {
            ((SlidingdoorState*)state)->mode = SLIDINGDOOR_MODE_CLOSING;
        }
    }

    {
        register SlidingdoorState* fl = (SlidingdoorState*)state;
        if (fl->mode == SLIDINGDOOR_MODE_OPENING)
        {
            if (animUpdate->triggerCommand == 2)
            {
                fl->mode = SLIDINGDOOR_MODE_OPEN;
            }
        }
        else if (fl->mode == SLIDINGDOOR_MODE_CLOSING)
        {
            if (animUpdate->triggerCommand == 1)
            {
                fl->mode = SLIDINGDOOR_MODE_CLOSED;
            }
        }
    }

    result = 0;
    {
        u32 modeAfter = ((u32)state[0] >> 5) & 7;
        if (modeAfter != SLIDINGDOOR_MODE_OPENING)
        {
            if (modeAfter != SLIDINGDOOR_MODE_CLOSING) result = 1;
        }
    }
    return result;
}

int slidingdoor_getExtraSize(void) { return 0x1; }
int slidingdoor_getObjectTypeId(void) { return 0x0; }

void slidingdoor_free(void)
{
}

void slidingdoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void slidingdoor_hitDetect(void)
{
}

void slidingdoor_update(u8* obj)
{
    u8* sub;
    u8* data;
    if (((GameObject*)obj)->unkF4 != 0) return;
    sub = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((SlidingdoorPlacement*)data)->preemptEvent != 0)
    {
        u32 mode = (u32)((sub[0] >> 5) & 7);
        if (mode != SLIDINGDOOR_MODE_CLOSED)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, ((SlidingdoorPlacement*)data)->preemptEvent);
        }
    }
    {
        s8 id = ((SlidingdoorPlacement*)data)->startupSequenceId;
        if (id != -1)
        {
            (*gObjectTriggerInterface)->runSequence(id, obj, -1);
        }
    }
    *(u32*)&((GameObject*)obj)->unkF4 = 1;
}

void slidingdoor_init(u8* obj, u8* data)
{
    u8* sub;
    f32 scale;
    u32 doorState = 0;
    *(u32*)&((GameObject*)obj)->unkF4 = doorState;
    ((GameObject*)obj)->anim.rotX = (s16)(data[0x1f] << 8);
    ((GameObject*)obj)->animEventCallback = slidingdoor_SeqFn;
    scale = (f32)(u32)data[0x21] / 64.0f;
    ((GameObject*)obj)->anim.rootMotionScale = scale;
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    sub = ((GameObject*)obj)->extra;
    ((SlidingdoorState*)sub)->mode = doorState;
}

void slidingdoor_release(void)
{
}

void slidingdoor_initialise(void)
{
}
