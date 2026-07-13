/*
 * dll_0172 linkb_levcontrol - level controller for Link's boss arena (the
 * Tricky/SharpClaw encounter). It drives a 5-stage progression machine
 * (state->stage) gated on game bits, runs the per-stage trigger sequence,
 * pokes the Tricky object (fn_80138908) at each transition, edge-latches the
 * arena music (track 0x1A) on the sun-position sky flag, maintains gamebit
 * latches via SCGameBitLatch_Update, and re-arms gamebit 0x4e3 from the
 * tricky-energy meter on a timer.
 *
 * init seeds stage from the highest set progress bit (0x543/0x387/0x386/
 * 0x385/0x384) and primes the ambient env fx by save-load status.
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/savegame_load_api.h"
#include "main/audio/music_api.h"
#include "main/sky_api.h"
#include "main/object.h"
#include "main/dll/dll_80136a40.h"
#include "main/render.h"
#include "main/mapEvent.h"
#include "main/object_descriptor.h"
#include "main/objseq.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

typedef struct LinkbLevState
{
    int flags;
    s8 trickyHitCount : 2;
    u8 stage : 3;
    u8 unk_02_low : 3; /* cleared on every stage advance, never read */
    u8 altPath : 1;    /* stage-3 gamebit 0x380 latch */
    u8 unusedFlags : 7;
    u8 pad6[2];
    f32 timer;
    s16 music;
} LinkbLevState;

#define LINKBLEVCONTROL_OBJFLAG_PARENT_SLACK       0x1000
#define LINKBLEVCONTROL_OBJFLAG_HIDDEN             0x4000
#define LINKBLEVCONTROL_OBJFLAG_HITDETECT_DISABLED 0x2000

/* env-effect id activated on level init (immediate when save already loaded,
 * else deferred; index-style, role opaque) */
#define LINKBLEVCONTROL_ENVFX_A 0x23c

/* arena music track (also stored in state->music as the active-track marker) */
#define LINKB_MUSIC_TRACK 0x1a

/* progression game bits; each set bit advances stage N-1 -> N */
enum
{
    GAMEBIT_LINKB_STAGE_1 = 0x384,
    GAMEBIT_LINKB_STAGE_2 = 0x385,
    GAMEBIT_LINKB_STAGE_3 = 0x386,
    GAMEBIT_LINKB_STAGE_4 = 0x387,
    GAMEBIT_LINKB_STAGE_5 = 0x543
};

enum LinkbLevStage
{
    LINKBLEVCONTROL_STAGE_START = 0, /* awaiting stage-1 gate bit (0x384)     */
    LINKBLEVCONTROL_STAGE_1 = 1,     /* stage 1 reached (gate 0x384)          */
    LINKBLEVCONTROL_STAGE_2 = 2,     /* stage 2 reached (gate 0x385)          */
    LINKBLEVCONTROL_STAGE_3 = 3,     /* stage 3 reached (gate 0x386)          */
    LINKBLEVCONTROL_STAGE_4 = 4,     /* stage 4 reached (gate 0x387)          */
    LINKBLEVCONTROL_STAGE_5 = 5      /* final stage reached (gate 0x543)      */
};

extern u8 lbl_803238D8[];
__declspec(section ".sdata2") f32 lbl_803E47C8 = 2000.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E47CC = 0.0f;
#pragma explicit_zero_data off
extern void SCGameBitLatch_Update(void* p, int mask, int a, int b, int c, int d);
extern void fn_80088870(u8* a, u8* b, u8* c, u8* d);

int linkb_levcontrol_getExtraSize(void)
{
    return 0x10;
}

void linkb_levcontrol_update(int* obj)
{
    LinkbLevState* state;
    int* tricky;
    GameObject* player;
    u8* cur;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    tricky = (int*)getTrickyObject();
    cur = (*gMapEventInterface)->getTrickyEnergy();
    if ((*gSkyInterface)->getSunPosition(0) != 0)
    {
        if (state->music != -1)
        {
            state->music = -1;
            if (state->flags & 8)
            {
                Music_Trigger(LINKB_MUSIC_TRACK, 0);
            }
        }
    }
    else
    {
        if (state->music != LINKB_MUSIC_TRACK)
        {
            state->music = LINKB_MUSIC_TRACK;
            if (state->flags & 8)
            {
                Music_Trigger(LINKB_MUSIC_TRACK, 1);
            }
        }
    }
    SCGameBitLatch_Update(state, 1, -1, -1, 0x3a0, 0x35);
    SCGameBitLatch_Update(state, 2, -1, -1, 0xb36, 0x96);
    SCGameBitLatch_Update(state, 8, -1, -1, 0x3a1, state->music);
    if (state->flags & 4)
    {
        if (mainGetBit(0x1fd) == 0 && mainGetBit(0x256) == 0)
        {
            mainSetBits(0x36e, 0);
            state->flags &= ~4;
        }
    }
    else
    {
        if (mainGetBit(0x256) != 0 || mainGetBit(0x1fd) != 0)
        {
            mainSetBits(0x36e, 1);
            state->flags |= 4;
        }
    }
    if (tricky != NULL)
    {
        fn_80138908((GameObject*)tricky, 0);
        switch (state->stage)
        {
        case LINKBLEVCONTROL_STAGE_START:
            if (mainGetBit(GAMEBIT_LINKB_STAGE_1) != 0)
            {
                fn_80138908((GameObject*)tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->unk_02_low = 0;
                return;
            }
            break;
        case LINKBLEVCONTROL_STAGE_1:
            if (mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0)
            {
                if (!(((GameObject*)player)->objectFlags & LINKBLEVCONTROL_OBJFLAG_PARENT_SLACK))
                {
                    mainSetBits(GAMEBIT_LINKB_STAGE_2, 1);
                    fn_80138908((GameObject*)tricky, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->unk_02_low = 0;
                    return;
                }
            }
            break;
        case LINKBLEVCONTROL_STAGE_2:
            if (cur[0] != 0)
            {
                fn_80138908((GameObject*)tricky, 1);
                if (state->trickyHitCount-- == -1 &&
                    !(((GameObject*)tricky)->objectFlags & LINKBLEVCONTROL_OBJFLAG_PARENT_SLACK))
                {
                    mainSetBits(GAMEBIT_LINKB_STAGE_3, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->unk_02_low = 0;
                    return;
                }
            }
            break;
        case LINKBLEVCONTROL_STAGE_3:
            if (mainGetBit(0x1fd) != 0)
            {
                mainSetBits(GAMEBIT_LINKB_STAGE_4, 1);
                state->stage++;
                break;
            }
            if (mainGetBit(0x380) != 0)
            {
                state->altPath = 1;
                break;
            }
            if (state->altPath != 0)
            {
                mainSetBits(GAMEBIT_LINKB_STAGE_4, 1);
                fn_80138908((GameObject*)tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->unk_02_low = 0;
                return;
            }
            break;
        case LINKBLEVCONTROL_STAGE_4:
            if (mainGetBit(GAMEBIT_LINKB_STAGE_5) != 0)
            {
                fn_80138908((GameObject*)tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->unk_02_low = 0;
                return;
            }
            break;
        }
    }
    if (tricky != NULL)
    {
        if (!(((GameObject*)tricky)->objectFlags & LINKBLEVCONTROL_OBJFLAG_PARENT_SLACK))
        {
            state->timer = state->timer + timeDelta;
        }
        if (mainGetBit(GAMEBIT_TrickyTalk) == 1 && cur[0] >= 4)
        {
            mainSetBits(GAMEBIT_TrickyTalk, 0xff);
        }
        if (state->timer >= lbl_803E47C8)
        {
            state->timer = state->timer - lbl_803E47C8;
            if (mainGetBit(GAMEBIT_TrickyTalk) == 0xff && cur[0] < 4)
            {
                mainSetBits(GAMEBIT_TrickyTalk, 1);
            }
        }
    }
}

void linkb_levcontrol_init(int* obj)
{
    /* the (u8*)(int) launder is load-bearing: it makes the fn_80088870 arg
     * reuse envBase's register instead of re-materializing the address */
    u8* envBase = (u8*)(int)lbl_803238D8;
    LinkbLevState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags =
        (u16)(((GameObject*)obj)->objectFlags |
              (LINKBLEVCONTROL_OBJFLAG_HIDDEN | LINKBLEVCONTROL_OBJFLAG_HITDETECT_DISABLED));
    if (mainGetBit(0x36e) != 0)
    {
        state->flags &= 4;
    }
    if (mainGetBit(GAMEBIT_LINKB_STAGE_5) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_5;
    }
    else if (mainGetBit(GAMEBIT_LINKB_STAGE_4) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_4;
    }
    else if (mainGetBit(GAMEBIT_LINKB_STAGE_3) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_3;
    }
    else if (mainGetBit(GAMEBIT_LINKB_STAGE_2) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_2;
    }
    else if (mainGetBit(GAMEBIT_LINKB_STAGE_1) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_1;
    }
    fn_80088870(envBase + 0x38, (u8*)(int)lbl_803238D8, envBase + 0x70, envBase + 0xa8);
    if (getSaveGameLoadStatus() != 0)
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0) == 0)
        {
            envFxActFn_800887f8(0x3f);
        }
        getEnvfxActImmediately(0, 0, LINKBLEVCONTROL_ENVFX_A, 0);
    }
    else
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0) == 0)
        {
            envFxActFn_800887f8(0x1f);
        }
        getEnvfxActInt(0, 0, LINKBLEVCONTROL_ENVFX_A, 0);
    }
    state->music = 0;
}
