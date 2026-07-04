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
 *
 * The unit also exports gIMIcePillarObjDescriptor (the imicepillar object,
 * whose callbacks live in other TUs).
 */
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/object_descriptor.h"
#include "main/objseq.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

#define LINKBLEVCONTROL_OBJFLAG_PARENT_SLACK 0x1000
#define LINKBLEVCONTROL_OBJFLAG_HIDDEN 0x4000
#define LINKBLEVCONTROL_OBJFLAG_HITDETECT_DISABLED 0x2000
extern void Music_Trigger(int id, int arg);
extern int getSaveGameLoadStatus(void);

extern void SCGameBitLatch_Update(void* p, int mask, int a, int b, int c, int d);
extern void fn_80088870(u8* a, u8* b, u8* c, u8* d);
extern void envFxActFn_800887f8(u8 value);
extern u8 lbl_803238D8[];
extern int getEnvfxActImmediately(int a, int b, u16 idx, int d);
extern void* getTrickyObject(void);
extern void fn_80138908(int* tricky, int mode);
extern f32 lbl_803E47C8;

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

void imicepillar_free(void);
int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);
void imicepillar_hitDetect(void);
void imicepillar_update(void);
void imicepillar_init(void);
void imicepillar_release(void);
void imicepillar_initialise(void);
void imicepillar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};

int linkb_levcontrol_getExtraSize(void) { return 0x10; }

enum LinkbLevStage
{
    LINKBLEVCONTROL_STAGE_START = 0, /* awaiting stage-1 gate bit (0x384)     */
    LINKBLEVCONTROL_STAGE_1     = 1, /* stage 1 reached (gate 0x384)          */
    LINKBLEVCONTROL_STAGE_2     = 2, /* stage 2 reached (gate 0x385)          */
    LINKBLEVCONTROL_STAGE_3     = 3, /* stage 3 reached (gate 0x386)          */
    LINKBLEVCONTROL_STAGE_4     = 4, /* stage 4 reached (gate 0x387)          */
    LINKBLEVCONTROL_STAGE_5     = 5  /* final stage reached (gate 0x543)      */
};

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

void linkb_levcontrol_init(int* obj)
{
    extern int getEnvfxAct(int a, int b, u16 idx, int d); /* #57 */
    /* the (u8*)(int) launder is load-bearing: it makes the fn_80088870 arg
     * reuse envBase's register instead of re-materializing the address */
    u8* envBase = (u8*)(int)lbl_803238D8;
    LinkbLevState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (LINKBLEVCONTROL_OBJFLAG_HIDDEN | LINKBLEVCONTROL_OBJFLAG_HITDETECT_DISABLED));
    if (GameBit_Get(0x36e) != 0)
    {
        state->flags &= 4;
    }
    if (GameBit_Get(GAMEBIT_LINKB_STAGE_5) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_5;
    }
    else if (GameBit_Get(GAMEBIT_LINKB_STAGE_4) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_4;
    }
    else if (GameBit_Get(GAMEBIT_LINKB_STAGE_3) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_3;
    }
    else if (GameBit_Get(GAMEBIT_LINKB_STAGE_2) != 0)
    {
        state->stage = LINKBLEVCONTROL_STAGE_2;
    }
    else if (GameBit_Get(GAMEBIT_LINKB_STAGE_1) != 0)
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
        getEnvfxActImmediately(0, 0, 0x23c, 0);
    }
    else
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0) == 0)
        {
            envFxActFn_800887f8(0x1f);
        }
        getEnvfxAct(0, 0, 0x23c, 0);
    }
    state->music = 0;
}

void linkb_levcontrol_update(int* obj)
{
    LinkbLevState* state;
    int* tricky;
    int* player;
    u8* cur;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
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
        if (GameBit_Get(0x1fd) == 0 && GameBit_Get(0x256) == 0)
        {
            GameBit_Set(0x36e, 0);
            state->flags &= ~4;
        }
    }
    else
    {
        if (GameBit_Get(0x256) != 0 || GameBit_Get(0x1fd) != 0)
        {
            GameBit_Set(0x36e, 1);
            state->flags |= 4;
        }
    }
    if (tricky != NULL)
    {
        fn_80138908(tricky, 0);
        switch (state->stage)
        {
        case LINKBLEVCONTROL_STAGE_START:
            if (GameBit_Get(GAMEBIT_LINKB_STAGE_1) != 0)
            {
                fn_80138908(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->unk_02_low = 0;
                return;
            }
            break;
        case LINKBLEVCONTROL_STAGE_1:
            if (GameBit_Get(0xc1) != 0)
            {
                if (!(((GameObject*)player)->objectFlags & LINKBLEVCONTROL_OBJFLAG_PARENT_SLACK))
                {
                    GameBit_Set(GAMEBIT_LINKB_STAGE_2, 1);
                    fn_80138908(tricky, 1);
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
                fn_80138908(tricky, 1);
                if (state->trickyHitCount-- == -1 && !(((GameObject*)tricky)->objectFlags & LINKBLEVCONTROL_OBJFLAG_PARENT_SLACK))
                {
                    GameBit_Set(GAMEBIT_LINKB_STAGE_3, 1);
                    (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                    state->stage++;
                    state->unk_02_low = 0;
                    return;
                }
            }
            break;
        case LINKBLEVCONTROL_STAGE_3:
            if (GameBit_Get(0x1fd) != 0)
            {
                GameBit_Set(GAMEBIT_LINKB_STAGE_4, 1);
                state->stage++;
                break;
            }
            if (GameBit_Get(0x380) != 0)
            {
                state->altPath = 1;
                break;
            }
            if (state->altPath != 0)
            {
                GameBit_Set(GAMEBIT_LINKB_STAGE_4, 1);
                fn_80138908(tricky, 1);
                (*gObjectTriggerInterface)->runSequence(state->stage, obj, -1);
                state->stage++;
                state->unk_02_low = 0;
                return;
            }
            break;
        case LINKBLEVCONTROL_STAGE_4:
            if (GameBit_Get(GAMEBIT_LINKB_STAGE_5) != 0)
            {
                fn_80138908(tricky, 1);
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
        if (GameBit_Get(0x4e3) == 1 && cur[0] >= 4)
        {
            GameBit_Set(0x4e3, 0xff);
        }
        if (state->timer >= lbl_803E47C8)
        {
            state->timer = state->timer - lbl_803E47C8;
            if (GameBit_Get(0x4e3) == 0xff && cur[0] < 4)
            {
                GameBit_Set(0x4e3, 1);
            }
        }
    }
}
