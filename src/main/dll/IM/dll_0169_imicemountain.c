/*
 * imicemountain (DLL 0x169) - the master event controller for the Ice
 * Mountain map. A single instance drives the level's scripted progress:
 * it arms the map-event group triggers at init, then runs one of three
 * top-level branches selected by the map-event "act" queried at startup
 * (1 = full event sequence, 2 = boulder-chase replay, 5 = already
 * complete).
 *
 * The act-1 branch steps an internal event-state machine
 * (imicemountain_updateEventState, states 1..7) that gates avalanche
 * effects, the boulder spawn, level locks and the final warp out. Every
 * frame the controller also shows the "turn back" warning text while a
 * timer is positive, latches the day/night music, and refreshes a block
 * of SCGameBitLatch records that mirror world state into game bits.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objanim_update.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/music_trigger_ids.h"

/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState
{
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

extern void getLActions();
extern void gameBitFn_800ea2e0(int idx);

extern f32 lbl_803E46E0;
extern f32 lbl_803E46D8;
extern void objRenderFn_8003b8f4(f32);
extern void getEnvfxAct(int* obj, int* target, int id, int p);
extern void fn_801AC108(int* obj, int* extra);

extern void fn_801AC01C(int* obj);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);

extern void Music_Trigger(int id, int arg);
extern void SCGameBitLatch_Update(void* state, int mask, int a, int b, int c, int d);
extern f32 timeDelta;
extern f32 lbl_803E46DC;

int IMIceMountain_SeqFn(void* obj, int unused, ObjAnimUpdateState* animUpdate);

void imicemountain_free(void)
{
}

void imicemountain_hitDetect(void)
{
}

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))
#define MEVT_QUERY(a)         (*gMapEventInterface)->getMapAct((a))

/* imicemountain_init: clear the ice-mountain gamebit block, arm the
 * map-event triggers, then branch on the queried level state to set the
 * boulder's start state and fire the appropriate triggers. */
#pragma scheduling off
#pragma peephole off
void imicemountain_init(int* obj)
{
    IMIceMountainState* sub = ((GameObject*)obj)->extra;
    int i;
    ((GameObject*)obj)->animEventCallback = IMIceMountain_SeqFn;
    for (i = 1; (u8)i <= 0xd; i++)
    {
        gameBitFn_800ea2e0(i);
    }
    sub->warningTextTimer = lbl_803E46E0;
    MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 1, 0);
    MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 5, 1);
    unlockLevel(0, 0, 1);
    if (GameBit_Get(0x379) != 0)
    {
        MEVT_SET(((GameObject *)obj)->anim.mapEventSlot, 2);
    }
    sub->mapEventState = MEVT_QUERY(((GameObject *)obj)->anim.mapEventSlot);
    switch (sub->mapEventState)
    {
    case 1:
        if (GameBit_Get(0x72) != 0)
        {
            if (GameBit_Get(0x379) != 0)
            {
                sub->eventState = 5;
            }
            else
            {
                GameBit_Set(0x3a3, 0);
                GameBit_Set(0x3a2, 0);
                GameBit_Set(0xcb, 0);
                GameBit_Set(0x379, 0);
                sub->eventState = 3;
            }
        }
        else
        {
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 0, 1);
            if (GameBit_Get(0xadc) != 0 && GameBit_Get(0xadd) != 0)
            {
                MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 0xb, 1);
            }
            if (GameBit_Get(0x6e) != 0)
            {
                sub->eventState = 1;
            }
            else
            {
                MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 2, 1);
                sub->eventState = 7;
            }
        }
        MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 3, 1);
        MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 4, 1);
        MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 7, 1);
        break;
    case 2:
        GameBit_Set(0x3a3, 0);
        GameBit_Set(0x3a2, 0);
        GameBit_Set(0xce, 0);
        GameBit_Set(0x37b, 0);
        GameBit_Set(0xc8, 0);
        GameBit_Set(0x374, 0);
        GameBit_Set(0x37c, 0);
        MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 2, 0);
        break;
    case 3:
    case 4:
        break;
    }
}
#undef MEVT_TRIGGER
#undef MEVT_SET
#undef MEVT_QUERY
#pragma peephole on

int imicemountain_getExtraSize(void) { return 0x14; }
int imicemountain_getObjectTypeId(void) { return 0x0; }

#pragma scheduling on
#pragma peephole off
void imicemountain_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E46D8);
}

#pragma scheduling off
#pragma peephole on
int IMIceMountain_SeqFn(void* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    ((IMIceMountainState*)((GameObject*)obj)->extra)->latchFlags |= 1;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 2)
        {
            GameBit_Set(0x378, 0);
            GameBit_Set(0x3b9, 0);
        }
    }
    return 0;
}

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))

/* imicemountain_updateEventState: the act-1 event machine (states 1..7;
 * state 0 idles), advancing avalanche fx, the boulder spawn, level
 * locks and the final warp as the relevant game bits are set. */
#pragma peephole off
void imicemountain_updateEventState(int* obj)
{
    IMIceMountainState* extra = ((GameObject*)obj)->extra;
    switch (extra->eventState)
    {
    case 7:
        if (GameBit_Get(0x6e) != 0)
        {
            extra->eventState = 1;
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 2, 0);
        }
        break;
    case 1:
        if (GameBit_Get(0xadc) != 0 && GameBit_Get(0xadd) != 0)
        {
            GameBit_Set(0xade, 1);
            extra->eventState = 2;
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 0xb, 1);
        }
        else if (GameBit_Get(0x70) != 0)
        {
            extra->eventState = 2;
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 0xb, 1);
        }
        break;
    case 2:
        if (GameBit_Get(0x70) != 0)
        {
            extra->eventState = 3;
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 6, 1);
        }
        break;
    case 3:
        if (GameBit_Get(0x72) != 0)
        {
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 0, 0);
        }
        if (GameBit_Get(0x3a2) != 0)
        {
            extra->eventState = 4;
            GameBit_Set(0xe5d, 1);
            GameBit_Set(0xe5e, 1);
            GameBit_Set(0xe5f, 1);
            GameBit_Set(0xe60, 1);
            GameBit_Set(0xe61, 1);
            GameBit_Set(0xe62, 1);
            GameBit_Set(0xe63, 1);
            GameBit_Set(0xe64, 1);
            GameBit_Set(0xe65, 1);
            GameBit_Set(0xe66, 1);
            GameBit_Set(0xe67, 1);
            GameBit_Set(0xe68, 1);
            GameBit_Set(0xe69, 1);
            GameBit_Set(0xe6a, 1);
            GameBit_Set(0xe6b, 1);
        }
        if (((GameObject*)obj)->unkF4 == 0)
        {
            getEnvfxAct(obj, obj, 0xa3, 0);
            getEnvfxAct(obj, obj, 0x9e, 0);
            getEnvfxAct(obj, obj, 0x119, 0);
            getLActions(obj, obj, 0x15b, 0, 0, 0);
            getLActions(obj, obj, 0x15c, 0, 0, 0);
            getLActions(obj, obj, 0x17c, 0, 0, 0);
            getLActions(obj, obj, 0x17b, 0, 0, 0);
            (*gCloudActionInterface)->func09Nop(1);
            ((GameObject*)obj)->unkF4 = 1;
        }
        break;
    case 4:
        fn_801AC108(obj, (int*)extra);
        break;
    case 5:
        if ((extra->latchFlags & 1) != 0)
        {
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 3, 0);
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 4, 0);
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 6, 0);
            MEVT_TRIGGER(((GameObject *)obj)->anim.mapEventSlot, 7, 0);
            extra->eventState = 0;
            MEVT_SET(((GameObject *)obj)->anim.mapEventSlot, 2);
        }
        break;
    case 6:
        if ((extra->latchFlags & 1) != 0)
        {
            extra->warpCountdown = 2;
        }
        if (extra->warpCountdown > 0)
        {
            if (--extra->warpCountdown == 0)
            {
                GameBit_Set(0x4e5, 0);
                warpToMap(0x1a, 0);
            }
        }
        break;
    }
}
#undef MEVT_TRIGGER
#undef MEVT_SET

/* imicemountain_update: lazy-spawn the ambient effects, run the active state,
 * fade the warning timer, drive the music latch, then refresh the gamebit latches. */
void imicemountain_update(int* obj)
{
    IMIceMountainState* extra = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->unkF4 == 0)
    {
        getEnvfxAct(obj, obj, 0xa3, 0);
        getEnvfxAct(obj, obj, 0x9e, 0);
        getEnvfxAct(obj, obj, 0x104, 0);
        (*gCloudActionInterface)->func09Nop(1);
        ((GameObject*)obj)->unkF4 = 1;
    }
    switch (extra->mapEventState)
    {
    case 1:
        imicemountain_updateEventState(obj);
        break;
    case 2:
        if (GameBit_Get(0x3a3) != 0)
        {
            fn_801AC01C(obj);
        }
        break;
    case 3:
    case 4:
        break;
    }
    extra->latchFlags &= ~1;
    if (extra->warningTextTimer > lbl_803E46DC)
    {
        gameTextSetColor(255, 255, 255, 255);
        gameTextShow(0x351);
        extra->warningTextTimer = extra->warningTextTimer - timeDelta;
        if (extra->warningTextTimer < *(f32*)&lbl_803E46DC)
        {
            extra->warningTextTimer = lbl_803E46DC;
        }
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0)
    {
        if (extra->musicTrack != -1)
        {
            extra->musicTrack = -1;
            if ((extra->latchFlags & 8) != 0)
            {
                Music_Trigger(MUSICTRIG_galleon_docks, 0);
            }
        }
    }
    else
    {
        if (extra->musicTrack != 26)
        {
            extra->musicTrack = 26;
            if ((extra->latchFlags & 8) != 0)
            {
                Music_Trigger(MUSICTRIG_galleon_docks, 1);
            }
        }
    }
    SCGameBitLatch_Update(&extra->latchFlags, 2, 705, 568, 493, 178);
    SCGameBitLatch_Update(&extra->latchFlags, 16, 442, 441, 470, 180);
    SCGameBitLatch_Update(&extra->latchFlags, 4, -1, -1, 928, 233);
    SCGameBitLatch_Update(&extra->latchFlags, 8, -1, -1, 929, extra->musicTrack);
}
