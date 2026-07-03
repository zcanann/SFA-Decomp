/*
 * shlevelcontrol (DLL 0x1AE) - the SnowHorn / ThornTail Hollow area level
 * controller object.
 *
 * sh_levelcontrol_update is the area's per-frame script driver: it keeps
 * the day/night music in sync (SH_LevelControl_setMusic + the
 * SCGameBitLatch helpers), mirrors a set of game bits onto map-event
 * object-group statuses, and dispatches the active sub-event by the
 * map-event act (unk5): early cutscenes, the ThornTail egg events, the
 * timed "bloop" collection minigame (air meter), and the env-fx / sky
 * weather sets. SH_LevelControl_SeqFn handles the totem-log-puzzle map
 * teardown. init seeds the music latches and clears the bloop bits.
 */
#include "main/game_ui_interface.h"
#include "main/dll/SC/SClantern.h"
#include "main/dll/SC/SCtotemlogpuz.h"
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/dll/SP/SPshopkeeper.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/music_trigger_ids.h"
extern void envFxActFn_800887f8(u8 value);
extern int mapUnload(int mapId, int flags);
extern u64 FUN_80286838();
extern u32 FUN_80286884();
extern u32 countLeadingZeros();
extern char sSPShopNumBloopsFormat[];
extern f32 lbl_803E54B0;
extern f32 lbl_803E54B4;
extern f32 timeDelta;
extern void fn_80137948(char* fmt, ...);

extern int ObjList_FindObjectById(int objectId);
extern int isScreenTransitionActive(void);
extern void padClearAnalogInputX(int port);
extern void padClearAnalogInputY(int port);
extern void buttonDisable(int port, u32 mask);
extern int playerHasSpell(int obj, int spell);
extern void gameTextShow(int a);
extern void fn_80088870(void* a, void* b, void* c, void* d);
extern void skyFn_80088e54(int mode, f32 brightness);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern int getEnvfxActImmediately(int a, int b, u16 idx, int d);
extern int getSaveGameLoadStatus(void);
extern void timeOfDayFn_80055000(void);
extern f32 lbl_803E54C0;

#define PAD_BUTTON_A 0x100
#define PAD_BUTTON_B 0x200
#define PAD_BUTTON_MENU 0x1000

int sh_levelcontrol_getExtraSize(void)
{
    return 0x14;
}

void sh_levelcontrol_free(void)
{

    envFxActFn_800887f8(0);
    if (GameBit_Get(0x13F) == 0)
    {
        (*gGameUIInterface)->airMeterShutdown();
    }
    if (GameBit_Get(0x193) != 0)
    {
        GameBit_Set(0x194, 0);
    }
}

#define SCTOTEMLOGPUZ_RESET_GAMEBIT 0xBF8
#define SCTOTEMLOGPUZ_EVENT_COUNTDOWN_RESET 5
#define SCTOTEMLOGPUZ_EVENT_COUNTDOWN_ENABLE 1
#define SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS 0x20000000

int SH_LevelControl_SeqFn(void* obj, void* unused, SCTotemLogPuzzleUpdateState* updateState)
{
    extern void SH_LevelControl_setMusic(void* p);
    SCTotemLogPuzzleObject* puzzleObj;
    int i;
    puzzleObj = (SCTotemLogPuzzleObject*)obj;
    i = 0;
    while (i < updateState->eventCount)
    {
        switch (*(u8*)&updateState->eventHandled[i])
        {
        case 0:
            SH_LevelControl_setMusic(puzzleObj->runtime);
            break;
        }
        i++;
    }
    mapUnloadFn_801d7c94(obj, puzzleObj->runtime);
    return 0;
}

#pragma dont_inline on
void mapUnloadFn_801d7c94(void* obj, void* p2)
{

    SCTotemLogPuzzleObject* puzzleObj;
    SCTotemLogPuzzleRuntime* runtime;
    puzzleObj = (SCTotemLogPuzzleObject*)obj;
    runtime = (SCTotemLogPuzzleRuntime*)p2;

    if ((u32)GameBit_Get(SCTOTEMLOGPUZ_RESET_GAMEBIT) != 0)
    {
        runtime->eventCountdown = SCTOTEMLOGPUZ_EVENT_COUNTDOWN_RESET;
        GameBit_Set(SCTOTEMLOGPUZ_RESET_GAMEBIT, 0);
    }
    if (runtime->eventCountdown == 0) return;

    if (runtime->eventCountdown == SCTOTEMLOGPUZ_EVENT_COUNTDOWN_RESET)
    {
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 1, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 4, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 6, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 7, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 8, 0);
        (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 9, 0);
        mapUnload(0x13, SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS);
        mapUnload(0x41, SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS);
        mapUnload(0x43, SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS);
        mapUnload(0x45, SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS);
    }
    if (runtime->eventCountdown != SCTOTEMLOGPUZ_EVENT_COUNTDOWN_ENABLE)
    {
        goto dec;
    }
    (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 0, 1);
    (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 2, 1);
    (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 3, 1);
    (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 5, 1);
    (*gMapEventInterface)->setObjGroupStatus(puzzleObj->animId, 0xa, 1);
dec:
    runtime->eventCountdown--;
}
#pragma dont_inline reset

#pragma opt_common_subs off
void SCGameBitLatch_Update(SCGameBitLatchState* state, int mask, s16 clearIfSetBit,
                           s16 clearIfClearBit, s16 latchBit, int musicId)
{

    extern void Music_Trigger(int id, int arg);

    int hasClearIfSetBit = (-1 - clearIfSetBit) | (clearIfSetBit + 1);
    int hasClearIfClearBit = (-1 - clearIfClearBit) | (clearIfClearBit + 1);
    u8 clearIfSetBitValid = (u8)((u32)hasClearIfSetBit >> 31);
    u8 clearIfClearBitValid = (u8)((u32)hasClearIfClearBit >> 31);

    if ((state->activeMask & mask) != 0)
    {
        if (clearIfSetBitValid == 0 || GameBit_Get(clearIfSetBit) == 0)
        {
            if (GameBit_Get(latchBit) != 0) goto end;
        }
        if (clearIfSetBitValid != 0)
        {
            GameBit_Set(clearIfSetBit, 0);
        }
        if (clearIfClearBitValid != 0)
        {
            GameBit_Set(clearIfClearBit, 0);
        }
        GameBit_Set(latchBit, 0);
        if (musicId != -1)
        {
            Music_Trigger(musicId, 0);
        }
        state->activeMask = state->activeMask & ~mask;
    }
    else
    {
        if (clearIfClearBitValid == 0 || GameBit_Get(clearIfClearBit) == 0)
        {
            if (GameBit_Get(latchBit) == 0) goto end;
        }
        if (clearIfSetBitValid != 0)
        {
            GameBit_Set(clearIfSetBit, 0);
        }
        if (clearIfClearBitValid != 0)
        {
            GameBit_Set(clearIfClearBit, 0);
        }
        GameBit_Set(latchBit, 1);
        if (musicId != -1)
        {
            Music_Trigger(musicId, 1);
        }
        state->activeMask = state->activeMask | mask;
    }
end:
    return;
}

#pragma opt_common_subs reset
void SCGameBitLatch_UpdateInverted(SCGameBitLatchState* state, int mask, s16 clearIfSetBit,
                                   s16 clearIfClearBit, s16 latchBit, int musicId)
{

    GameBit_Set(latchBit, !GameBit_Get(latchBit));
    SCGameBitLatch_Update(state, mask, clearIfSetBit, clearIfClearBit, latchBit, musicId);
    GameBit_Set(latchBit, !GameBit_Get(latchBit));
}

#pragma dont_inline on
void SH_LevelControl_setMusic(short* obj)
{

    extern void Music_Trigger(int id, int arg);
    extern void SH_LevelControl_setMusic(void* p);

    if ((*gSkyInterface)->getSunPosition(0) != 0)
    {
        if (obj[8] == 0x39 || obj[8] == -1)
        {
            obj[8] = 0x2d;
            if ((*(int*)obj & 1) != 0)
            {
                Music_Trigger(MUSICTRIG_nightjungle, 0);
                Music_Trigger(MUSICTRIG_PU1_Mysterious, 1);
            }
        }
        if (obj[9] == 0xc2 || obj[9] == -1)
        {
            obj[9] = 0xce;
            if ((*(int*)obj & 2) != 0)
            {
                Music_Trigger(MUSICTRIG_cldrnr_walkabout, 0);
                Music_Trigger(MUSICTRIG_CRF_Swim, 1);
            }
        }
    }
    else
    {
        if (obj[8] == 0x2d || obj[8] == -1)
        {
            obj[8] = 0x39;
            if ((*(int*)obj & 1) != 0)
            {
                Music_Trigger(MUSICTRIG_PU1_Mysterious, 0);
                Music_Trigger(MUSICTRIG_nightjungle, 1);
            }
        }
        if (obj[9] == 0xce || obj[9] == -1)
        {
            obj[9] = 0xc2;
            if ((*(int*)obj & 2) != 0)
            {
                Music_Trigger(MUSICTRIG_CRF_Swim, 0);
                Music_Trigger(MUSICTRIG_cldrnr_walkabout, 1);
            }
        }
    }
    if (GameBit_Get(0xb) != 0)
    {
        if (GameBit_Get(0x64b) != 0)
        {
            GameBit_Set(0x390, 1);
        }
        SCGameBitLatch_Update((SCGameBitLatchState*)obj, 1, 0x1a7, 0x64b, 0x372, obj[8]);
        SCGameBitLatch_Update((SCGameBitLatchState*)obj, 2, 0x1a8, 0xc0, 0x390, obj[9]);
        SCGameBitLatch_Update((SCGameBitLatchState*)obj, 4, -1, -1, 0x393, 0x36);
        SCGameBitLatch_Update((SCGameBitLatchState*)obj, 8, -1, -1, 0xa32, 0x98);
        SCGameBitLatch_Update((SCGameBitLatchState*)obj, 0x10, -1, -1, 0xbfe, 0xc3);
    }
}
#pragma dont_inline reset

typedef struct ShLevelcontrolState
{
    u32 flags; /* flag word; bit 2 cleared on substate transitions */
    u8 waitCounter; /* counter incremented before a gated action fires */
    u8 mapAct; /* map-event act selecting the active sub-event handler */
    u8 eventState; /* bloop-event substate machine 0..7 */
    u8 pad7;
    f32 timer8; /* air-meter countdown */
    f32 hudTextTimer; /* countdown for the on-screen hint text */
    s16 unk10;
    s16 musicLatch; /* current map music/ambient id latch (0xcc/0xf2/0xdb/-1) */
    u8 pad14[0x18 - 0x14];
} ShLevelcontrolState;

STATIC_ASSERT(offsetof(ShLevelcontrolState, waitCounter) == 0x4);
STATIC_ASSERT(offsetof(ShLevelcontrolState, eventState) == 0x6);
STATIC_ASSERT(offsetof(ShLevelcontrolState, timer8) == 0x8);
STATIC_ASSERT(offsetof(ShLevelcontrolState, hudTextTimer) == 0xC);
STATIC_ASSERT(offsetof(ShLevelcontrolState, musicLatch) == 0x12);

#pragma dont_inline on
void SH_LevelControl_runBloopEvent(int obj, int state)
{
    extern s16 lbl_80327618[];
    extern void* Obj_GetPlayerObject(void);

    int player;
    u8 i;
    u8 bloopsRemaining;
    u8 j;

    if (((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0) == 0) &&
        (GameBit_Get(0x13f) == 0))
    {
        ((ShLevelcontrolState*)state)->eventState = 0;
        (*gGameUIInterface)->airMeterShutdown();
        for (j = 0; j < 0x12; j++)
        {
            GameBit_Set(lbl_80327618[j], 0);
        }
    }

    player = (int)Obj_GetPlayerObject();
    switch (((ShLevelcontrolState*)state)->eventState)
    {
    case 0:
        if (GameBit_Get(0x13f) != 0)
        {
            ((ShLevelcontrolState*)state)->eventState = 7;
        }
        else
        {
            ((ShLevelcontrolState*)state)->eventState = 1;
        }
        break;
    case 1:
        if (GameBit_Get(0x124) != 0)
        {
            (*gMapEventInterface)->savePoint(player + 0xc, ((GameObject*)player)->anim.rotX, 1, 0);
            ((ShLevelcontrolState*)state)->timer8 = lbl_803E54B0;
            (*gGameUIInterface)->initAirMeter(100000, 0x5db);
            ((ShLevelcontrolState*)state)->eventState = 2;
        }
        break;
    case 2:
        bloopsRemaining = 0x12;
        for (i = 0; i < 0x12; i++)
        {
            if (GameBit_Get(lbl_80327618[i]) != 0)
            {
                bloopsRemaining--;
            }
        }
        fn_80137948(sSPShopNumBloopsFormat, bloopsRemaining);
        if (bloopsRemaining == 0)
        {
            (*gGameUIInterface)->airMeterShutdown();
            (*gScreenTransitionInterface)->start(0x14, 1);
            ((ShLevelcontrolState*)state)->eventState = 3;
            Sfx_PlayFromObject(0, SFXmn_sml_trex_fstep);
        }
        else
        {
            ((ShLevelcontrolState*)state)->timer8 -= bloopsRemaining * timeDelta;
            if (((ShLevelcontrolState*)state)->timer8 >= lbl_803E54B4)
            {
                (*gGameUIInterface)->runAirMeter((int)((ShLevelcontrolState*)state)->timer8);
            }
            else if ((u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0) != 0)
            {
                (*gGameUIInterface)->airMeterShutdown();
                (*gScreenTransitionInterface)->start(0x14, 1);
                ((ShLevelcontrolState*)state)->eventState = 5;
            }
            else
            {
                ((ShLevelcontrolState*)state)->timer8 = lbl_803E54B4;
                (*gGameUIInterface)->runAirMeter(1);
            }
        }
        break;
    case 3:
        if (((*gScreenTransitionInterface)->isFinished() != 0) &&
            ((((GameObject*)Obj_GetPlayerObject())->objectFlags & 0x1000) == 0))
        {
            GameBit_Set(0x13f, 1);
            (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
            ((ShLevelcontrolState*)state)->eventState = 4;
        }
        break;
    case 4:
        ((ShLevelcontrolState*)state)->eventState = 7;
        break;
    case 5:
        if (((*gScreenTransitionInterface)->isFinished() != 0) &&
            ((((GameObject*)Obj_GetPlayerObject())->objectFlags & 0x1000) == 0))
        {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
            ((ShLevelcontrolState*)state)->eventState = 6;
        }
        break;
    case 6:
        (*gMapEventInterface)->gotoRestartPoint();
        break;
    case 7:
        if (GameBit_Get(0xea6) == 0)
        {
            GameBit_Set(0xea6, 1);
            if (GameBit_Get(0x1a2) == 0)
            {
                GameBit_Set(0x9d5, 1);
            }
        }
        break;
    }

    if (((ShLevelcontrolState*)state)->eventState == 2)
    {
        if (((ShLevelcontrolState*)state)->musicLatch != 0xf2)
        {
            ((ShLevelcontrolState*)state)->musicLatch = 0xf2;
            GameBit_Set(0xc0, 1);
            ((ShLevelcontrolState*)state)->flags &= ~2;
        }
    }
    else if (((ShLevelcontrolState*)state)->musicLatch != 0xcc)
    {
        ((ShLevelcontrolState*)state)->musicLatch = 0xcc;
        GameBit_Set(0xc0, 1);
        ((ShLevelcontrolState*)state)->flags &= ~2;
    }

    if ((GameBit_Get(0xea8) == 0) && (GameBit_Get(0x91b) != 0))
    {
        GameBit_Set(0xea8, 1);
        (*gMapEventInterface)->savePoint(0, 0, 1, 0);
    }
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
#define SHOPKEEPER_THORNTAIL_OBJECT_ID 0x442ff
#define SHOPKEEPER_OBJFLAG_REFRESH_MAP 0x2
#define SHOPKEEPER_OBJFLAG_THORNTAIL_TRIGGERED 0x40
#define SHOPKEEPER_OBJFLAG_EARLY_SCENE_STARTED 0x80
#define SHOPKEEPER_LOADING_FLAG 0x1000
#define SHOPKEEPER_OBJFLAG_HIDDEN 0x4000

typedef struct ShopkeeperObject
{
    u8 unk0[0xac];
    s8 mapId;
    u8 unkAD[3];
    u16 flagsB0;
} ShopkeeperObject;

#define OBJECT_TRIGGER_REFRESH(triggerId, obj, arg) \
    (*gObjectTriggerInterface)->runSequence((triggerId), (void *)(obj), (arg))
#define SCREEN_TRANSITION_START(transitionId, value) \
    (*gScreenTransitionInterface)->start((transitionId), (value))
#define SCREEN_TRANSITION_FINISHED() \
    (*gScreenTransitionInterface)->isFinished()
#define MAP_EVENT_TRIGGER(mapId, eventId, value, arg) \
    (*gMapEventInterface)->savePoint((mapId), (eventId), (value), (arg))
#define MAP_EVENT_GET_ANIM(mapId, eventId) \
    (*gMapEventInterface)->getObjGroupStatus((mapId), (eventId))
#define MAP_EVENT_SET_ANIM(mapId, eventId, value) \
    (*gMapEventInterface)->setObjGroupStatus((mapId), (eventId), (value))
#define SHOPKEEPER_APPLY_MAP_OVERRIDE(state, enabledBit)      \
    if (GameBit_Get((enabledBit)) != 0) {                     \
        if ((state)->mapOverride != 0xcc) {                   \
            (state)->mapOverride = 0xcc;                      \
            GameBit_Set(0xc0, 1);                             \
            (state)->flags &= ~SHOPKEEPER_OBJFLAG_REFRESH_MAP;\
        }                                                     \
    } else if ((state)->mapOverride == 0xcc) {                \
        (state)->mapOverride = -1;                            \
    }

#pragma scheduling off
#pragma peephole off
void SH_LevelControl_doThornTailEvents(int obj, ShopkeeperLevelControlState* state)
{
    extern int Obj_GetPlayerObject(void);

    ShopkeeperObject* thornTailObj;
    ShopkeeperObject* playerObj;

    SHOPKEEPER_APPLY_MAP_OVERRIDE(state, 0x193);

    switch (state->thornTailState)
    {
    case 0:
        if (GameBit_Get(0xd39) != 0)
        {
            state->thornTailState = 7;
        }
        else
        {
            OBJECT_TRIGGER_REFRESH(5, obj, -1);
            state->thornTailState = 1;
        }
        break;
    case 1:
        thornTailObj = (ShopkeeperObject*)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
        if ((thornTailObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0)
        {
            playerObj = (ShopkeeperObject*)Obj_GetPlayerObject();
            if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0)
            {
                OBJECT_TRIGGER_REFRESH(6, obj, -1);
                state->thornTailState = 7;
                GameBit_Set(0xd39, 1);
            }
        }
        break;
    case 7:
        break;
    }

    if ((state->flags & SHOPKEEPER_OBJFLAG_THORNTAIL_TRIGGERED) == 0 &&
        GameBit_Get(0x190) != 0 &&
        GameBit_Get(0x191) != 0 &&
        GameBit_Get(0x192) != 0)
    {
        if (GameBit_Get(0x193) == 0)
        {
            thornTailObj = (ShopkeeperObject*)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
            if (thornTailObj != 0)
            {
                playerObj = (ShopkeeperObject*)Obj_GetPlayerObject();
                if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0)
                {
                    if (isScreenTransitionActive() != 0)
                    {
                        GameBit_Set(0x193, 1);
                        OBJECT_TRIGGER_REFRESH(1, obj, -1);
                        state->flags |= SHOPKEEPER_OBJFLAG_THORNTAIL_TRIGGERED;
                    }
                    else
                    {
                        GameBit_Set(0x193, 1);
                        SCREEN_TRANSITION_START(0x14, 1);
                    }
                }
            }
        }
        else if (SCREEN_TRANSITION_FINISHED() != 0)
        {
            thornTailObj = (ShopkeeperObject*)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
            if (thornTailObj != 0)
            {
                playerObj = (ShopkeeperObject*)Obj_GetPlayerObject();
                if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0)
                {
                    OBJECT_TRIGGER_REFRESH(1, obj, -1);
                    state->flags |= SHOPKEEPER_OBJFLAG_THORNTAIL_TRIGGERED;
                }
            }
        }
    }

    if (GameBit_Get(0xea9) == 0 && GameBit_Get(0x611) != 0)
    {
        GameBit_Set(0xea9, 1);
        MAP_EVENT_TRIGGER(0, 0, 1, 0);
    }
}

void SH_LevelControl_doEarlyScenes(int obj, ShopkeeperLevelControlState* state)
{
    extern int Obj_GetPlayerObject(void);

    ShopkeeperObject* playerObj;

    SHOPKEEPER_APPLY_MAP_OVERRIDE(state, 0x1ab);

    if (state->earlySceneDelay >= 2)
    {
        if (GameBit_Get(0xb) == 0)
        {
            padClearAnalogInputX(0);
            padClearAnalogInputY(0);
            buttonDisable(0, PAD_BUTTON_A);
            buttonDisable(0, PAD_BUTTON_B);
            buttonDisable(0, PAD_BUTTON_MENU);
            playerObj = (ShopkeeperObject*)Obj_GetPlayerObject();
            if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0)
            {
                OBJECT_TRIGGER_REFRESH(0, obj, -1);
                GameBit_Set(0xb, 1);
            }
        }

        if ((state->flags & SHOPKEEPER_OBJFLAG_EARLY_SCENE_STARTED) == 0)
        {
            GameBit_Set(0x2ba, 0);
            state->flags |= SHOPKEEPER_OBJFLAG_EARLY_SCENE_STARTED;
        }
    }
    else
    {
        state->earlySceneDelay++;
    }

    if (GameBit_Get(0x2da) == 0 &&
        GameBit_Get(0x34a) != 0 &&
        GameBit_Get(0x36f) != 0 &&
        GameBit_Get(0x166) != 0 &&
        GameBit_Get(0x167) != 0)
    {
        playerObj = (ShopkeeperObject*)Obj_GetPlayerObject();
        if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0)
        {
            GameBit_Set(0x2da, 1);
        }
    }

    if ((u8)MAP_EVENT_GET_ANIM(((ShopkeeperObject *)obj)->mapId, 6) == 0)
    {
        playerObj = (ShopkeeperObject*)Obj_GetPlayerObject();
        if (playerHasSpell((int)playerObj, 0) != 0)
        {
            MAP_EVENT_SET_ANIM(((ShopkeeperObject *)obj)->mapId, 6, 1);
        }
    }
}

void sh_levelcontrol_update(int obj)
{
    extern u8 lbl_80327618[0x104];
    extern void SH_LevelControl_doEarlyScenes(int obj, u32* state);
    extern void SH_LevelControl_doThornTailEvents(int obj, u32* state);
    extern void SH_LevelControl_runBloopEvent(int obj, u32* state);
    extern int Obj_GetPlayerObject(void);
    extern void SH_LevelControl_setMusic(u32 * state);

    u32* state;
    u32 val;
    u32 val2;
    u32 val3;
    u8 animEvt;
    u8* base = lbl_80327618;

    state = ((GameObject*)obj)->extra;
    if (((ShLevelcontrolState*)state)->hudTextTimer > lbl_803E54B4)
    {
        gameTextShow(0x3f6);
        ((ShLevelcontrolState*)state)->hudTextTimer = ((ShLevelcontrolState*)state)->hudTextTimer - timeDelta;
        if (((ShLevelcontrolState*)state)->hudTextTimer < *(f32*)&lbl_803E54B4)
        {
            ((ShLevelcontrolState*)state)->hudTextTimer = lbl_803E54B4;
        }
    }
    SH_LevelControl_setMusic(state);
    val = GameBit_Get(0x3aa);
    if (val != 0)
    {
        if (((GameObject*)obj)->anim.mapEventSlot == 8)
        {
            animEvt = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1d);
            if (animEvt == '\0')
            {
                (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1d, 1);
            }
        }
        else
        {
            animEvt = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1d);
            if (animEvt != '\0')
            {
                (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1d, 0);
            }
        }
    }
    val = GameBit_Get(0x3b8);
    if (val != 0)
    {
        animEvt = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1c);
        if (animEvt == '\0')
        {
            (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1c, 1);
        }
    }
    else
    {
        animEvt = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1c);
        if (animEvt != '\0')
        {
            (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1c, 0);
        }
    }
    val = GameBit_Get(999);
    if ((val != 0) &&
        (animEvt = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1b),
            animEvt == '\0'))
    {
        (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1b, 1);
    }
    val = GameBit_Get(0x11);
    if (val != 0)
    {
        animEvt = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1a);
        if (animEvt == '\0')
        {
            (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1a, 1);
        }
    }
    else
    {
        animEvt = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1a);
        if (animEvt != '\0')
        {
            (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1a, 0);
        }
    }
    switch (((ShLevelcontrolState*)state)->mapAct)
    {
    case 1:
        SH_LevelControl_doEarlyScenes(obj, state);
        break;
    case 2:
        val = GameBit_Get(0xbf);
        if ((val != 0) && (val3 = GameBit_Get(0xc2), val3 < 6))
        {
            if (((ShLevelcontrolState*)state)->musicLatch != 0xdb)
            {
                ((ShLevelcontrolState*)state)->musicLatch = 0xdb;
                GameBit_Set(0xc0, 1);
                ((ShLevelcontrolState*)state)->flags = ((ShLevelcontrolState*)state)->flags & 0xfffffffd;
            }
        }
        else
        {
            val = GameBit_Get(0xc2);
            if ((val == 6) && (((ShLevelcontrolState*)state)->musicLatch != 0xcc))
            {
                ((ShLevelcontrolState*)state)->musicLatch = 0xcc;
                GameBit_Set(0xc0, 1);
                ((ShLevelcontrolState*)state)->flags = ((ShLevelcontrolState*)state)->flags & 0xfffffffd;
            }
        }
        val = GameBit_Get(0xc2);
        val2 = GameBit_Get(0x66d);
        if ((val2 + val == 6) && (val = GameBit_Get(0xe5b), val == 0))
        {
            Sfx_PlayFromObject(obj, SFXmn_sml_trex_fstep);
            GameBit_Set(0xe5b, 1);
        }
        break;
    case 3:
        SH_LevelControl_doThornTailEvents(obj, state);
        break;
    case 4:
        if (((ShLevelcontrolState*)state)->musicLatch != 0xcc)
        {
            ((ShLevelcontrolState*)state)->musicLatch = 0xcc;
            GameBit_Set(0xc0, 1);
            ((ShLevelcontrolState*)state)->flags = ((ShLevelcontrolState*)state)->flags & 0xfffffffd;
        }
        if (((ShLevelcontrolState*)state)->waitCounter >= 2)
        {
            val = GameBit_Get(0xdff);
            if (val == 0)
            {
                padClearAnalogInputX(0);
                padClearAnalogInputY(0);
                buttonDisable(0, PAD_BUTTON_A);
                buttonDisable(0, PAD_BUTTON_B);
                buttonDisable(0, PAD_BUTTON_MENU);
                val = Obj_GetPlayerObject();
                if ((((GameObject*)val)->objectFlags & 0x1000) == 0)
                {
                    (*gObjectTriggerInterface)->runSequence(7, (void*)obj, 0xffffffff);
                    GameBit_Set(0xdff, 1);
                }
            }
            else
            {
                val = GameBit_Get(0xede);
                if (val == 0)
                {
                    GameBit_Set(0xede, 1);
                    GameBit_Set(0x9d5, 1);
                }
            }
        }
        else
        {
            ((ShLevelcontrolState*)state)->waitCounter += 1;
        }
        break;
    case 5:
        val = GameBit_Get(0x23c);
        if (val != 0)
        {
            if (((ShLevelcontrolState*)state)->musicLatch != 0xcc)
            {
                ((ShLevelcontrolState*)state)->musicLatch = 0xcc;
                GameBit_Set(0xc0, 1);
                ((ShLevelcontrolState*)state)->flags = ((ShLevelcontrolState*)state)->flags & 0xfffffffd;
            }
        }
        else if (((ShLevelcontrolState*)state)->musicLatch == 0xcc)
        {
            ((ShLevelcontrolState*)state)->musicLatch = -1;
        }
        val = GameBit_Get(0x90);
        if (((val != 0) && (val = GameBit_Get(0xeb3), val == 0)) &&
            (val = Obj_GetPlayerObject(), (((GameObject*)val)->objectFlags & 0x1000) == 0))
        {
            GameBit_Set(0xeb3, 1);
        }
        break;
    case 6:
        SH_LevelControl_runBloopEvent(obj, state);
        break;
    case 7:
        val = GameBit_Get(0x1a0);
        if (val != 0)
        {
            if (((ShLevelcontrolState*)state)->musicLatch != 0xcc)
            {
                ((ShLevelcontrolState*)state)->musicLatch = 0xcc;
                GameBit_Set(0xc0, 1);
                ((ShLevelcontrolState*)state)->flags = ((ShLevelcontrolState*)state)->flags & 0xfffffffd;
            }
        }
        else if (((ShLevelcontrolState*)state)->musicLatch == 0xcc)
        {
            ((ShLevelcontrolState*)state)->musicLatch = -1;
        }
        if (((ShLevelcontrolState*)state)->waitCounter >= 2)
        {
            val = GameBit_Get(0x177);
            if (val == 0)
            {
                padClearAnalogInputX(0);
                padClearAnalogInputY(0);
                buttonDisable(0, PAD_BUTTON_A);
                buttonDisable(0, PAD_BUTTON_B);
                buttonDisable(0, PAD_BUTTON_MENU);
                val = Obj_GetPlayerObject();
                if ((((GameObject*)val)->objectFlags & 0x1000) == 0)
                {
                    (*gObjectTriggerInterface)->runSequence(4, (void*)obj, 0xffffffff);
                    GameBit_Set(0x177, 1);
                }
            }
        }
        else
        {
            ((ShLevelcontrolState*)state)->waitCounter += 1;
        }
        break;
    case 8:
        if (((ShLevelcontrolState*)state)->musicLatch != 0xcc)
        {
            ((ShLevelcontrolState*)state)->musicLatch = 0xcc;
            GameBit_Set(0xc0, 1);
            ((ShLevelcontrolState*)state)->flags = ((ShLevelcontrolState*)state)->flags & 0xfffffffd;
        }
        val = GameBit_Get(0x19c);
        if ((val != 0) && (val = GameBit_Get(0xf3e), val == 0))
        {
            GameBit_Set(0xf3e, 1);
            val = GameBit_Get(0xc64);
            if (val == 0)
            {
                GameBit_Set(0x9d5, 1);
            }
        }
    }
    val = GameBit_Get(0xd36);
    if (val != 0)
    {
        if (((GameObject*)obj)->unkF8 != 2)
        {
            ((GameObject*)obj)->unkF8 = 2;
            envFxActFn_800887f8(0);
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(0, 0, 0x1bf, 0);
                getEnvfxActImmediately(0, 0, 0x231, 0);
                getEnvfxActImmediately(0, 0, 0x232, 0);
                getEnvfxActImmediately(0, 0, 0x244, 0);
            }
            else
            {
                getEnvfxAct(0, 0, 0x1bf, 0);
                getEnvfxAct(0, 0, 0x231, 0);
                getEnvfxAct(0, 0, 0x232, 0);
                getEnvfxAct(0, 0, 0x244, 0);
            }
        }
    }
    else
    {
        val = GameBit_Get(0xd35);
        if (val != 0)
        {
            if (((GameObject*)obj)->unkF8 != 1)
            {
                ((GameObject*)obj)->unkF8 = 1;
                if (((GameObject*)obj)->unkF4 == 2)
                {
                    envFxActFn_800887f8(0);
                    getEnvfxActImmediately(0, 0, 0x1bf, 0);
                    getEnvfxActImmediately(0, 0, 0x1be, 0);
                    getEnvfxActImmediately(0, 0, 0x1c0, 0);
                    getEnvfxActImmediately(0, 0, 0x244, 0);
                }
                else
                {
                    envFxActFn_800887f8(0);
                    getEnvfxAct(0, 0, 0x1bf, 0);
                    getEnvfxAct(0, 0, 0x1be, 0);
                    getEnvfxAct(0, 0, 0x1c0, 0);
                    getEnvfxAct(0, 0, 0x244, 0);
                }
            }
        }
        else if (((GameObject*)obj)->unkF8 != 0)
        {
            ((GameObject*)obj)->unkF8 = 0;
            if (((GameObject*)obj)->unkF4 == 2)
            {
                fn_80088870(&base[0x5c], &base[0x24], &base[0x94], &base[0xcc]);
                envFxActFn_800887f8(0x3f);
                getEnvfxActImmediately(0, 0, 0x244, 0);
                skyFn_80088e54(0, lbl_803E54B4);
            }
            else
            {
                fn_80088870(&base[0x5c], &base[0x24], &base[0x94], &base[0xcc]);
                envFxActFn_800887f8(0x1f);
                getEnvfxAct(0, 0, 0x244, 0);
            }
        }
    }
    mapUnloadFn_801d7c94((void*)obj, state);
    return;
}

void sh_levelcontrol_init(int obj)
{

    extern void Music_Trigger(int id, int arg);

    int* state = ((GameObject*)obj)->extra;
    int i;
    u32 v;

    ((GameObject*)obj)->animEventCallback = SH_LevelControl_SeqFn;
    v = (u32)((GameObject*)obj)->objectFlags | SHOPKEEPER_OBJFLAG_HIDDEN;
    ((GameObject*)obj)->objectFlags = v;
    ((GameObject*)obj)->unkF8 = 3;

    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }

    ((ShLevelcontrolState*)state)->unk10 = -1;
    ((ShLevelcontrolState*)state)->hudTextTimer = lbl_803E54C0;

    if (GameBit_Get(0x611) != 0)
    {
        *(int*)state |= 0x40;
    }

    ((ShLevelcontrolState*)state)->mapAct = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);

    ((ShLevelcontrolState*)state)->musicLatch = -1;
    Music_Trigger(MUSICTRIG_fox_arwing, 0);
    Music_Trigger(MUSICTRIG_Barrels, 0);
    Music_Trigger(MUSICTRIG_PU3_Adventure_b2, 0);
    Music_Trigger(MUSICTRIG_PU3_Adventure_c4, 0);
    Music_Trigger(MUSICTRIG_wcity_day, 0);
    Music_Trigger(MUSICTRIG_trex_boss_1, 0);
    Music_Trigger(MUSICTRIG_drako_3, 0);
    GameBit_Set(3213, 1);

    if (GameBit_Get(319) == 0)
    {
        extern s16 lbl_80327618[];
        for (i = 0; i < 18; i++)
        {
            GameBit_Set(lbl_80327618[i], 0);
        }
    }
    timeOfDayFn_80055000();
}
