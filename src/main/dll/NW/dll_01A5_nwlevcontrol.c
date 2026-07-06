/*
 * nwlevcontrol (DLL 0x1A5) - the SnowHorn Wastes level controller (map
 * 'nwastes', 0x0A).
 *
 * Runs the area's overall progression: a countdown that gates a hint
 * message, the day/night music swap driven by the sun position, a set of
 * latched game-bit -> music/sfx reactions (SCGameBitLatch_Update), the
 * timed-challenge timer (init / count-up / stop with the SnowHorn rescue
 * bits 0x19d/0x19f), and a state machine that walks a table of target
 * objects (fn_801CFD68) firing their trigger sequences in turn.
 */
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/flybaddie1D7.h"
#include "main/objseq.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"
extern u32 Music_Trigger();
extern u32 gameTimerIsRunning(void);
extern f32 fn_80014668(void);
extern void timerSetToCountUp(void);
extern void gameTimerInit(s8 flags, int minutes);
extern u32 SCGameBitLatch_Update();

#define NWLEVCONTROL_OBJFLAG_HIDDEN 0x4000
#define NWLEVCONTROL_OBJFLAG_HITDETECT_DISABLED 0x2000

extern void gameTextShow(int a);
extern f32 lbl_803E5278;
extern f32 lbl_803E527C;
extern f32 lbl_803E5280;

extern int isGameTimerDisabled(void);
extern void fn_80088870(char* a, char* b, char* c, char* d);
extern int getSaveGameLoadStatus(void);
extern int getEnvfxActImmediately(int a, int b, u16 idx, int d);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern int ObjList_FindObjectById(int objectId);
extern int ObjTrigger_IsSetById();
extern void gameTimerStop(void);

/* NwLevControlState.mode: SnowHorn Wastes progression state machine.
 * Modes 3..7 are the intermediate table-walk steps (identical handling,
 * driven externally by the target-object trigger sequences) so they stay
 * numeric. */
enum NwLevControlMode
{
    NWLEVCONTROL_MODE_WAIT_START = 0,   /* wait for rescue bit 0x19d, then run seq 0 */
    NWLEVCONTROL_MODE_INIT_START = 1,   /* resumed-start: preempt+run seq, arm progression */
    NWLEVCONTROL_MODE_WALK_TABLE = 2,   /* walk target-object table, arm challenge timer */
    NWLEVCONTROL_MODE_WALK_FINAL = 8,   /* final table check, latch completion flag */
    NWLEVCONTROL_MODE_WAIT_MENU_LOCK = 9, /* wait for the menu-lock flag to be set */
    NWLEVCONTROL_MODE_TIMER_STEP = 10,  /* menu-locked: init/count-up/stop the timer */
    NWLEVCONTROL_MODE_CLEANUP = 0xb,    /* clear game bit 0xecd */
    NWLEVCONTROL_MODE_RESCUE_RETRIGGER = 0xc /* post-rescue re-trigger, then cleanup */
};

/* obj+0xB8 per-class state block (getExtraSize == 0x14). */
typedef struct NwLevControlState
{
    f32 countdown;       /* 0x00 hint-message countdown */
    u8 mode;             /* 0x04 state-machine mode */
    u8 timerMinutes;     /* 0x05 challenge timer minutes */
    u8 pad06[0x08 - 0x06];
    u32 flags;           /* 0x08 progression flag bits */
    u8 seqId;            /* 0x0C trigger sequence id */
    u8 nextMode;         /* 0x0D mode to enter after the timer step */
    u8 tableIndex;       /* 0x0E walk index into the target-object table */
    u8 pad0F[0x10 - 0x0F];
    s16 dayNightMusic;   /* 0x10 day/night music marker */
    u8 pad12[0x14 - 0x12];
} NwLevControlState;
STATIC_ASSERT(sizeof(NwLevControlState) == 0x14);

void nw_levcontrol_update(int objArg)
{
    int obj;
    short* player;
    u8 status;
    int sunPos;
    u32 gameBit;
    u32 rescueBit;
    u8 timerRunning;
    int flags;
    u32 timerActive;
    NwLevControlState* state;

    obj = objArg;
    state = (NwLevControlState*)((GameObject*)obj)->extra;
    player = (short*)Obj_GetPlayerObject();
    if (state->countdown > lbl_803E5278)
    {
        gameTextShow(0x435);
        state->countdown = state->countdown - timeDelta;
        if (state->countdown < lbl_803E5278)
        {
            state->countdown = *(f32 *)&lbl_803E5278;
        }
    }
    status = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    if (status != 1)
    {
        (*gMapEventInterface)->setMapAct((int)((GameObject*)obj)->anim.mapEventSlot, 1);
    }
    status = (*gMapEventInterface)->getMapAct(7);
    if (status == 1)
    {
        (*gMapEventInterface)->setMapAct(7, 2);
        GameBit_Set(0xf22, 1);
        GameBit_Set(0xf23, 1);
        GameBit_Set(0xf24, 1);
        GameBit_Set(0xf25, 1);
    }
    sunPos = (*gSkyInterface)->getSunPosition(0);
    if (sunPos != 0)
    {
        if (state->dayNightMusic != -1)
        {
            state->dayNightMusic = -1;
            if (((int)state->flags & 0x10) != 0)
            {
                Music_Trigger((int*)0x1a, 0);
            }
        }
    }
    else
    {
        if (state->dayNightMusic != 0x1a)
        {
            state->dayNightMusic = 0x1a;
            if (((int)state->flags & 0x10) != 0)
            {
                Music_Trigger((int*)0x1a, 1);
            }
        }
    }
    SCGameBitLatch_Update(&state->flags, 8, -1, -1, 0x3a0, 0x35);
    SCGameBitLatch_Update(&state->flags, 0x10, -1, -1, 0x3a1, (int*)(int)state->dayNightMusic);
    SCGameBitLatch_Update(&state->flags, 0x20, -1, -1, 0x393, 0x36);
    SCGameBitLatch_Update(&state->flags, 0x40, -1, -1, 0xcbb, 0xc4);
    timerActive = 0;
    gameBit = GameBit_Get(0x19f);
    rescueBit = GameBit_Get(0x19d);
    if (((rescueBit ^ gameBit) != 0) && (timerRunning = gameTimerIsRunning(), timerRunning != 0))
    {
        timerActive = 1;
    }
    GameBit_Set(0xf31, timerActive);
    SCGameBitLatch_Update(&state->flags, 0x80, -1, -1, 0xf31, 0xaf);
    gameBit = GameBit_Get(0x398);
    if ((gameBit != 0) &&
        (status = (*gMapEventInterface)->getObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1f), status == 0)
    )
    {
        (*gMapEventInterface)->setObjGroupStatus((int)((GameObject*)obj)->anim.mapEventSlot, 0x1f, 1);
    }
    if ((((int)state->flags & 2) != 0) && isGameTimerDisabled() != 0)
    {
        Sfx_PlayFromObject(0, SFXsc_clubhit02);
        (*gMapEventInterface)->gotoRestartPoint();
    }
    else
    {
        switch (state->mode)
        {
        case NWLEVCONTROL_MODE_WAIT_START:
            gameBit = GameBit_Get(0x19d);
            if (gameBit != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                state->mode = NWLEVCONTROL_MODE_WALK_TABLE;
                GameBit_Set(0xecd, 1);
            }
            break;
        case NWLEVCONTROL_MODE_INIT_START:
            (*gObjectTriggerInterface)->preempt(obj, 0x64a);
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 0x20);
            state->mode = NWLEVCONTROL_MODE_WALK_TABLE;
            GameBit_Set(0xecd, 1);
            break;
        case NWLEVCONTROL_MODE_WALK_TABLE:
            obj = fn_801CFD68((u8*)state);
            if (obj != 0)
            {
                state->timerMinutes = 0x32;
                state->flags = state->flags | 1;
            }
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
            fn_801CFD68((u8*)state);
            break;
        case NWLEVCONTROL_MODE_WALK_FINAL:
            obj = fn_801CFD68((u8*)state);
            if (obj == 1)
            {
                state->flags = state->flags | 4;
            }
            break;
        case NWLEVCONTROL_MODE_WAIT_MENU_LOCK:
            if ((*(u16*)(player + 0x58) & 0x1000) != 0)
            {
                state->mode = NWLEVCONTROL_MODE_TIMER_STEP;
            }
            break;
        case NWLEVCONTROL_MODE_TIMER_STEP:
            if ((*(u16*)(player + 0x58) & 0x1000) == 0)
            {
                flags = state->flags;
                if ((flags & 1) != 0)
                {
                    state->flags = flags & ~1;
                    state->flags = state->flags | 2;
                    gameTimerInit(0x15, (u32)state->timerMinutes);
                    timerSetToCountUp();
                    (*gMapEventInterface)->savePoint((int)(player + 6), (int)*player, 0, 0);
                }
                else if ((flags & 4) != 0)
                {
                    state->flags = flags & ~2;
                    state->flags = state->flags & ~4;
                    gameTimerStop();
                    Music_Trigger((int*)0xaf, 0);
                    GameBit_Set(0x19f, 1);
                }
                else
                {
                    int extra = (int)(fn_80014668() / lbl_803E527C);
                    gameTimerStop();
                    gameTimerInit(0x15, (u32)state->timerMinutes + extra);
                    timerSetToCountUp();
                }
                (*gObjectTriggerInterface)->runSequence(state->seqId, (void*)obj,
                                                        -1);
                state->mode = state->nextMode;
            }
            break;
        case NWLEVCONTROL_MODE_CLEANUP:
            gameBit = GameBit_Get(0xecd);
            if (gameBit != 0)
            {
                GameBit_Set(0xecd, 0);
            }
            break;
        case NWLEVCONTROL_MODE_RESCUE_RETRIGGER:
            (*gObjectTriggerInterface)->preempt(obj, 0x5a);
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, 8);
            state->mode = NWLEVCONTROL_MODE_CLEANUP;
        }
    }
    return;
}

void nw_levcontrol_init(int* obj)
{
    extern void envFxActFn_800887f8(u8 value);
    extern char lbl_803269F8[];
    char* base = lbl_803269F8;
    NwLevControlState* state = ((GameObject*)obj)->extra;

    Obj_GetPlayerObject();
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (NWLEVCONTROL_OBJFLAG_HIDDEN | NWLEVCONTROL_OBJFLAG_HITDETECT_DISABLED));

    if (GameBit_Get(0x19f) != 0)
    {
        state->mode = NWLEVCONTROL_MODE_RESCUE_RETRIGGER;
    }
    else if (GameBit_Get(0x19d) != 0)
    {
        state->mode = NWLEVCONTROL_MODE_INIT_START;
    }
    else
    {
        state->mode = NWLEVCONTROL_MODE_WAIT_START;
    }

    state->countdown = lbl_803E5280;

    fn_80088870(base + 0x8c, base + 0x54, base + 0xc4, base + 0xfc);

    if (getSaveGameLoadStatus() != 0)
    {
        envFxActFn_800887f8(0x3f);
        getEnvfxActImmediately(0, 0, 0x23c, 0);
    }
    else
    {
        envFxActFn_800887f8(0x1f);
        getEnvfxAct(0, 0, 0x23c, 0);
    }

    (*gMapEventInterface)->setObjGroupStatus(7, 0, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 2, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 5, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 10, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 0x1c, 0);
    (*gMapEventInterface)->setObjGroupStatus(7, 9, 1);
}

int fn_801CFD68(u8* stateBytes)
{
    extern s32 lbl_803269F8[];
    NwLevControlState* state = (NwLevControlState*)stateBytes;
    s32* table;
    int obj;

    table = lbl_803269F8;
    obj = ObjList_FindObjectById(table[state->tableIndex]);
    if (ObjTrigger_IsSetById(obj, 0x1ee) != 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        state->mode = NWLEVCONTROL_MODE_WAIT_MENU_LOCK;
        state->seqId = table[state->tableIndex + 7];
        state->nextMode = table[state->tableIndex + 0xe];
        state->tableIndex++;
        state->timerMinutes = 0x1e;
        return 1;
    }

    if (state->tableIndex != 0)
    {
        obj = ObjList_FindObjectById(table[state->tableIndex - 1]);
        if (ObjTrigger_IsSetById(obj, 0x1ee) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            state->mode = NWLEVCONTROL_MODE_WAIT_MENU_LOCK;
            state->seqId = table[state->tableIndex + 6];
            state->timerMinutes = 0;
            return 2;
        }
    }

    return 0;
}

int nw_levcontrol_getExtraSize(void)
{
    return 0x14;
}

/* On free, restore the default environment fx (only if this slot's object
 * group is no longer active) and always stop the challenge timer. */
void nw_levcontrol_free(GameObject* obj)
{
    extern void envFxActFn_800887f8(u8 value);
    s8 slot = obj->anim.mapEventSlot;
    int groupStatus = (*gMapEventInterface)->getObjGroupStatus((s32)slot, 0);
    if ((u8)groupStatus == 0)
    {
        envFxActFn_800887f8(0);
    }
    gameTimerStop();
}
