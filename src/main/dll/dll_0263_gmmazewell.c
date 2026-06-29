/*
 * gmmazewell (DLL 0x263) - the wishing/quest well in the maze area.
 *
 * The well watches a fixed set of nine quest/event game bits (the
 * gQuestBitTable rows below). While the well's hitbox is being touched
 * (INTERACT_FLAG_ACTIVATED) it scans those bits for a ready event: when
 * one fires it grants that row's reward bits, optionally unlocks a cheat
 * (rows 0-2), records the row's dialogue id as a pending trigger, and
 * runs sequence 0 with input disabled. The pending dialogue is shown the
 * next time event 1 is received (gmmazewell_clearPendingTriggerCallback).
 *
 * On enter it stamps a savepoint at the player and plays maze-well music
 * (track 0x36, gated by game bit 0xEFC); leaving stops both. The prompt
 * is suppressed (INTERACT_FLAG_PROMPT_SUPPRESSED) whenever no watched
 * event is currently ready.
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

typedef struct GmmazewellState
{
    u8 unk0;            /* 0x00: cleared at init, never read */
    u8 savepointSet;    /* 0x01: savepoint stamped once player object is available */
    u8 pad2[2];         /* 0x02 */
    s32 pendingDialogue; /* 0x04: dialogue id queued for the next event 1 (-1 = none) */
} GmmazewellState;

STATIC_ASSERT(offsetof(GmmazewellState, pendingDialogue) == 0x4);
STATIC_ASSERT(sizeof(GmmazewellState) == 0x8);

/* Quest-bit table layout (gQuestBitTable, 44 s16 entries):
 *   [0..8]   watched quest/event bits
 *   [10..18] reward bits granted when the matching event fires
 *   [20..28] follow-up bits
 *   [28..]   dialogue ids, viewed as s32 via gQuestBitTable32[14..21] */
#define QUEST_BIT_COUNT 9
#define QUEST_REWARD_BASE 10
#define QUEST_FOLLOWUP_BASE 20
#define QUEST_DIALOGUE_BASE32 14

/* game bit + music track toggled while the well is active */
#define GAMEBIT_MAZEWELL_ACTIVE 0xefc
#define MUSIC_MAZEWELL 0x36

#define MAZEWELL_DEFAULT_DIALOGUE 1316

int gmmazewell_getExtraSize(void) { return sizeof(GmmazewellState); }

void gmmazewell_render(void* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6978);
}

void gmmazewell_free(void)
{
    GameBit_Set(GAMEBIT_MAZEWELL_ACTIVE, 0);
    Music_Trigger(MUSIC_MAZEWELL, 0);
}

void gmmazewell_init(int obj)
{
    GmmazewellState* state = ((GameObject*)obj)->extra;
    state->unk0 = 0;
    GameBit_Set(GAMEBIT_MAZEWELL_ACTIVE, 1);
    Music_Trigger(MUSIC_MAZEWELL, 1);
    ((GameObject*)obj)->animEventCallback = gmmazewell_clearPendingTriggerCallback;
}

int gmmazewell_clearPendingTriggerCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    GmmazewellState* state = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1 && state->pendingDialogue != -1)
        {
            (*gGameUIInterface)->showNpcDialogue(state->pendingDialogue, 0x14, 0x8c, 0);
            state->pendingDialogue = -1;
        }
    }
    return 0;
}

void gmmazewell_update(unsigned int obj)
{
    int objId;
    s16* questBits = lbl_8032A730;
    s32* questBits32 = (s32*)questBits;
    GmmazewellState* state = ((GameObject*)obj)->extra;
    u8* player;
    int matchedBit;
    s16* p;
    int i;

    if (state->savepointSet == 0)
    {
        player = Obj_GetPlayerObject();
        if (player != 0)
        {
            (*gMapEventInterface)->savePoint((int)(player + 0xc), ((GameObject*)player)->anim.rotX, 0,
                                             getCurMapLayer());
            state->savepointSet = 1;
        }
    }

    ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;

    for (i = 0, p = questBits; (u32)i < QUEST_BIT_COUNT; i++)
    {
        if (GameBit_Get(*p) != 0)
        {
            matchedBit = questBits[i];
            goto checkValue;
        }
        p++;
    }
    matchedBit = 0;
checkValue:
    if (matchedBit != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    else
    {
        ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }

    objId = obj;
    if ((((GameObject*)objId)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        int found;
        for (i = 0, p = questBits; (u32)i < QUEST_BIT_COUNT; i++)
        {
            if ((*gGameUIInterface)->isEventReady(*p) != 0)
            {
                if (lbl_803DC968 != 0)
                {
                    state = ((GameObject*)obj)->extra;
                    switch (i)
                    {
                    case 0:
                    case 1:
                    case 2:
                        GameBit_Set(questBits[i + QUEST_REWARD_BASE], 1);
                        saveFileStruct_unlockCheat((u8)i);
                        break;
                    }
                    state->pendingDialogue = questBits32[i + QUEST_DIALOGUE_BASE32];
                    GameBit_Set(questBits[i + QUEST_FOLLOWUP_BASE], 1);
                }
                else
                {
                    state = ((GameObject*)obj)->extra;
                    state->pendingDialogue = questBits32[i + QUEST_DIALOGUE_BASE32];
                    switch (i)
                    {
                    case 3:
                        state->pendingDialogue = MAZEWELL_DEFAULT_DIALOGUE;
                    case 0:
                    case 1:
                    case 2:
                        GameBit_Set(questBits[i + QUEST_REWARD_BASE], 1);
                        saveFileStruct_unlockCheat((u8)i);
                        break;
                    }
                    GameBit_Set(questBits[i + QUEST_FOLLOWUP_BASE], 1);
                }
                found = 1;
                goto checkFound;
            }
            p++;
        }
        found = 0;
    checkFound:
        if (found != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            buttonDisable(0, 256);
        }
    }

    objRenderFn_80041018(obj);
}
