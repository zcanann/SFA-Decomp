/*
 * gmmazewell (DLL 0x263) - the wishing/quest well in the maze area.
 *
 * The well watches a fixed set of nine quest/event game bits (the
 * gQuestBitTable rows below). While the well's hitbox is being touched
 * (INTERACT_FLAG_ACTIVATED) it scans those bits for a ready event: when
 * one fires it grants that row's reward bits, optionally unlocks a cheat
 * (rows 0-2), records the row's dialogue id as a pending trigger, and
 * runs sequence 0 with input disabled. The pending dialogue is shown the
 * next time event 1 is received (GM_MazeWell_SeqFn).
 *
 * On enter it stamps a savepoint at the player and plays maze-well music
 * (track 0x36, gated by game bit 0xEFC); leaving stops both. The prompt
 * is suppressed (INTERACT_FLAG_PROMPT_SUPPRESSED) whenever no watched
 * event is currently ready.
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/dll/dll_0263_gmmazewell.h"

#define PAD_BUTTON_A 0x100

/* Quest-bit table layout (gQuestBitTable, 44 s16 entries):
 *   [0..8]   watched quest/event bits
 *   [10..18] reward bits granted when the matching event fires
 *   [20..28] follow-up bits
 *   [28..]   dialogue ids, viewed as s32 via gQuestBitTable32[14..21] */
#define QUEST_BIT_COUNT       9
#define QUEST_REWARD_BASE     10
#define QUEST_FOLLOWUP_BASE   20
#define QUEST_DIALOGUE_BASE32 14

/* music track toggled while the well is active (game bit is GAMEBIT_MAZEWELL_ACTIVE) */
#define MUSIC_MAZEWELL 0x36

#define MAZEWELL_DEFAULT_DIALOGUE 1316

/* Row indices into gQuestBitTable[]; rows 0-3 map 1:1 to enum CheatId, rows 4-7
 * grant no cheat, row 8 is the unused/dead 9th token. */
enum QuestWellRow
{
    QUESTWELL_CREDITS = 0,       /* ThornTail Shop      -> CHEAT_SHOW_CREDITS */
    QUESTWELL_SEPIA = 1,         /* Cape Claw           -> CHEAT_SEPIA_MODE */
    QUESTWELL_MUSIC_TEST = 2,    /* Ice Mountain        -> CHEAT_MUSIC_TEST */
    QUESTWELL_DINO_LANGUAGE = 3, /* Moon Mtn Pass       -> CHEAT_DINO_LANGUAGE (non-Japanese only) */
    QUESTWELL_LIGHTFOOT = 4,     /* LightFoot Village   -> nothing */
    QUESTWELL_OCEAN_FP = 5,      /* Ocean Force Point   -> nothing */
    QUESTWELL_VOLCANO_FP = 6,    /* Volcano Force Point -> nothing */
    QUESTWELL_SNOWHORN = 7,      /* SnowHorn Wastes     -> nothing */
    QUESTWELL_UNUSED = 8         /* Nowhere - dead 9th token */
};

int GM_MazeWell_SeqFn(struct GameObject *obj, int unused, ObjAnimUpdateState* animUpdate)
{
    GmmazewellState* state = (obj)->extra;
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

int GM_MazeWell_getExtraSize(void)
{
    return sizeof(GmmazewellState);
}

void GM_MazeWell_free(void)
{
    mainSetBits(GAMEBIT_MAZEWELL_ACTIVE, 0);
    Music_Trigger(MUSIC_MAZEWELL, 0);
}

void GM_MazeWell_render(void* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E6978);
}

void GM_MazeWell_update(unsigned int obj)
{
    int objId;
    s16* questBits = lbl_8032A730;
    s32* questBits32 = (s32*)questBits;
    GmmazewellState* state = ((GameObject*)obj)->extra;
    u8* player;
    int matchedBit;
    s16* questBitPtr;
    enum QuestWellRow i;

    if (state->savepointSet == 0)
    {
        player = Obj_GetPlayerObject();
        if (player != 0)
        {
            (*gMapEventInterface)
                ->savePoint((int)(player + 0xc), ((GameObject*)player)->anim.rotX, 0, getCurMapLayer());
            state->savepointSet = 1;
        }
    }

    ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;

    for (i = 0, questBitPtr = questBits; (u32)i < QUEST_BIT_COUNT; i++)
    {
        if (mainGetBit(*questBitPtr) != 0)
        {
            matchedBit = questBits[i];
            goto checkValue;
        }
        questBitPtr++;
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
        for (i = 0, questBitPtr = questBits; (u32)i < QUEST_BIT_COUNT; i++)
        {
            if ((*gGameUIInterface)->isEventReady(*questBitPtr) != 0)
            {
                if (lbl_803DC968 != 0)
                {
                    state = ((GameObject*)obj)->extra;
                    switch (i)
                    {
                    case 0:
                    case 1:
                    case 2:
                        mainSetBits(questBits[i + QUEST_REWARD_BASE], 1);
                        saveFileStruct_unlockCheat((u8)i);
                        break;
                    }
                    state->pendingDialogue = questBits32[i + QUEST_DIALOGUE_BASE32];
                    mainSetBits(questBits[i + QUEST_FOLLOWUP_BASE], 1);
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
                        mainSetBits(questBits[i + QUEST_REWARD_BASE], 1);
                        saveFileStruct_unlockCheat((u8)i);
                        break;
                    }
                    mainSetBits(questBits[i + QUEST_FOLLOWUP_BASE], 1);
                }
                found = 1;
                goto checkFound;
            }
            questBitPtr++;
        }
        found = 0;
    checkFound:
        if (found != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            buttonDisable(0, PAD_BUTTON_A);
        }
    }

    objRenderFn_80041018(obj);
}

void GM_MazeWell_init(struct GameObject *obj)
{
    GmmazewellState* state = (obj)->extra;
    state->unk0 = 0;
    mainSetBits(GAMEBIT_MAZEWELL_ACTIVE, 1);
    Music_Trigger(MUSIC_MAZEWELL, 1);
    (obj)->animEventCallback = GM_MazeWell_SeqFn;
}
