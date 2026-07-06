/*
 * dbsh_symbol (DLL 0x196) - the spin-the-symbol minigame object in the
 * DarkIce Mines SnowHorn shrine (shares the shrine's RISE_DONE/CLOSE
 * game bits with dbshshrine, DLL 0x195).
 *
 * dbsh_symbol_update walks a small state machine on phase: hide the
 * model, play a stone-scuff cue, arm trigger sequence 0, then resolve -
 * granting CLOSE_A when the spin finished or CLOSE_B otherwise. While
 * the trigger sequence runs, DBSH_Symbol_SeqFn accumulates spin from the
 * A-button, drives this symbol and its mirror partner (the nearby
 * objType-0x20F symbol) through ObjAnim moves, plays the loop/grunt/creak
 * sfx, and reports completion once spinProgress reaches DBSH_SPIN_DONE.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/dbshsymbol_types.h"
#include "main/game_object.h"
#include "main/dll/cup1C3.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/audio/sfx_trigger_ids.h"

#define DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG OBJ_MODEL_STATE_SHADOW_VISIBLE

/* shared with the shrine object (DLL 0x195) */
#define DBSH_GB_RISE_DONE 0x16a
#define DBSH_GB_CLOSE_A 0x16b
#define DBSH_GB_CLOSE_B 0x16c

#define DBSH_PARTNER_OBJTYPE 0x20f /* mirror symbol spun alongside this one */
#define DBSH_SPIN_DONE 0x7ef4      /* spinProgress at a full turn */

#define PAD_BUTTON_A 0x100

extern int Obj_GetPlayerObject(void);
extern int randomGetRange(int lo, int hi);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(u32 obj, u32 channel);
extern u8 gDbShSymbolScuffPlayed;
extern u8 framesThisStep;
extern void Sfx_SetObjectSfxVolume(int obj, int sfx, int vol, f32 f);
extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId);
extern void gameTimerInit(s8 flags, int minutes);
extern void timerSetToCountUp(void);
extern void gameTimerStop(void);
extern int isGameTimerDisabled(void);
extern int getButtonsJustPressedIfNotBusy(int p);
extern f32 timeDelta;
extern f32 lbl_803E50E0;
extern f32 lbl_803E50E4;
extern f32 lbl_803E50EC;
extern f32 lbl_803E50F0;
extern f32 lbl_803E50F4;
extern f32 lbl_803E50FC;
extern f32 lbl_803E5100;
extern f32 lbl_803E5104;
extern f32 lbl_803E5108;

STATIC_ASSERT(sizeof(DbshSymbolState) == 0x24);
STATIC_ASSERT(offsetof(DbshSymbolState, phase) == 0x1E);
STATIC_ASSERT(offsetof(DbshSymbolState, flags) == 0x20);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E5118;

int DBSH_Symbol_SeqFn(int obj, int anim, ObjAnimUpdateState* animUpdate)
{
    int v;
    int* list;
    int idx;
    int count;
    int i;
    DbshSymbolState* state;
    int player;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    Sfx_SetObjectSfxVolume(obj, SFXTRIG_blockscrape_lp, 10, lbl_803E50E0);
    Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_blockscrape_lp);
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            gameTimerInit(0x1d, 0x3c);
            timerSetToCountUp();
            state->flags.active = 0;
            ((GameObject*)obj)->anim.modelState->flags |= DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
        }
    }
    if (state->flags.active != 0)
    {
        return 0;
    }
    if (state->partnerObj == NULL)
    {
        list = ObjList_GetObjects(&idx, &count);
        while (idx < count)
        {
            *(int*)&state->partnerObj = list[idx];
            if (((GameObject*)state->partnerObj)->anim.seqId == DBSH_PARTNER_OBJTYPE)
            {
                break;
            }
            idx++;
        }
    }
    if (state->partnerObj == NULL)
    {
        return 0;
    }
    for (i = 0; i < framesThisStep; i++)
    {
        if (isGameTimerDisabled() != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16);
            state->flags.finished = 0;
            state->flags.active = 1;
            (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, 0xbd);
        }
        if ((getButtonsJustPressedIfNotBusy(0) & PAD_BUTTON_A) != 0)
        {
            state->spinSpeed = state->spinSpeed + lbl_803E50E4;
        }
        if (state->spinSpeed > 80.0f)
        {
            state->spinSpeed = 80.0f;
        }
        state->spinProgress = (int)((f32)state->spinProgress + state->spinSpeed);
        if (state->spinProgress >= DBSH_SPIN_DONE)
        {
            gameTimerStop();
            Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16);
            ObjAnim_SetCurrentMove(player, 0, lbl_803E50EC, 0);
            state->flags.finished = 1;
            state->flags.active = 1;
            state->spinProgress = DBSH_SPIN_DONE;
            (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, 0xbd);
            return 0;
        }
        (*gObjectTriggerInterface)->setXrot(state->triggerHandle, state->spinProgress);
        if (state->spinProgress < 0)
        {
            state->spinProgress = 0;
            if (state->spinSpeed < lbl_803E50EC)
            {
                state->spinSpeed = *(f32*)&lbl_803E50EC;
            }
            state->prevSpinProgress = state->spinProgress;
            if (state->spinSpeed > lbl_803E50F0)
            {
                state->spinSpeed = state->spinSpeed - lbl_803E50F4;
            }
            return 0;
        }
        if (state->spinSpeed > -80.0f)
        {
            state->spinSpeed = state->spinSpeed - lbl_803E50FC;
        }
        if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
            player, ((f32)state->spinProgress - state->prevSpinProgress) / 7500.0f,
            timeDelta, NULL) != 0)
        {
            if (((GameObject*)player)->anim.currentMoveProgress < lbl_803E50EC)
            {
                ((GameObject*)player)->anim.currentMoveProgress =
                    lbl_803E5104 + ((GameObject*)player)->anim.currentMoveProgress;
            }
        }
        if (state->partnerObj != NULL)
        {
            if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
                *(int*)&state->partnerObj, -((f32)state->spinProgress - state->prevSpinProgress) / lbl_803E5100,
                timeDelta, NULL) != 0)
            {
                f32 h = ((GameObject*)state->partnerObj)->anim.currentMoveProgress;
                if (h < lbl_803E50EC)
                {
                    ((GameObject*)state->partnerObj)->anim.currentMoveProgress =
                        lbl_803E5104 + h;
                }
            }
        }
        state->prevSpinProgress = state->spinProgress;
    }
    state->sfxTimerA = state->sfxTimerA - timeDelta;
    if (state->sfxTimerA < lbl_803E50EC)
    {
        if (state->spinSpeed < lbl_803E50EC)
        {
            state->sfxTimerA = (f32)(int)
            randomGetRange(0x28, 0x64);
        }
        else
        {
            state->sfxTimerA = (f32)(int)
            randomGetRange(0x78, 0xf0);
        }
        Sfx_PlayFromObject(player, SFXTRIG_literun116_var);
    }
    state->sfxTimerB = state->sfxTimerB - timeDelta;
    if (state->sfxTimerB < lbl_803E50EC)
    {
        if (state->spinSpeed > lbl_803E50EC)
        {
            state->sfxTimerB = (f32)(int)
            randomGetRange(0x28, 0x64);
        }
        else
        {
            state->sfxTimerB = (f32)(int)
            randomGetRange(0x78, 0xf0);
        }
        Sfx_PlayFromObject(obj, SFXTRIG_spotfox03);
    }
    {
        f32 vol = (lbl_803E5108 * state->spinSpeed >= lbl_803E50EC)
                      ? lbl_803E5108 * state->spinSpeed
                      : -(lbl_803E5108 * state->spinSpeed);
        v = (int)vol;
        if (v > 100)
        {
            v = 100;
        }
        Sfx_SetObjectSfxVolume(obj, SFXTRIG_blockscrape_lp, (u8)v, lbl_803E50E0);
    }
    return 0;
}

void dbsh_symbol_update(int obj)
{
    s16 phase;
    u32 puzzleStarted;
    DbshSymbolState* state;

    state = ((GameObject*)obj)->extra;
    puzzleStarted = GameBit_Get(DBSH_GB_RISE_DONE);
    if (puzzleStarted == 0)
    {
        state->phase = 0;
        state->partnerObj = NULL;
        GameBit_Set(DBSH_GB_CLOSE_B, 0);
    }
    else
    {
        phase = state->phase;
        if (phase == 0)
        {
            ((GameObject*)obj)->anim.modelState->flags &= ~(u64)DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
            state->phase = 1;
        }
        else if (phase == 2)
        {
            state->phase = 3;
            state->triggerHandle =
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        else if (phase == 1)
        {
            if (gDbShSymbolScuffPlayed != 0)
            {
                gDbShSymbolScuffPlayed = 0;
                Sfx_PlayFromObject(obj, SFXfoot_stone_scuff);
            }
            state->phase = 2;
            gDbShSymbolScuffPlayed = 1;
        }
        else if (phase == 3)
        {
            ((GameObject*)obj)->anim.modelState->flags &= ~(u64)DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
            if (state->flags.finished != 0)
            {
                GameBit_Set(DBSH_GB_CLOSE_A, 1);
            }
            else
            {
                GameBit_Set(DBSH_GB_CLOSE_B, 1);
            }
            Sfx_StopObjectChannel(obj, 0x7f);
            state->flags.active = 1;
        }
    }
}

int dbsh_symbol_getExtraSize(void)
{
    return 0x24;
}

void dbsh_symbol_free(void)
{
    gameTimerStop();
}

void dbsh_symbol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5104);
}

void dbsh_symbol_init(int* obj)
{
    DbshSymbolState* state = ((GameObject*)obj)->extra;

    state->spinSpeed = lbl_803E50EC;
    state->spinProgress = 0;
    state->prevSpinProgress = 0;
    state->phase = 0;
    *(int*)&state->partnerObj = 0;
    state->flags.finished = 0;
    state->flags.active = 1;

    ((GameObject*)obj)->anim.localPosY -= lbl_803E5118;
    ((GameObject*)obj)->animEventCallback = DBSH_Symbol_SeqFn;

    ((GameObject*)obj)->anim.modelState->flags &= ~(u64)DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
}
