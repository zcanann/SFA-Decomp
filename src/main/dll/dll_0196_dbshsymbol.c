#include "main/audio/sfx_ids.h"
#include "main/dll/dbshsymbol_types.h"
#include "main/game_object.h"
#include "main/dll/cup1C3.h"
#include "main/objlib.h"
#include "main/objseq.h"

#define DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG OBJ_MODEL_STATE_SHADOW_VISIBLE

extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);

extern u8 lbl_803DBF68;
extern u8 framesThisStep;

extern void Sfx_SetObjectSfxVolume(int obj, int sfx, int vol, f32 f);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfx);
extern void gameTimerInit(int a, int b);
extern void timerSetToCountUp(void);
extern void gameTimerStop(void);
extern int isGameTimerDisabled(void);
extern int getButtonsJustPressedIfNotBusy(int p);
extern f32 timeDelta;
extern f32 lbl_803E50E0;
extern f32 lbl_803E50E4;
extern f32 lbl_803E50E8;
extern f32 lbl_803E50EC;
extern f32 lbl_803E50F0;
extern f32 lbl_803E50F4;
extern f32 lbl_803E50F8;
extern f32 lbl_803E50FC;
extern f32 lbl_803E5100;
extern f32 lbl_803E5104;
extern f32 lbl_803E5108;

/*
 * Per-object extra state for the DBSH spin-symbol minigame
 * (dbsh_symbol_getExtraSize == 0x24).
 */

STATIC_ASSERT(sizeof(DbshSymbolState) == 0x24);
STATIC_ASSERT(offsetof(DbshSymbolState, phase) == 0x1E);
STATIC_ASSERT(offsetof(DbshSymbolState, flags) == 0x20);

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5118;

int DBSH_Symbol_SeqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate)
{
    extern int Obj_GetPlayerObject(void);
    f32 maxSpeed;
    f32 spdThresh;
    f32 animDiv;
    int v;
    int* list;
    int idx;
    int count;
    int i;
    int player;
    DbshSymbolState* state;

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    Sfx_SetObjectSfxVolume((int)obj, 0x3af, 10, lbl_803E50E0);
    Sfx_KeepAliveLoopedObjectSound((int)obj, 0x3af);
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == 1)
        {
            gameTimerInit(0x1d, 0x3c);
            timerSetToCountUp();
            state->flags.active = 0;
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
        }
    }
    if (state->flags.active == 0)
    {
        return 0;
    }
    if (state->partnerObj == NULL)
    {
        list = (int*)ObjList_GetObjects(&idx, &count);
        while (idx < count)
        {
            *(int*)&state->partnerObj = list[idx];
            if (*(s16*)(*(int*)&state->partnerObj + 0x46) == 0x20f)
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
    maxSpeed = lbl_803E50E8;
    spdThresh = lbl_803E50F8;
    animDiv = lbl_803E5100;
    for (i = 0; i < framesThisStep; i++)
    {
        if (isGameTimerDisabled() != 0)
        {
            Sfx_PlayFromObject((int)obj, 0x1d4);
            state->flags.finished = 0;
            state->flags.active = 1;
            (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, 0xbd);
        }
        if ((getButtonsJustPressedIfNotBusy(0) & 0x100) != 0)
        {
            state->spinSpeed = state->spinSpeed + lbl_803E50E4;
        }
        if (state->spinSpeed > maxSpeed)
        {
            state->spinSpeed = maxSpeed;
        }
        state->spinProgress = (int)((f32)state->spinProgress + state->spinSpeed);
        if (state->spinProgress >= 0x7ef4)
        {
            gameTimerStop();
            Sfx_PlayFromObject((int)obj, 0x1d4);
            ObjAnim_SetCurrentMove(player, 0, lbl_803E50EC, 0);
            state->flags.finished = 1;
            state->flags.active = 1;
            state->spinProgress = 0x7ef4;
            (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, 0xbd);
            return 0;
        }
        (*gObjectTriggerInterface)->setXrot(state->triggerHandle, 0xbd);
        if (state->spinProgress < 0)
        {
            state->spinProgress = 0;
            if (state->spinSpeed < lbl_803E50EC)
            {
                state->spinSpeed = lbl_803E50EC;
            }
            state->prevSpinProgress = state->spinProgress;
            if (state->spinSpeed > lbl_803E50F0)
            {
                state->spinSpeed = state->spinSpeed - lbl_803E50F4;
            }
            return 0;
        }
        if (state->spinSpeed > spdThresh)
        {
            state->spinSpeed = state->spinSpeed - lbl_803E50FC;
        }
        if (((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
            player, ((f32)state->spinProgress - (f32)state->prevSpinProgress) / animDiv,
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
                *(int*)&state->partnerObj, -((f32)state->spinProgress - (f32)state->prevSpinProgress) / lbl_803E5100,
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
        Sfx_PlayFromObject(player, 0x13a);
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
        Sfx_PlayFromObject((int)obj, 0x4a3);
    }
    {
        f32 vol = lbl_803E5108 * state->spinSpeed;
        if (vol >= lbl_803E50EC)
        {
        }
        else
        {
            vol = -vol;
        }
        v = (int)vol;
        if (v > 100)
        {
            v = 100;
        }
        Sfx_SetObjectSfxVolume((int)obj, 0x3af, (u8)v, lbl_803E50E0);
    }
    return 0;
}

void dbsh_symbol_update(int obj)
{
    extern undefined4 GameBit_Set(int eventId, int value);
    s16 phase;
    uint puzzleStarted;
    DbshSymbolState* state;

    state = ((GameObject*)obj)->extra;
    puzzleStarted = GameBit_Get(0x16a);
    if (puzzleStarted == 0)
    {
        state->phase = 0;
        state->partnerObj = NULL;
        GameBit_Set(0x16c, 0);
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
            if (lbl_803DBF68 != '\0')
            {
                lbl_803DBF68 = 0;
                Sfx_PlayFromObject(obj, SFXfoot_stone_scuff);
            }
            state->phase = 2;
            lbl_803DBF68 = '\x01';
        }
        else if (phase == 3)
        {
            ((GameObject*)obj)->anim.modelState->flags &= ~(u64)DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
            if (state->flags.finished != 0)
            {
                GameBit_Set(0x16b, 1);
            }
            else
            {
                GameBit_Set(0x16c, 1);
            }
            Sfx_StopObjectChannel(obj, 0x7f);
            state->flags.active = 1;
        }
    }
    return;
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
    objRenderFn_8003b8f4(lbl_803E5104);
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
    ((GameObject*)obj)->animEventCallback = (void*)DBSH_Symbol_SeqFn;

    ((GameObject*)obj)->anim.modelState->flags &= ~(u64)DBSH_SYMBOL_OBJECT_MODEL_ACTIVE_FLAG;
}
