#include "ghidra_import.h"
#include "main/dll/DR/DRlaserturret.h"
#include "main/objanim.h"

#pragma peephole off
#pragma scheduling off

extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int Stack_IsFull(void *stack);
extern int Stack_Push(void *stack, void *value);
extern void timerSetToCountUp(void);
extern void gameTimerInit(int, int);
extern int buttonDisable(int, int);
extern int padGetAnalogInput(int, char *, char *);
extern uint getButtonsJustPressed(int);
extern uint GameBit_Get(int bit);
extern int GameBit_Set(int bit, int value);
extern int randomGetRange(int lo, int hi);
extern void *Obj_GetPlayerObject(void);
extern void ObjHits_DisableObject(void *);
extern void ObjHits_EnableObject(void *);
extern int ObjTrigger_IsSet(void *);
extern void *objFindTexture(void *obj, int idx, int flags);
extern int hitDetectFn_80065e50(void *obj, float x, float y, float z, void *out, int p5, int p6);
extern void hudFn_8011f38c(int);
extern void hudFn_8011f6f0(int);
extern double shopKeeperRotateFn_801e7c4c(void *obj, void *playerObj, int p3);
extern float fn_80293E80(double);
extern int playerGetMoney(void *playerObj);

extern void *gScreenTransitionInterface;
extern void *gObjectTriggerInterface;
extern void *gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern u8 framesThisStep;
extern f32 timeDelta;
extern s16 lbl_803DC0A0[1];
extern f32 lbl_803DC0A4[3];
extern f32 lbl_803E59DC;
extern f32 lbl_803E59E0;
extern f32 lbl_803E59E4;
extern f32 lbl_803E59E8;
extern f32 lbl_803E59EC;
extern f32 lbl_803E59F0;
extern f32 lbl_803E5A08;
extern f32 lbl_803E5A0C;
extern f32 lbl_803E5A10;
extern f32 lbl_803E5A14;
extern f32 lbl_803E5A18;
extern f32 lbl_803E5A1C;
extern f32 lbl_803E5A20;

/*
 * --INFO--
 *
 * Function: DRlaserturret_updateIdle
 * EN v1.0 Address: 0x801E6B10
 * EN v1.0 Size: 504b
 */
int DRlaserturret_updateIdle(DRLaserTurretObject *obj, DRLaserTurretAnimState *animState)
{
    void *playerObj;
    DRLaserTurretState *state;
    void *psStack;
    int v;
    int sum;
    int rng;

    playerObj = Obj_GetPlayerObject();
    state = obj->state;
    state->promptState = 0xff;
    animState->animStepScale = lbl_803E59E4;
    if (obj->currentMove != 0) {
        ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_IDLE, lbl_803E59DC, 0);
    }
    ObjHits_EnableObject(obj);
    obj->hitFlags &= ~0x08;
    if (GameBit_Get(DR_LASERTURRET_GAMEBIT_SHOP_OPEN) == 0) {
        v = DR_LASERTURRET_STATE_PUSH_IDLE;
        psStack = state->stateStack;
        if (Stack_IsFull(psStack) == 0) {
            Stack_Push(psStack, &v);
        }
        return DR_LASERTURRET_STATE_CONTINUE;
    }
    shopKeeperRotateFn_801e7c4c(obj, playerObj, 0);
    obj->y =
        state->bobAmplitude *
            fn_80293E80(
                (double)(lbl_803E59E8 *
                         (float)(uint)state->bobPhase /
                         lbl_803E59EC)) +
        state->bobBaseY;
    sum = (uint)state->bobPhase + (uint)framesThisStep * 0x100;
    if (sum > 0xffff) {
        rng = randomGetRange(0xf, 0x23);
        state->bobAmplitude = (float)rng * lbl_803E59F0;
    }
    state->bobPhase = (u16)sum;
    if ((obj->hitFlags & 1) != 0) {
        if (playerGetMoney(playerObj) >= 1) {
            GameBit_Set(DR_LASERTURRET_GAMEBIT_HAS_MONEY, 1);
            buttonDisable(0, DR_LASERTURRET_BUTTON_ACCEPT);
        } else {
            rng = randomGetRange(0, 2);
            (*(code **)gObjectTriggerInterface)[0x48 / 4](rng, obj, -1);
            buttonDisable(0, DR_LASERTURRET_BUTTON_ACCEPT);
        }
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: DRlaserturret_updateTracking
 * EN v1.0 Address: 0x801E6D08
 * EN v1.0 Size: 1052b
 */
int DRlaserturret_updateTracking(void *obj, DRLaserTurretAnimState *animState)
{
    void *playerObj;
    DRLaserTurretState *state;
    void *psStack;
    int v;
    int sum;
    int rng;
    float fmin;
    float fdist;
    int count;
    int idx;
    void **arr;

    playerObj = Obj_GetPlayerObject();
    state = *(DRLaserTurretState **)((char *)obj + 0xb8);
    if (animState->stateEntered != 0) {
        rng = randomGetRange(0x1f4, 0x3e8);
        state->actionTimer = (f32)rng;
        state->flags = state->flags & ~DR_LASERTURRET_FLAG_ACTION_ACTIVE;
    }
    if ((state->flags & DR_LASERTURRET_FLAG_ACTION_ACTIVE) != 0) {
        if (animState->moveComplete != 0) {
            if (*(s16 *)((char *)obj + 0xa0) == DR_LASERTURRET_ANIM_TRACKING) {
                if (animState->animStepScale > lbl_803E59DC) {
                    ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_ALERT, 0.0f, 0);
                    goto L_DE8;
                }
            }
            if (*(s16 *)((char *)obj + 0xa0) != 0) {
                ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_IDLE, lbl_803E59DC, 0);
            }
        L_DE8:
            animState->animStepScale = lbl_803E59E4;
            state->flags = state->flags & ~DR_LASERTURRET_FLAG_ACTION_ACTIVE;
            rng = randomGetRange(0x1f4, 0x3e8);
            state->actionTimer = (f32)rng;
        }
    } else {
        if (*(s16 *)((char *)obj + 0xa0) != DR_LASERTURRET_ANIM_ALERT &&
            *(s16 *)((char *)obj + 0xa0) != 0) {
            ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_IDLE, lbl_803E59DC, 0);
            animState->animStepScale = lbl_803E59E4;
        }
    }
    state->actionTimer = state->actionTimer - timeDelta;
    if (state->actionTimer <= lbl_803E59DC &&
        (state->flags & DR_LASERTURRET_FLAG_ACTION_ACTIVE) == 0) {
        Sfx_PlayFromObject((int)obj, DR_LASERTURRET_SFX_ACTION);
        if (*(s16 *)((char *)obj + 0xa0) == DR_LASERTURRET_ANIM_ALERT) {
            ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_TRACKING, lbl_803E5A08, 0);
            animState->animStepScale = lbl_803E5A0C;
        } else {
            rng = randomGetRange(0, 1);
            ObjAnim_SetCurrentMove((int)obj, (int)lbl_803DC0A0[rng], lbl_803E59DC, 0);
            animState->animStepScale = lbl_803DC0A4[rng];
        }
        state->flags = state->flags | DR_LASERTURRET_FLAG_ACTION_ACTIVE;
    }
    if (GameBit_Get(DR_LASERTURRET_GAMEBIT_SHOP_OPEN) == 0) {
        v = DR_LASERTURRET_STATE_PUSH_TRACKING;
        psStack = state->stateStack;
        if (Stack_IsFull(psStack) == 0) {
            Stack_Push(psStack, &v);
        }
        return DR_LASERTURRET_STATE_CONTINUE;
    }
    {
        float t = (float)shopKeeperRotateFn_801e7c4c(obj, playerObj, 0);
        float target;
        if (t > lbl_803E5A18) {
            target = lbl_803E5A14;
        } else {
            target = lbl_803E59DC;
        }
        animState->aimBlend =
            lbl_803E5A10 * (target - animState->aimBlend) * timeDelta + animState->aimBlend;
        if (animState->aimBlend > lbl_803E5A1C) {
            animState->aimBlend = lbl_803E59DC;
        }
        animState->aimBlend = lbl_803E59DC;
    }
    count = hitDetectFn_80065e50(obj, *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
                        *(f32 *)((char *)obj + 0x14), &arr, 0, 0);
    fmin = lbl_803E5A20;
    if (count > 0) {
        for (idx = 0; idx < count; idx++) {
            fdist = *(f32 *)arr[idx] - *(f32 *)((char *)obj + 0x10);
            if (fdist < lbl_803E59DC) {
                fdist = -fdist;
            }
            if (fdist < fmin) {
                state->bobBaseY = lbl_803E59E0 + *(f32 *)arr[idx];
                fmin = fdist;
            }
        }
    }
    *(f32 *)((char *)obj + 0x10) =
        state->bobAmplitude *
            fn_80293E80(
                (double)(lbl_803E59E8 *
                         (float)(uint)state->bobPhase /
                         lbl_803E59EC)) +
        state->bobBaseY;
    sum = (uint)state->bobPhase + (uint)framesThisStep * 0x100;
    if (sum > 0xffff) {
        rng = randomGetRange(0xf, 0x23);
        state->bobAmplitude = (float)rng * lbl_803E59F0;
    }
    state->bobPhase = (u16)sum;
    if (ObjTrigger_IsSet(obj) != 0) {
        rng = randomGetRange(0, 2);
        (*(code **)gObjectTriggerInterface)[0x48 / 4](rng, obj, -1);
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: DRlaserturret_startLinkedTarget
 * EN v1.0 Address: 0x801E7124
 * EN v1.0 Size: 128b
 */
int DRlaserturret_startLinkedTarget(void *obj)
{
    DRLaserTurretState *state;
    int v;

    state = *(DRLaserTurretState **)((char *)obj + 0xb8);
    if (GameBit_Get(DR_LASERTURRET_GAMEBIT_LINK_READY) == 0) {
        return 0;
    }
    v = (int)GameBit_Get(DR_LASERTURRET_GAMEBIT_LINK_STARTED);
    if (v == 0) {
        int *target;
        GameBit_Set(DR_LASERTURRET_GAMEBIT_LINK_STARTED, 1);
        target = state->linkedTarget;
        (**(code ***)((char *)target + 0x68))[0x24 / 4](target, 1, 2);
    }
    return DR_LASERTURRET_STATE_LINKED_TARGET;
}

/*
 * --INFO--
 *
 * Function: DRlaserturret_handlePromptChoice
 * EN v1.0 Address: 0x801E71A4
 * EN v1.0 Size: 1096b
 */
int DRlaserturret_handlePromptChoice(void *obj, void *param2, int dispatch)
{
    DRLaserTurretState *state;
    char stickHi;
    char stickLo;
    s16 v9d0;
    int btn;
    int slot;
    char nudge;
    int *texture;

    state = *(DRLaserTurretState **)((char *)obj + 0xb8);
    if (dispatch == DR_LASERTURRET_PROMPT_COUNT) {
        padGetAnalogInput(0, &stickHi, &stickLo);
        if ((s8)stickLo < 0) {
            state->countValue = state->countValue - 1;
            Sfx_PlayFromObject(0, DR_LASERTURRET_SFX_PROMPT_TICK);
        } else if ((s8)stickLo > 0) {
            state->countValue = state->countValue + 1;
            Sfx_PlayFromObject(0, DR_LASERTURRET_SFX_PROMPT_TICK);
        }
        if (state->countValue > state->maxCount) {
            state->countValue = state->maxCount;
        }
        if (state->countValue > state->countScale << 1) {
            state->countValue = (s16)(state->countScale << 1);
        } else if (state->countValue < state->countScale >> 1) {
            state->countValue = (s16)(state->countScale >> 1);
        }
        v9d0 = state->countValue;
        texture = objFindTexture(obj, DR_LASERTURRET_ONES_TEXTURE_SLOT, 0);
        *texture = (v9d0 - v9d0 / 10 * 10) << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
        texture = objFindTexture(obj, DR_LASERTURRET_TENS_TEXTURE_SLOT, 0);
        slot = v9d0 / 10;
        *texture = (slot - slot / 10 * 10) << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
        slot = slot / 10;
        if (slot > DR_LASERTURRET_MAX_DIGIT) slot = DR_LASERTURRET_MAX_DIGIT;
        texture = objFindTexture(obj, DR_LASERTURRET_HUNDREDS_TEXTURE_SLOT, 0);
        *texture = slot << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
    } else if (dispatch == DR_LASERTURRET_PROMPT_DIGIT_COUNT) {
        padGetAnalogInput(0, &stickHi, &stickLo);
        if ((s8)stickLo < 0) {
            state->digitCount = state->digitCount - 1;
            Sfx_PlayFromObject(0, DR_LASERTURRET_SFX_PROMPT_TICK);
        } else if ((s8)stickLo > 0) {
            state->digitCount = state->digitCount + 1;
            Sfx_PlayFromObject(0, DR_LASERTURRET_SFX_PROMPT_TICK);
        }
        if (state->digitCount > state->maxCount) {
            state->digitCount = (u8)state->maxCount;
        }
        if (state->digitCount > DR_LASERTURRET_MAX_DIGIT_COUNT) {
            state->digitCount = DR_LASERTURRET_MAX_DIGIT_COUNT;
        } else if (state->digitCount < DR_LASERTURRET_MIN_DIGIT_COUNT) {
            state->digitCount = DR_LASERTURRET_MIN_DIGIT_COUNT;
        }
        {
            u8 v = state->digitCount;
            texture = objFindTexture(obj, DR_LASERTURRET_ONES_TEXTURE_SLOT, 0);
            *texture = (v - v / 10 * 10) << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
            texture = objFindTexture(obj, DR_LASERTURRET_TENS_TEXTURE_SLOT, 0);
            slot = v / 10;
            *texture = (slot - slot / 10 * 10) << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
            slot = slot / 10;
            if (slot > DR_LASERTURRET_MAX_DIGIT) slot = DR_LASERTURRET_MAX_DIGIT;
            texture = objFindTexture(obj, DR_LASERTURRET_HUNDREDS_TEXTURE_SLOT, 0);
            *texture = slot << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
        }
        btn = getButtonsJustPressed(0);
        if ((btn & DR_LASERTURRET_BUTTON_CANCEL) != 0) {
            state->flags = state->flags | DR_LASERTURRET_FLAG_CONFIRM_PROMPT;
            (*(code **)gScreenTransitionInterface)[0x8 / 4](0x1e, 1);
            return 1;
        }
    }
    btn = getButtonsJustPressed(0);
    if ((btn & DR_LASERTURRET_BUTTON_ACCEPT) == 0) {
        return 0;
    }
    if (state->countValue < state->countTarget) {
        if (state->nudgeCount >= DR_LASERTURRET_MAX_NUDGE_COUNT) nudge = 2;
        else nudge = 0;
    } else {
        nudge = 1;
    }
    switch (dispatch) {
    case DR_LASERTURRET_PROMPT_COUNT:
        if ((s8)nudge == 0) {
            state->nudgeCount = state->nudgeCount + 1;
        }
        return ((s8)nudge == 0) ? 1 : 0;
    case DR_LASERTURRET_PROMPT_NUDGE:
        if ((s8)nudge == 1) {
            int *target = state->linkedTarget;
            (**(code ***)((char *)target + 0x68))[0x48 / 4](target);
        }
        return ((s8)nudge == 1) ? 1 : 0;
    case DR_LASERTURRET_PROMPT_MAX_NUDGE:
        return ((s8)nudge == 2) ? 1 : 0;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: DRlaserturret_startTimedChallenge
 * EN v1.0 Address: 0x801E75EC
 * EN v1.0 Size: 180b
 */
void DRlaserturret_startTimedChallenge(void *obj)
{
    DRLaserTurretState *state;

    state = *(DRLaserTurretState **)((char *)obj + 0xb8);
    if ((state->flags & DR_LASERTURRET_FLAG_START_SEQUENCE) != 0) {
        int *target;
        gameTimerInit(0x11, 0x1e);
        timerSetToCountUp();
        hudFn_8011f6f0(1);
        GameBit_Set(DR_LASERTURRET_GAMEBIT_TIMER_STARTED, 1);
        target = state->linkedTarget;
        (**(code ***)((char *)target + 0x68))[0x4c / 4](target, state->digitCount);
        (*(code **)gTitleMenuControlInterface)[0x4 / 4](0, 0xf5, 0, 0, 0);
    } else {
        hudFn_8011f38c(0);
    }
    state->flags = 0;
}

#pragma scheduling reset
#pragma peephole reset
