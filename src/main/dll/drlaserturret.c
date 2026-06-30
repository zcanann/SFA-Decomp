/*
 * drlaserturret - the laser-turret shop/minigame controller.
 *
 * While the shop is closed (DR_LASERTURRET_GAMEBIT_SHOP_OPEN unset) the
 * turret idles, vertically bobbing on bobPhase, and re-pushes its idle
 * state onto the shared state stack. Once the shop is open it faces the
 * player (shopKeeperRotateFn) and, in the tracking state, periodically
 * plays an alert/tracking animation and offers a purchase prompt: if the
 * player has money it enables the accept button, otherwise it runs a
 * brush-off trigger sequence.
 *
 * handlePromptChoice drives the on-model digit readout (ones/tens/
 * hundreds texture slots) while the player dials a count or digit-count
 * value with the analog stick, then dispatches accept/cancel through the
 * prompt-state ids. startTimedChallenge arms the game timer and HUD and
 * commands the linked target object to begin the challenge.
 */
#include "main/dll/DR/DRlaserturret.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/screen_transition.h"
#include "main/pad.h"
#include "main/gameplay_runtime.h"
#include "sfa_light_decls.h"
extern int Stack_IsFull(void* stack);
extern int Stack_Push(void* stack, void* value);

extern void gameTimerInit(s8 flags, int minutes);
extern void buttonDisable(int port, u32 mask);
extern int padGetAnalogInput(int, char*, char*);
extern int ObjTrigger_IsSet(void*);
extern int hitDetectFn_80065e50(void* obj, float x, float y, float z, void* out, int p5, int p6);
extern void hudFn_8011f38c(u8 x);
extern double shopKeeperRotateFn_801e7c4c(void* obj, void* playerObj, int p3);
extern float mathSinf(float x);
extern int playerGetMoney(void* player);
extern void* gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern u8 framesThisStep;
extern f32 timeDelta;
extern s16 gDrLaserTurretIdleAnimMoves[1];
__declspec(section ".sdata") extern f32 gDrLaserTurretIdleAnimStepScales[3];

extern const f32 lbl_803E59DC;
extern const f32 lbl_803E59E0;
extern f32 gDrLaserTurretDefaultAnimStepScale;
extern f32 gDrLaserTurretPi;
extern f32 gDrLaserTurretBobPhaseScale;
extern f32 lbl_803E59F0;
extern f32 lbl_803E5A08;
extern f32 lbl_803E5A0C;
extern f32 lbl_803E5A10;
extern f32 lbl_803E5A14;
extern f32 lbl_803E5A18;
extern f32 lbl_803E5A1C;
extern f32 lbl_803E5A20;

int DRlaserturret_updateIdle(DRLaserTurretObject* obj, DRLaserTurretAnimState* animState)
{
    void* playerObj;
    DRLaserTurretState* state;
    void* stack;
    int pushState;
    int sum;
    int rng;

    playerObj = Obj_GetPlayerObject();
    state = obj->state;
    state->promptState = 0xff;
    animState->animStepScale = gDrLaserTurretDefaultAnimStepScale;
    if (obj->currentMove != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_IDLE, lbl_803E59DC, 0);
    }
    ObjHits_EnableObject((u32)obj);
    obj->hitFlags &= ~DR_LASERTURRET_HITFLAG_CLEAR_PROMPT;
    if (GameBit_Get(DR_LASERTURRET_GAMEBIT_SHOP_OPEN) == 0)
    {
        pushState = DR_LASERTURRET_STATE_PUSH_IDLE;
        stack = state->stateStack;
        if (Stack_IsFull(stack) == 0)
        {
            Stack_Push(stack, &pushState);
        }
        return DR_LASERTURRET_STATE_CONTINUE;
    }
    shopKeeperRotateFn_801e7c4c(obj, playerObj, 0);
    obj->y =
        state->bobAmplitude *
        mathSinf(
            (double)(gDrLaserTurretPi *
                (float)(u32)state->bobPhase /
                gDrLaserTurretBobPhaseScale)) +
        state->bobBaseY;
    sum = state->bobPhase + framesThisStep * 0x100;
    if (sum > 0xffff)
    {
        float rngf;
        rng = randomGetRange(0xf, 0x23);
        rngf = (float)rng;
        rngf = lbl_803E59F0 * rngf;
        state->bobAmplitude = rngf;
    }
    state->bobPhase = sum;
    if ((obj->hitFlags & DR_LASERTURRET_HITFLAG_CAN_PROMPT) != 0)
    {
        if (playerGetMoney(playerObj) >= 1)
        {
            GameBit_Set(DR_LASERTURRET_GAMEBIT_HAS_MONEY, 1);
            buttonDisable(0, DR_LASERTURRET_BUTTON_ACCEPT);
        }
        else
        {
            rng = randomGetRange(0, 2);
            (*gObjectTriggerInterface)->runSequence(rng, obj, -1);
            buttonDisable(0, DR_LASERTURRET_BUTTON_ACCEPT);
        }
    }
    return 0;
}

int DRlaserturret_updateTracking(DRLaserTurretObject* obj, DRLaserTurretAnimState* animState)
{
    void* playerObj;
    DRLaserTurretState* state;
    void* stack;
    void** arr;
    int pushState;
    int sum;
    int rng;
    float dist;
    float minDist;
    int count;
    int idx;
    double t;
    float rate;
    float target;
    float d;

    playerObj = Obj_GetPlayerObject();
    state = obj->state;
    if (animState->stateEntered != 0)
    {
        rng = randomGetRange(0x1f4, 0x3e8);
        state->actionTimer = rng;
        state->flags = state->flags & ~DR_LASERTURRET_FLAG_ACTION_ACTIVE;
    }
    if ((state->flags & DR_LASERTURRET_FLAG_ACTION_ACTIVE) != 0)
    {
        if (animState->moveComplete != 0)
        {
            if (obj->currentMove == DR_LASERTURRET_ANIM_TRACKING)
            {
                if (animState->animStepScale > lbl_803E59DC)
                {
                    ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_ALERT, lbl_803E59DC, 0);
                    goto action_done;
                }
            }
            if (obj->currentMove != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_IDLE, lbl_803E59DC, 0);
            }
        action_done:
            animState->animStepScale = gDrLaserTurretDefaultAnimStepScale;
            state->flags = state->flags & ~DR_LASERTURRET_FLAG_ACTION_ACTIVE;
            rng = randomGetRange(0x1f4, 0x3e8);
            state->actionTimer = rng;
        }
    }
    else
    {
        if (obj->currentMove != DR_LASERTURRET_ANIM_ALERT && obj->currentMove != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_IDLE, lbl_803E59DC, 0);
            animState->animStepScale = gDrLaserTurretDefaultAnimStepScale;
        }
    }
    state->actionTimer = state->actionTimer - timeDelta;
    if (state->actionTimer <= lbl_803E59DC &&
        (state->flags & DR_LASERTURRET_FLAG_ACTION_ACTIVE) == 0)
    {
        Sfx_PlayFromObject((int)obj, DR_LASERTURRET_SFX_ACTION);
        if (obj->currentMove == DR_LASERTURRET_ANIM_ALERT)
        {
            ObjAnim_SetCurrentMove((int)obj, DR_LASERTURRET_ANIM_TRACKING, lbl_803E5A08, 0);
            animState->animStepScale = lbl_803E5A0C;
        }
        else
        {
            rng = randomGetRange(0, 1);
            ObjAnim_SetCurrentMove((int)obj, gDrLaserTurretIdleAnimMoves[rng], lbl_803E59DC, 0);
            animState->animStepScale = gDrLaserTurretIdleAnimStepScales[rng];
        }
        state->flags = state->flags | DR_LASERTURRET_FLAG_ACTION_ACTIVE;
    }
    if (GameBit_Get(DR_LASERTURRET_GAMEBIT_SHOP_OPEN) == 0)
    {
        pushState = DR_LASERTURRET_STATE_PUSH_TRACKING;
        stack = state->stateStack;
        if (Stack_IsFull(stack) == 0)
        {
            Stack_Push(stack, &pushState);
        }
        return DR_LASERTURRET_STATE_CONTINUE;
    }
    t = shopKeeperRotateFn_801e7c4c(obj, playerObj, 0);
    rate = lbl_803E5A10;
    if (t > lbl_803E5A18)
    {
        target = lbl_803E5A14;
    }
    else
    {
        target = lbl_803E59DC;
    }
    d = rate * (target - animState->aimBlend);
    animState->aimBlend = d * timeDelta + animState->aimBlend;
    if (animState->aimBlend > lbl_803E5A1C)
    {
        animState->aimBlend = lbl_803E59DC;
    }
    animState->aimBlend = lbl_803E59DC;
    count = hitDetectFn_80065e50(obj, obj->x, obj->y, obj->z, &arr, 0, 0);
    minDist = lbl_803E5A20;
    for (idx = 0; idx < count; idx++)
    {
        dist = *(f32*)arr[idx] - obj->y;
        if (dist < lbl_803E59DC)
        {
            dist = -dist;
        }
        if (dist < minDist)
        {
            state->bobBaseY = lbl_803E59E0 + *(f32*)arr[idx];
            minDist = dist;
        }
    }
    obj->y =
        state->bobAmplitude *
        mathSinf(
            (double)(gDrLaserTurretPi *
                (float)(u32)state->bobPhase /
                gDrLaserTurretBobPhaseScale)) +
        state->bobBaseY;
    sum = state->bobPhase + framesThisStep * 0x100;
    if (sum > 0xffff)
    {
        float rngf;
        rng = randomGetRange(0xf, 0x23);
        rngf = (float)rng;
        rngf = lbl_803E59F0 * rngf;
        state->bobAmplitude = rngf;
    }
    state->bobPhase = sum;
    if (ObjTrigger_IsSet(obj) != 0)
    {
        rng = randomGetRange(0, 2);
        (*gObjectTriggerInterface)->runSequence(rng, obj, -1);
    }
    return 0;
}

int DRlaserturret_startLinkedTarget(DRLaserTurretObject* obj)
{
    DRLaserTurretState* state;

    state = obj->state;
    if (GameBit_Get(DR_LASERTURRET_GAMEBIT_LINK_READY) == 0)
    {
        return 0;
    }
    if ((int)GameBit_Get(DR_LASERTURRET_GAMEBIT_LINK_STARTED) == 0)
    {
        int* target;
        GameBit_Set(DR_LASERTURRET_GAMEBIT_LINK_STARTED, 1);
        target = state->linkedTarget;
        (**(VtableFn***)((char*)target + 0x68))[0x24 / 4](target, 1, 2);
    }
    return DR_LASERTURRET_STATE_LINKED_TARGET;
}

int DRlaserturret_handlePromptChoice(DRLaserTurretObject* obj, void* param2, int dispatch)
{
    DRLaserTurretState* state;
    char stickHi;
    char stickLo;
    int btn;
    int cv;
    char nudge;
    ObjTextureRuntimeSlot* texture;

    state = obj->state;
    if (dispatch == DR_LASERTURRET_PROMPT_COUNT)
    {
        padGetAnalogInput(0, &stickHi, &stickLo);
        if ((s8)stickLo < 0)
        {
            state->countValue--;
            Sfx_PlayFromObject(0, DR_LASERTURRET_SFX_PROMPT_TICK);
        }
        else if ((s8)stickLo > 0)
        {
            state->countValue++;
            Sfx_PlayFromObject(0, DR_LASERTURRET_SFX_PROMPT_TICK);
        }
        if (state->countValue > state->maxCount)
        {
            state->countValue = state->maxCount;
        }
        if (state->countValue > state->countScale << 1)
        {
            state->countValue = (s16)(state->countScale << 1);
        }
        else if (state->countValue < state->countScale >> 1)
        {
            state->countValue = (s16)(state->countScale >> 1);
        }
        cv = state->countValue;
        texture = objFindTexture(obj, DR_LASERTURRET_ONES_TEXTURE_SLOT, 0);
        texture->textureId = (cv % 10) << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
        texture = objFindTexture(obj, DR_LASERTURRET_TENS_TEXTURE_SLOT, 0);
        texture->textureId = ((cv / 10) % 10) << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
        cv = cv / 100;
        if (cv > DR_LASERTURRET_MAX_DIGIT) cv = DR_LASERTURRET_MAX_DIGIT;
        texture = objFindTexture(obj, DR_LASERTURRET_HUNDREDS_TEXTURE_SLOT, 0);
        texture->textureId = cv << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
    }
    else if (dispatch == DR_LASERTURRET_PROMPT_DIGIT_COUNT)
    {
        padGetAnalogInput(0, &stickHi, &stickLo);
        if ((s8)stickLo < 0)
        {
            state->digitCount--;
            Sfx_PlayFromObject(0, DR_LASERTURRET_SFX_PROMPT_TICK);
        }
        else if ((s8)stickLo > 0)
        {
            state->digitCount++;
            Sfx_PlayFromObject(0, DR_LASERTURRET_SFX_PROMPT_TICK);
        }
        if (state->digitCount > state->maxCount)
        {
            state->digitCount = state->maxCount;
        }
        if (state->digitCount > DR_LASERTURRET_MAX_DIGIT_COUNT)
        {
            state->digitCount = DR_LASERTURRET_MAX_DIGIT_COUNT;
        }
        else if (state->digitCount < DR_LASERTURRET_MIN_DIGIT_COUNT)
        {
            state->digitCount = DR_LASERTURRET_MIN_DIGIT_COUNT;
        }
        {
            cv = state->digitCount;
            texture = objFindTexture(obj, DR_LASERTURRET_ONES_TEXTURE_SLOT, 0);
            texture->textureId = (cv % 10) << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
            texture = objFindTexture(obj, DR_LASERTURRET_TENS_TEXTURE_SLOT, 0);
            texture->textureId = ((cv / 10) % 10) << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
            cv = cv / 100;
            if (cv > DR_LASERTURRET_MAX_DIGIT) cv = DR_LASERTURRET_MAX_DIGIT;
            texture = objFindTexture(obj, DR_LASERTURRET_HUNDREDS_TEXTURE_SLOT, 0);
            texture->textureId = cv << DR_LASERTURRET_DIGIT_TEXTURE_SHIFT;
        }
        btn = getButtonsJustPressed(0);
        if ((btn & DR_LASERTURRET_BUTTON_CANCEL) != 0u)
        {
            state->flags = state->flags | DR_LASERTURRET_FLAG_CONFIRM_PROMPT;
            (*gScreenTransitionInterface)->start(0x1e, 1);
            return 1;
        }
    }
    btn = getButtonsJustPressed(0);
    if ((btn & DR_LASERTURRET_BUTTON_ACCEPT) == 0u)
    {
        return 0;
    }
    if (state->countValue < state->countTarget)
    {
        nudge = (state->nudgeCount < DR_LASERTURRET_MAX_NUDGE_COUNT) ? 0 : 2;
    }
    else
    {
        nudge = 1;
    }
    switch (dispatch)
    {
    case DR_LASERTURRET_PROMPT_COUNT:
        if ((s8)nudge == 0)
        {
            state->nudgeCount++;
        }
        return nudge == 0;
    case DR_LASERTURRET_PROMPT_NUDGE:
        if ((s8)nudge == 1)
        {
            int* target = state->linkedTarget;
            (**(VtableFn***)((char*)target + 0x68))[0x48 / 4](target);
        }
        return nudge == 1;
    case DR_LASERTURRET_PROMPT_MAX_NUDGE:
        return nudge == 2;
    }
    return 0;
}

void DRlaserturret_startTimedChallenge(DRLaserTurretObject* obj)
{
    DRLaserTurretState* state;

    state = obj->state;
    if ((state->flags & DR_LASERTURRET_FLAG_START_SEQUENCE) != 0)
    {
        int* target;
        gameTimerInit(0x11, 0x1e);
        timerSetToCountUp();
        hudFn_8011f6f0(1);
        GameBit_Set(DR_LASERTURRET_GAMEBIT_TIMER_STARTED, 1);
        target = state->linkedTarget;
        (**(VtableFn***)((char*)target + 0x68))[0x4c / 4](target, state->digitCount);
        (*(VtableFn**)gTitleMenuControlInterface)[0x4 / 4](0, 0xf5, 0, 0, 0);
    }
    else
    {
        hudFn_8011f38c(0);
    }
    state->flags = 0;
}
