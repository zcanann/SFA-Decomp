/*
 * levelname (DLL 0xF8) - the on-screen "level name" banner object.
 *
 * A placement-spawned marker that animates a text banner in and out as the
 * player approaches. The obj extra (0x18 bytes) is the shared TFrameAnimator
 * / LevelnameState record; a phase byte at 0x14 drives a small state machine:
 *   phase 0  wait until the player is within the trigger radius, then (if
 *            armed) set the enable game bit and advance.
 *   phase 1  slide the banner in - raise the text Y offset by 4 per frame
 *            until it reaches 0xdc (220).
 *   phase 2  hold, wobbling the Y offset with a sine while counting elapsed
 *            frames against the duration cap, then advance.
 *   phase 3  slide the banner out - lower the Y offset to 0, then settle.
 *   phase 4  idle.
 * The sequence callback (LevelName_SeqFn) reacts to anim event id 1 by
 * setting the enable game bit and jumping straight to phase 1.
 *
 * Render/hitDetect/free/release/initialise are empty; behaviour is driven
 * entirely by update() and the sequence callback.
 */
#include "main/object_api.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/textrender_api.h"
#include "main/vecmath.h"
#include "main/dll/dll_00F8_levelname.h"
#include "main/object_descriptor.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

#define LEVELNAME_PHASE_WAIT      0
#define LEVELNAME_PHASE_SLIDE_IN  1
#define LEVELNAME_PHASE_HOLD      2
#define LEVELNAME_PHASE_SLIDE_OUT 3
#define LEVELNAME_PHASE_IDLE      4

#define LEVELNAME_BANNER_Y_MAX  0xdc
#define LEVELNAME_BANNER_Y_STEP 4
#define LEVELNAME_SEQEV_SHOW    1 /* anim event id that triggers the banner */
#define LEVELNAME_SEQFN_HANDLED 4 /* LevelName_SeqFn return when the show event fired */


int LevelName_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    LevelNameState* state = obj->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == LEVELNAME_SEQEV_SHOW)
        {
            if (state->enableGameBit != -1)
            {
                mainSetBits(state->enableGameBit, 1);
            }
            state->phase = LEVELNAME_PHASE_SLIDE_IN;
            return LEVELNAME_SEQFN_HANDLED;
        }
    }
    return 0;
}

int LevelName_getExtraSize(void)
{
    return sizeof(LevelNameState);
}
int LevelName_getObjectTypeId(void)
{
    return 0x0;
}

void LevelName_free(void)
{
}

void LevelName_render(void)
{
}

void LevelName_hitDetect(void)
{
}

void LevelName_update(GameObject* obj)
{
    LevelNameState* state;
    GameObject* player;

    state = obj->extra;
    switch (state->phase)
    {
    case LEVELNAME_PHASE_WAIT:
        player = Obj_GetPlayerObject();
        if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < (f32)(u32)state->triggerRadius)
        {
            if (state->enableGameBit != -1)
            {
                mainSetBits(state->enableGameBit, 1);
            }
            state->phase = LEVELNAME_PHASE_SLIDE_IN;
        }
        break;
    case LEVELNAME_PHASE_SLIDE_IN:
        state->bannerY = (s16)(state->bannerY + framesThisStep * LEVELNAME_BANNER_Y_STEP);
        if (state->bannerY > LEVELNAME_BANNER_Y_MAX)
        {
            state->bannerY = LEVELNAME_BANNER_Y_MAX;
            state->phase = LEVELNAME_PHASE_HOLD;
        }
        break;
    case LEVELNAME_PHASE_HOLD:
    {
        state->elapsedFrames += framesThisStep;
        if ((u32)state->elapsedFrames > (u32)state->holdDuration)
        {
            state->phase = LEVELNAME_PHASE_SLIDE_OUT;
        }
        state->bannerY =
            (s16)((s32)(30.0f *
                        mathSinf((3.1415927410125732f * (f32)((s32)state->elapsedFrames * 0x500)) /
                                 32768.0f)) +
                  LEVELNAME_BANNER_Y_MAX);
        break;
    }
    case LEVELNAME_PHASE_SLIDE_OUT:
        state->bannerY = (s16)(state->bannerY - framesThisStep * LEVELNAME_BANNER_Y_STEP);
        if (state->bannerY < 0)
        {
            state->bannerY = 0;
            state->phase = LEVELNAME_PHASE_IDLE;
        }
        break;
    case LEVELNAME_PHASE_IDLE:
        break;
    }
}

void LevelName_init(GameObject* obj, LevelNamePlacement* placement)
{
    LevelNameState* state;
    int* text;

    state = obj->extra;
    obj->animEventCallback = LevelName_SeqFn;
    text = (int*)gameTextGet(placement->textId);
    state->textData = **(int**)(text + 2);
    state->holdDuration = 0x64;
    state->textRecord = (int)text;
    state->triggerRadius = placement->triggerRadius;
    state->enableGameBit = placement->enableGameBit;
    state->phase = LEVELNAME_PHASE_WAIT;
    state->bannerY = 0;
    state->elapsedFrames = 0;
    if (state->enableGameBit != -1)
    {
        if (mainGetBit(state->enableGameBit) != 0)
        {
            state->phase = LEVELNAME_PHASE_IDLE;
        }
    }
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void LevelName_release(void)
{
}

void LevelName_initialise(void)
{
}

ObjectDescriptor gLevelNameObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    LevelName_initialise,
    LevelName_release,
    0,
    (ObjectDescriptorCallback)LevelName_init,
    (ObjectDescriptorCallback)LevelName_update,
    (ObjectDescriptorCallback)LevelName_hitDetect,
    (ObjectDescriptorCallback)LevelName_render,
    (ObjectDescriptorCallback)LevelName_free,
    (ObjectDescriptorCallback)LevelName_getObjectTypeId,
    LevelName_getExtraSize,
};
