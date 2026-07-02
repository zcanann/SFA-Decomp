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
 * The sequence callback (levelname_SeqFn) reacts to anim event id 1 by
 * setting the enable game bit and jumping straight to phase 1.
 *
 * Render/hitDetect/free/release/initialise are empty; behaviour is driven
 * entirely by update() and the sequence callback. Exported through
 * gAreaObjDescriptor (the name is reused per-DLL) with 10 callback slots.
 */
#include "main/dll/tFrameAnimator.h"
#include "main/dll/levelnamestate_struct.h"
#include "main/game_object.h"
#include "main/dll/tframeanimator_state.h"
#include "main/engine_shared.h"

#define LEVELNAME_OBJFLAG_HITDETECT_DISABLED 0x2000
extern void GameBit_Set(int eventId, int value);
extern f32 Vec_distance(f32* a, f32* b);
extern f32 lbl_803E36E0;
extern f32 lbl_803E36E4;
extern f32 lbl_803E36E8;

int area_getExtraSize(void);
int area_getObjectTypeId(void);
void area_free(void);
void area_render(void);
void area_hitDetect(void);
void area_update(void);
void area_init(GameObject* obj);
void area_release(void);
void area_initialise(void);

#define LEVELNAME_PHASE_WAIT 0
#define LEVELNAME_PHASE_SLIDE_IN 1
#define LEVELNAME_PHASE_HOLD 2
#define LEVELNAME_PHASE_SLIDE_OUT 3
#define LEVELNAME_PHASE_IDLE 4

#define LEVELNAME_PHASE 0x14       /* state machine phase byte (struct .phase) */
#define LEVELNAME_TRIGGER_DIST 0xc /* trigger radius byte in the extra record */
#define LEVELNAME_BANNER_Y_MAX 0xdc
#define LEVELNAME_BANNER_Y_STEP 4
#define LEVELNAME_SEQEV_SHOW 1     /* anim event id that triggers the banner */
#define LEVELNAME_SEQFN_HANDLED 4  /* levelname_SeqFn return when the show event fired */

void levelname_free(void)
{
}

void levelname_render(void)
{
}

void levelname_hitDetect(void)
{
}

void levelname_release(void)
{
}

void levelname_initialise(void)
{
}

void levelname_update(int* obj)
{
    u8* state;
    int* player;

    state = ((GameObject*)obj)->extra;
    switch (state[LEVELNAME_PHASE])
    {
    case LEVELNAME_PHASE_WAIT:
        player = Obj_GetPlayerObject();
        if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) <
            (f32)(u32)state[LEVELNAME_TRIGGER_DIST])
        {
            if (((LevelnameState*)state)->gameBit != -1)
            {
                GameBit_Set(((LevelnameState*)state)->gameBit, 1);
            }
            state[LEVELNAME_PHASE] = LEVELNAME_PHASE_SLIDE_IN;
        }
        break;
    case LEVELNAME_PHASE_SLIDE_IN:
        ((LevelnameState*)state)->bannerY = (s16)(((LevelnameState*)state)->bannerY + framesThisStep * LEVELNAME_BANNER_Y_STEP);
        if (((LevelnameState*)state)->bannerY > LEVELNAME_BANNER_Y_MAX)
        {
            ((LevelnameState*)state)->bannerY = LEVELNAME_BANNER_Y_MAX;
            state[LEVELNAME_PHASE] = LEVELNAME_PHASE_HOLD;
        }
        break;
    case LEVELNAME_PHASE_HOLD:
        {
            ((LevelnameState*)state)->holdTimer += framesThisStep;
            if ((u32)((LevelnameState*)state)->holdTimer > (u32)((LevelnameState*)state)->holdDuration)
            {
                state[LEVELNAME_PHASE] = LEVELNAME_PHASE_SLIDE_OUT;
            }
            ((LevelnameState*)state)->bannerY = (s16)(
                (s32)(lbl_803E36E0 * mathSinf(
                    (lbl_803E36E4 * (f32)((s32)((LevelnameState*)state)->holdTimer * 0x500)) / lbl_803E36E8)) + LEVELNAME_BANNER_Y_MAX);
            break;
        }
    case LEVELNAME_PHASE_SLIDE_OUT:
        ((LevelnameState*)state)->bannerY = (s16)(((LevelnameState*)state)->bannerY - framesThisStep * LEVELNAME_BANNER_Y_STEP);
        if (((LevelnameState*)state)->bannerY < 0)
        {
            ((LevelnameState*)state)->bannerY = 0;
            state[LEVELNAME_PHASE] = LEVELNAME_PHASE_IDLE;
        }
        break;
    case LEVELNAME_PHASE_IDLE:
        break;
    }
}

void levelname_init(int obj, int objDef)
{
    int* state;
    int* text;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = levelname_SeqFn;
    text = (int*)gameTextGet(*(int*)(objDef + 0x1c));
    ((TFrameAnimatorState*)state)->unk4 = **(int**)(text + 2);
    ((TFrameAnimatorState*)state)->duration = 0x64;
    ((TFrameAnimatorState*)state)->textRecord = (int)text;
    ((TFrameAnimatorState*)state)->unkC = *(u8*)(objDef + 0x20);
    ((TFrameAnimatorState*)state)->enableGameBit = *(s16*)(objDef + 0x18);
    ((TFrameAnimatorState*)state)->phase = LEVELNAME_PHASE_WAIT;
    ((TFrameAnimatorState*)state)->bannerY = 0;
    ((TFrameAnimatorState*)state)->elapsedFrames = 0;
    if (((TFrameAnimatorState*)state)->enableGameBit != -1)
    {
        if (GameBit_Get(((TFrameAnimatorState*)state)->enableGameBit) != 0)
        {
            ((TFrameAnimatorState*)state)->phase = LEVELNAME_PHASE_IDLE;
        }
    }
    ((GameObject*)obj)->objectFlags |= LEVELNAME_OBJFLAG_HITDETECT_DISABLED;
}

int levelname_getExtraSize(void) { return 0x18; }
int levelname_getObjectTypeId(void) { return 0x0; }

int levelname_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* state = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == LEVELNAME_SEQEV_SHOW)
        {
            if (((TFrameAnimatorState*)state)->enableGameBit != -1)
            {
                GameBit_Set(((TFrameAnimatorState*)state)->enableGameBit, 1);
            }
            ((TFrameAnimatorState*)state)->phase = LEVELNAME_PHASE_SLIDE_IN;
            return LEVELNAME_SEQFN_HANDLED;
        }
    }
    return 0;
}

ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)area_initialise,
    (ObjectDescriptorCallback)area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};
