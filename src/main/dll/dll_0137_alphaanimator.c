/*
 * DLL 0x137 - AlphaAnimator
 *
 * Object that animates the alpha/fade of the map block it sits in. On the
 * first tick where its block is loaded (MapBlockData.unk4 & 8) it latches the
 * placement's params into AlphaAnimatorState, reads the arming game-bit
 * (placement gateBit), seeds the fade level, and for mode 3 allocates a
 * per-vertex alpha buffer. Each subsequent tick it ramps alphaLevel toward the
 * target by (rate * framesThisStep), gated by the game-bit, in one of four
 * modes (modeFlags & 3):
 *   0 - one-shot ramp to target, then sets completion bit (completeBit) and stops
 *   1 - ping-pong between startAlpha and targetAlpha bounds
 *   2 - bidirectional ramp driven by the live gate bit; plays sfxId on a gate
 *       transition (when modeFlags>>2 set) and sets/clears the completion bit
 *   3 - timeDelta-based float fade (fadeA/fadeB), sets completion bit at fadeMax
 * doneCount counts finished ramps and freezes the object once it exceeds 2.
 * AlphaAnimator_render draws via objRenderModelAndHitVolumes; AlphaAnimator_free
 * releases the mode-3 buffer.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/mm.h"
#include "main/lightmap_api.h"
#include "main/object_descriptor.h"

typedef struct AlphaanimatorPlacement
{
    ObjPlacement head; /* 0x00 */
    s16 gateBit;
    s16 completeBit;
    u8 startAlpha;
    u8 targetAlpha;
    u8 active;
    s8 rate;
    u8 modeFlags;
    u8 pad21[0x22 - 0x21];
    u16 fadeMax;
    u16 sfxId;
    u8 pad26[0x28 - 0x26];
} AlphaanimatorPlacement;

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

/* AlphaanimatorPlacement.modeFlags & 3 - alpha-fade mode */
#define ALPHAANIM_MODE_ONESHOT  0 /* ramp to target once, set completeBit, stop */
#define ALPHAANIM_MODE_PINGPONG 1 /* bounce between startAlpha and targetAlpha */
#define ALPHAANIM_MODE_GATED    2 /* direction follows live gate bit; sfx on gate flip */
#define ALPHAANIM_MODE_TIMED    3 /* timeDelta float fade (fadeA/fadeMax) */


int AlphaAnimator_getExtraSize(void)
{
    return 0x1c;
}
int AlphaAnimator_getObjectTypeId(void)
{
    return 0x0;
}

void AlphaAnimator_free(int* obj)
{
    AlphaAnimatorState* state = (AlphaAnimatorState*)((GameObject*)obj)->extra;
    void* buf = state->buf;
    if (buf != NULL)
        mm_free(buf);
}

void AlphaAnimator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void AlphaAnimator_hitDetect(void)
{
}

void AlphaAnimator_update(int* obj)
{
    AlphaanimatorPlacement* placement;
    AlphaAnimatorState* state;
    int mode;
    MapBlockData* block;
    f32 absRate;
    int lvl;
    placement = (AlphaanimatorPlacement*)((GameObject*)obj)->anim.placementData;
    state = (AlphaAnimatorState*)((GameObject*)obj)->extra;
    mode = placement->modeFlags & 3;
    block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                            (double)((GameObject*)obj)->anim.localPosY,
                                            (double)((GameObject*)obj)->anim.localPosZ));
    if (block == NULL)
    {
        state->doneCount = 0;
        return;
    }
    if ((block->flags4 & 8) == 0)
    {
        return;
    }
    if (state->vertCount == 0)
    {
        state->active = placement->active;
        if (state->vertCount == 0)
        {
            state->active = 0;
        }
        if ((s8)state->active == 0)
        {
            return;
        }
        state->fadeB = state->fadeA = 0.0f;
        state->fadeMax = (f32)(u32)placement->fadeMax;
        if (placement->gateBit == -1)
        {
            state->gateVal = 1;
        }
        else
        {
            state->gateVal = mainGetBit(placement->gateBit);
        }
        state->alphaLevel = placement->startAlpha;
        if (placement->completeBit != -1 && mainGetBit(placement->completeBit) != 0)
        {
            state->alphaLevel = placement->targetAlpha;
            state->fadeA = 1.0f + state->fadeMax;
            state->gateVal = 1;
        }
        if (mode == ALPHAANIM_MODE_TIMED)
        {
            state->buf = mmAlloc(state->vertCount << 2, 5, 0);
        }
        /* double-toggle of bit 0 - a real no-op present in retail */
        block->flags4 = block->flags4 ^ 1;
        block->flags4 = block->flags4 ^ 1;
    }
    if ((s8)state->active == 0)
    {
        return;
    }
    if (mode == ALPHAANIM_MODE_GATED)
    {
        state->gateVal = mainGetBit(placement->gateBit);
        if ((s8)state->doneCount > 2 && (s8)state->gateVal != (s8)state->prevGate)
        {
            if ((placement->modeFlags >> 2) != 0)
            {
                Sfx_PlayFromObject((u32)obj, placement->sfxId);
            }
            state->doneCount = 0;
            state->prevGate = state->gateVal;
        }
        if ((s8)state->doneCount > 2)
        {
            return;
        }
    }
    else
    {
        if ((s8)state->doneCount > 2)
        {
            return;
        }
        if ((s8)state->gateVal == 0)
        {
            state->gateVal = mainGetBit(placement->gateBit);
            if ((s8)state->gateVal == 0)
            {
                return;
            }
            if ((placement->modeFlags >> 2) != 0)
            {
                Sfx_PlayFromObject((u32)obj, placement->sfxId);
            }
        }
    }
    switch (mode)
    {
    case ALPHAANIM_MODE_ONESHOT:
        if (placement->startAlpha > placement->targetAlpha)
        {
            state->alphaLevel = (s16)(state->alphaLevel - placement->rate * framesThisStep);
            if (state->alphaLevel <= placement->targetAlpha)
            {
                state->alphaLevel = placement->targetAlpha;
                if (placement->completeBit != -1)
                {
                    mainSetBits(placement->completeBit, 1);
                }
                state->doneCount += 1;
            }
        }
        else
        {
            state->alphaLevel = (s16)(state->alphaLevel + placement->rate * framesThisStep);
            if (state->alphaLevel >= placement->targetAlpha)
            {
                state->alphaLevel = placement->targetAlpha;
                if (placement->completeBit != -1)
                {
                    mainSetBits(placement->completeBit, 1);
                }
                state->doneCount += 1;
            }
        }
        break;
    case ALPHAANIM_MODE_PINGPONG:
        if (placement->startAlpha > placement->targetAlpha)
        {
            state->alphaLevel = (s16)(state->alphaLevel - placement->rate * framesThisStep);
            if (state->alphaLevel < placement->targetAlpha)
            {
                state->alphaLevel = (s16)(placement->startAlpha - (int)(placement->targetAlpha - state->alphaLevel));
            }
        }
        else
        {
            state->alphaLevel = (s16)(state->alphaLevel + placement->rate * framesThisStep);
            lvl = state->alphaLevel;
            if (lvl > placement->startAlpha)
            {
                lvl -= placement->targetAlpha;
                state->alphaLevel = (s16)(placement->targetAlpha + lvl);
            }
        }
        break;
    case ALPHAANIM_MODE_GATED:
        if ((s8)state->gateVal != 0)
        {
            if (placement->startAlpha > placement->targetAlpha)
            {
                state->alphaLevel = (s16)(state->alphaLevel - placement->rate * framesThisStep);
                if (state->alphaLevel > placement->targetAlpha)
                {
                    return;
                }
                state->alphaLevel = placement->targetAlpha;
                if (placement->completeBit != -1)
                {
                    mainSetBits(placement->completeBit, 1);
                }
                state->doneCount += 1;
            }
            else
            {
                state->alphaLevel = (s16)(state->alphaLevel + placement->rate * framesThisStep);
                if (state->alphaLevel < placement->targetAlpha)
                {
                    return;
                }
                state->alphaLevel = placement->targetAlpha;
                if (placement->completeBit != -1)
                {
                    mainSetBits(placement->completeBit, 1);
                }
                state->doneCount += 1;
            }
        }
        else
        {
            if (placement->startAlpha > placement->targetAlpha)
            {
                state->alphaLevel = (s16)(state->alphaLevel + placement->rate * framesThisStep);
                if (state->alphaLevel < placement->startAlpha)
                {
                    return;
                }
                state->alphaLevel = placement->startAlpha;
                if (placement->completeBit != -1)
                {
                    mainSetBits(placement->completeBit, 0);
                }
                state->doneCount += 1;
            }
            else
            {
                state->alphaLevel = (s16)(state->alphaLevel - placement->rate * framesThisStep);
                if (state->alphaLevel > placement->startAlpha)
                {
                    return;
                }
                state->alphaLevel = placement->startAlpha;
                if (placement->completeBit != -1)
                {
                    mainSetBits(placement->completeBit, 0);
                }
                state->doneCount += 1;
            }
        }
        break;
    case ALPHAANIM_MODE_TIMED:
    {
        int rate = placement->rate;
        if (rate < 0)
        {
            rate = -rate;
        }
        absRate = (f32)rate / 10.0f;
        state->fadeA = absRate * timeDelta + state->fadeA;
        if (state->fadeA > state->fadeMax)
        {
            state->fadeA = state->fadeMax;
            mainSetBits(placement->completeBit, 1);
            state->doneCount += 1;
        }
        state->fadeB = state->fadeA - 50.0f;
        break;
    }
    }
}

void AlphaAnimator_init(int* obj)
{
    *(s8*)&((AlphaAnimatorState*)((GameObject*)obj)->extra)->prevGate = -1;
}

void AlphaAnimator_release(void)
{
}

void AlphaAnimator_initialise(void)
{
}

ObjectDescriptor gAlphaAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)AlphaAnimator_initialise,
    (ObjectDescriptorCallback)AlphaAnimator_release,
    0,
    (ObjectDescriptorCallback)AlphaAnimator_init,
    (ObjectDescriptorCallback)AlphaAnimator_update,
    (ObjectDescriptorCallback)AlphaAnimator_hitDetect,
    (ObjectDescriptorCallback)AlphaAnimator_render,
    (ObjectDescriptorCallback)AlphaAnimator_free,
    (ObjectDescriptorCallback)AlphaAnimator_getObjectTypeId,
    AlphaAnimator_getExtraSize,
};
