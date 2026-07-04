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
 * alphaanimator_render draws via objRenderFn_8003b8f4; alphaanimator_free
 * releases the mode-3 buffer.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/mm.h"
#include "main/sfa_shared_decls.h"
extern void* mapGetBlock(int i);
extern void objRenderFn_8003b8f4(f32);
extern void Sfx_PlayFromObject(int* obj, int id);
extern u8 framesThisStep;
extern f32 timeDelta;
/* shared .sdata2 float constants (retail links these from a common pool;
 * the retail object imports them as externs, so they must not be spelled
 * as literals here) */
extern f32 lbl_803E3F78; /* = 1.0f */
extern f32 lbl_803E3F7C; /* = 0.0f */
extern f32 lbl_803E3F80; /* = 10.0f (mode-3 rate divisor) */
extern f32 lbl_803E3F84; /* = 50.0f (fadeB trails fadeA by 50) */

typedef struct AlphaanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
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
#define ALPHAANIM_MODE_ONESHOT 0   /* ramp to target once, set completeBit, stop */
#define ALPHAANIM_MODE_PINGPONG 1  /* bounce between startAlpha and targetAlpha */
#define ALPHAANIM_MODE_GATED 2     /* direction follows live gate bit; sfx on gate flip */
#define ALPHAANIM_MODE_TIMED 3     /* timeDelta float fade (fadeA/fadeMax) */

void alphaanimator_free(int* obj)
{
    AlphaAnimatorState* o = (AlphaAnimatorState*)((GameObject*)obj)->extra;
    void* p = o->buf;
    if (p != NULL) mm_free(p);
}

void alphaanimator_hitDetect(void)
{
}

void alphaanimator_release(void)
{
}

void alphaanimator_initialise(void)
{
}

int alphaanimator_getExtraSize(void) { return 0x1c; }
int alphaanimator_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
void alphaanimator_init(int* obj)
{
    *(s8*)&((AlphaAnimatorState*)((GameObject*)obj)->extra)->prevGate = -1;
}

#pragma scheduling on
#pragma peephole off
void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderFn_8003b8f4(lbl_803E3F78);
}

#pragma scheduling off
void alphaanimator_update(int* obj)
{
 /* #57 */
    AlphaanimatorPlacement* d;
    AlphaAnimatorState* s;
    int mode;
    MapBlockData* block;
    f32 absRate;
    int lvl;
    d = (AlphaanimatorPlacement*)((GameObject*)obj)->anim.placementData;
    s = (AlphaAnimatorState*)((GameObject*)obj)->extra;
    mode = d->modeFlags & 3;
    block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                            (double)((GameObject*)obj)->anim.localPosY,
                                            (double)((GameObject*)obj)->anim.localPosZ));
    if (block == NULL)
    {
        s->doneCount = 0;
        return;
    }
    if ((block->flags4 & 8) == 0)
    {
        return;
    }
    if (s->vertCount == 0)
    {
        s->active = d->active;
        if (s->vertCount == 0)
        {
            s->active = 0;
        }
        if ((s8)s->active == 0)
        {
            return;
        }
        s->fadeB = s->fadeA = lbl_803E3F7C;
        s->fadeMax = (f32)(u32)d->fadeMax;
        if (d->gateBit == -1)
        {
            s->gateVal = 1;
        }
        else
        {
            s->gateVal = GameBit_Get(d->gateBit);
        }
        s->alphaLevel = d->startAlpha;
        if (d->completeBit != -1 && GameBit_Get(d->completeBit) != 0)
        {
            s->alphaLevel = d->targetAlpha;
            s->fadeA = lbl_803E3F78 + s->fadeMax;
            s->gateVal = 1;
        }
        if (mode == ALPHAANIM_MODE_TIMED)
        {
            s->buf = mmAlloc(s->vertCount << 2, 5, 0);
        }
        /* double-toggle of bit 0 - a real no-op present in retail */
        block->flags4 = block->flags4 ^ 1;
        block->flags4 = block->flags4 ^ 1;
    }
    if ((s8)s->active == 0)
    {
        return;
    }
    if (mode == ALPHAANIM_MODE_GATED)
    {
        s->gateVal = GameBit_Get(d->gateBit);
        if ((s8)s->doneCount > 2 &&
            (s8)s->gateVal != (s8)s->prevGate)
        {
            if ((d->modeFlags >> 2) != 0)
            {
                Sfx_PlayFromObject(obj, d->sfxId);
            }
            s->doneCount = 0;
            s->prevGate = s->gateVal;
        }
        if ((s8)s->doneCount > 2)
        {
            return;
        }
    }
    else
    {
        if ((s8)s->doneCount > 2)
        {
            return;
        }
        if ((s8)s->gateVal == 0)
        {
            s->gateVal = GameBit_Get(d->gateBit);
            if ((s8)s->gateVal == 0)
            {
                return;
            }
            if ((d->modeFlags >> 2) != 0)
            {
                Sfx_PlayFromObject(obj, d->sfxId);
            }
        }
    }
    switch (mode)
    {
    case ALPHAANIM_MODE_ONESHOT:
        if (d->startAlpha > d->targetAlpha)
        {
            s->alphaLevel =
                (s16)(s->alphaLevel - d->rate * framesThisStep);
            if (s->alphaLevel <= d->targetAlpha)
            {
                s->alphaLevel = d->targetAlpha;
                if (d->completeBit != -1)
                {
                    GameBit_Set(d->completeBit, 1);
                }
                s->doneCount += 1;
            }
        }
        else
        {
            s->alphaLevel =
                (s16)(s->alphaLevel + d->rate * framesThisStep);
            if (s->alphaLevel >= d->targetAlpha)
            {
                s->alphaLevel = d->targetAlpha;
                if (d->completeBit != -1)
                {
                    GameBit_Set(d->completeBit, 1);
                }
                s->doneCount += 1;
            }
        }
        break;
    case ALPHAANIM_MODE_PINGPONG:
        if (d->startAlpha > d->targetAlpha)
        {
            s->alphaLevel =
                (s16)(s->alphaLevel - d->rate * framesThisStep);
            if (s->alphaLevel < d->targetAlpha)
            {
                s->alphaLevel =
                    (s16)(d->startAlpha -
                        (int)(d->targetAlpha - s->alphaLevel));
            }
        }
        else
        {
            s->alphaLevel =
                (s16)(s->alphaLevel + d->rate * framesThisStep);
            lvl = s->alphaLevel;
            if (lvl > d->startAlpha)
            {
                lvl -= d->targetAlpha;
                s->alphaLevel = (s16)(d->targetAlpha + lvl);
            }
        }
        break;
    case ALPHAANIM_MODE_GATED:
        if ((s8)s->gateVal != 0)
        {
            if (d->startAlpha > d->targetAlpha)
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel - d->rate * framesThisStep);
                if (s->alphaLevel > d->targetAlpha)
                {
                    return;
                }
                s->alphaLevel = d->targetAlpha;
                if (d->completeBit != -1)
                {
                    GameBit_Set(d->completeBit, 1);
                }
                s->doneCount += 1;
            }
            else
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel + d->rate * framesThisStep);
                if (s->alphaLevel < d->targetAlpha)
                {
                    return;
                }
                s->alphaLevel = d->targetAlpha;
                if (d->completeBit != -1)
                {
                    GameBit_Set(d->completeBit, 1);
                }
                s->doneCount += 1;
            }
        }
        else
        {
            if (d->startAlpha > d->targetAlpha)
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel + d->rate * framesThisStep);
                if (s->alphaLevel < d->startAlpha)
                {
                    return;
                }
                s->alphaLevel = d->startAlpha;
                if (d->completeBit != -1)
                {
                    GameBit_Set(d->completeBit, 0);
                }
                s->doneCount += 1;
            }
            else
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel - d->rate * framesThisStep);
                if (s->alphaLevel > d->startAlpha)
                {
                    return;
                }
                s->alphaLevel = d->startAlpha;
                if (d->completeBit != -1)
                {
                    GameBit_Set(d->completeBit, 0);
                }
                s->doneCount += 1;
            }
        }
        break;
    case ALPHAANIM_MODE_TIMED:
    {
        int rate = d->rate;
        if (rate < 0)
        {
            rate = -rate;
        }
        absRate = (f32)rate / lbl_803E3F80;
        s->fadeA =
            absRate * timeDelta + s->fadeA;
        if (s->fadeA > s->fadeMax)
        {
            s->fadeA = s->fadeMax;
            GameBit_Set(d->completeBit, 1);
            s->doneCount += 1;
        }
        s->fadeB = s->fadeA - lbl_803E3F84;
        break;
    }
    }
}
