/*
 * DLL 0x137 - AlphaAnimator
 *
 * Object that animates the alpha/fade of the map block it sits in. On the
 * first tick where its block is loaded (MapBlockData.unk4 & 8) it latches the
 * placement's params into AlphaAnimatorState, reads the arming game-bit
 * (placement unk18), seeds the fade level, and for mode 3 allocates a
 * per-vertex alpha buffer. Each subsequent tick it ramps alphaLevel toward the
 * target by (unk1F * framesThisStep), gated by the game-bit, in one of four
 * modes (unk20 & 3):
 *   0 - one-shot ramp to target, then sets completion bit (unk1A) and stops
 *   1 - ping-pong between unk1C and unk1D bounds
 *   2 - bidirectional ramp driven by the live gate bit; plays sfxId on a gate
 *       transition (when unk20>>2 set) and sets/clears the completion bit
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

extern void* mapGetBlock(int idx);
extern void objRenderFn_8003b8f4(f32);
extern void mm_free(void* p);
extern void* mmAlloc(int size, int align, int tag);
extern void Sfx_PlayFromObject(int* obj, int id);
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E3F78;
extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;

typedef struct AlphaanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 unk1C;
    u8 unk1D;
    u8 active;
    u8 unk1F;
    u8 unk20;
    u8 pad21[0x22 - 0x21];
    u16 fadeMax;
    u16 sfxId;
    u8 pad26[0x28 - 0x26];
} AlphaanimatorPlacement;

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

void alphaanimator_free(int* obj)
{
    AlphaAnimatorState* o = (AlphaAnimatorState*)((int**)obj)[0xb8 / 4];
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
    s8 v = -1;
    *(s8*)&((AlphaAnimatorState*)((int**)obj)[0xb8 / 4])->prevGate = v;
}

#pragma scheduling on
#pragma peephole off
void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F78);
}

#pragma peephole on
#pragma scheduling off
#pragma peephole off
void alphaanimator_update(int* obj)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    int* d;
    AlphaAnimatorState* s;
    int mode;
    void* block;
    f32 absRate;
    d = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    s = (AlphaAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    mode = ((AlphaanimatorPlacement*)d)->unk20 & 3;
    block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                            (double)((GameObject*)obj)->anim.localPosY,
                                            (double)((GameObject*)obj)->anim.localPosZ));
    if (block == NULL)
    {
        s->doneCount = 0;
        return;
    }
    if ((((MapBlockData*)block)->unk4 & 8) == 0)
    {
        return;
    }
    if (s->vertCount == 0)
    {
        s->active = ((AlphaanimatorPlacement*)d)->active;
        if (s->vertCount == 0)
        {
            s->active = 0;
        }
        if ((s8)s->active == 0)
        {
            return;
        }
        s->fadeA = s->fadeB = lbl_803E3F7C;
        s->fadeMax = (f32)(u32)((AlphaanimatorPlacement*)d)->fadeMax;
        if (((AlphaanimatorPlacement*)d)->unk18 == -1)
        {
            s->gateVal = 1;
        }
        else
        {
            s->gateVal = (s8)GameBit_Get(((AlphaanimatorPlacement*)d)->unk18);
        }
        s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1C;
        if (((AlphaanimatorPlacement*)d)->unk1A != -1 && GameBit_Get(((AlphaanimatorPlacement*)d)->unk1A) != 0)
        {
            s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1D;
            s->fadeA = lbl_803E3F78 + s->fadeMax;
            s->gateVal = 1;
        }
        if (mode == 3)
        {
            *(int*)&s->buf = (int)mmAlloc(s->vertCount << 2, 5, 0);
        }
        ((MapBlockData*)block)->unk4 = ((MapBlockData*)block)->unk4 ^ 1;
        ((MapBlockData*)block)->unk4 = ((MapBlockData*)block)->unk4 ^ 1;
    }
    if ((s8)s->active == 0)
    {
        return;
    }
    if (mode == 2)
    {
        s->gateVal = (s8)GameBit_Get(((AlphaanimatorPlacement*)d)->unk18);
        if ((s8)s->doneCount > 2 &&
            (s8)s->gateVal != (s8)s->prevGate)
        {
            if ((((AlphaanimatorPlacement*)d)->unk20 >> 2) != 0)
            {
                Sfx_PlayFromObject(obj, ((AlphaanimatorPlacement*)d)->sfxId);
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
            s->gateVal = (s8)GameBit_Get(((AlphaanimatorPlacement*)d)->unk18);
            if ((s8)s->gateVal == 0)
            {
                return;
            }
            if ((((AlphaanimatorPlacement*)d)->unk20 >> 2) != 0)
            {
                Sfx_PlayFromObject(obj, ((AlphaanimatorPlacement*)d)->sfxId);
            }
        }
    }
    switch (mode)
    {
    case 0:
        if (((AlphaanimatorPlacement*)d)->unk1C > ((AlphaanimatorPlacement*)d)->unk1D)
        {
            s->alphaLevel =
                (s16)(s->alphaLevel - (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
            if (s->alphaLevel <= ((AlphaanimatorPlacement*)d)->unk1D)
            {
                s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1D;
                if (((AlphaanimatorPlacement*)d)->unk1A != -1)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 1);
                }
                s->doneCount += 1;
            }
        }
        else
        {
            s->alphaLevel =
                (s16)(s->alphaLevel + (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
            if (s->alphaLevel >= ((AlphaanimatorPlacement*)d)->unk1D)
            {
                s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1D;
                if (((AlphaanimatorPlacement*)d)->unk1A != -1)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 1);
                }
                s->doneCount += 1;
            }
        }
        break;
    case 1:
        if (((AlphaanimatorPlacement*)d)->unk1C > ((AlphaanimatorPlacement*)d)->unk1D)
        {
            s->alphaLevel =
                (s16)(s->alphaLevel - (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
            if (s->alphaLevel < ((AlphaanimatorPlacement*)d)->unk1D)
            {
                s->alphaLevel =
                    (s16)(((AlphaanimatorPlacement*)d)->unk1C -
                        (((AlphaanimatorPlacement*)d)->unk1D - s->alphaLevel));
            }
        }
        else
        {
            s->alphaLevel =
                (s16)(s->alphaLevel + (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
            if (s->alphaLevel > ((AlphaanimatorPlacement*)d)->unk1C)
            {
                s->alphaLevel =
                    (s16)(((AlphaanimatorPlacement*)d)->unk1D +
                        (s->alphaLevel - ((AlphaanimatorPlacement*)d)->unk1D));
            }
        }
        break;
    case 2:
        if ((s8)s->gateVal != 0)
        {
            if (((AlphaanimatorPlacement*)d)->unk1C > ((AlphaanimatorPlacement*)d)->unk1D)
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel - (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
                if (s->alphaLevel > ((AlphaanimatorPlacement*)d)->unk1D)
                {
                    return;
                }
                s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1D;
                if (((AlphaanimatorPlacement*)d)->unk1A != -1)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 1);
                }
                s->doneCount += 1;
            }
            else
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel + (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
                if (s->alphaLevel < ((AlphaanimatorPlacement*)d)->unk1D)
                {
                    return;
                }
                s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1D;
                if (((AlphaanimatorPlacement*)d)->unk1A != -1)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 1);
                }
                s->doneCount += 1;
            }
        }
        else
        {
            if (((AlphaanimatorPlacement*)d)->unk1C > ((AlphaanimatorPlacement*)d)->unk1D)
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel + (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
                if (s->alphaLevel < ((AlphaanimatorPlacement*)d)->unk1C)
                {
                    return;
                }
                s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1C;
                if (((AlphaanimatorPlacement*)d)->unk1A != -1)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 0);
                }
                s->doneCount += 1;
            }
            else
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel - (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
                if (s->alphaLevel > ((AlphaanimatorPlacement*)d)->unk1C)
                {
                    return;
                }
                s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1C;
                if (((AlphaanimatorPlacement*)d)->unk1A != -1)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 0);
                }
                s->doneCount += 1;
            }
        }
        break;
    case 3:
        absRate = (f32)(s8)((AlphaanimatorPlacement*)d)->unk1F;
        if ((s8)((AlphaanimatorPlacement*)d)->unk1F < 0)
        {
            absRate = (f32)(-(s8)((AlphaanimatorPlacement*)d)->unk1F);
        }
        s->fadeA =
            absRate / lbl_803E3F80 * timeDelta + s->fadeA;
        if (s->fadeA > s->fadeMax)
        {
            s->fadeA = s->fadeMax;
            GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 1);
            s->doneCount += 1;
        }
        s->fadeB = s->fadeA - lbl_803E3F84;
        break;
    }
}
