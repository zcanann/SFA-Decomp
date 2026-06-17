/*
 * AlphaAnimator (DLL 0x137) - one of the map-mesh animator classes
 * compiled into this object (wave / alpha / ground / vis animators).
 *
 * An alpha-animator placement drives the per-vertex alpha of the map
 * block it sits in. Its per-instance state (AlphaAnimatorState) tracks
 * the current alpha level and the fade endpoints; the placement record
 * (AlphaanimatorPlacement) supplies the from/to alpha, fade step and the
 * game bit that gates and reports the fade.
 *
 * placement.modeFlags & 3 selects the fade mode (ALPHAANIM_MODE_*):
 *   0 ONESHOT   - step toward the target, set the game bit, count done
 *   1 PINGPONG  - bounce between the two alpha levels
 *   2 GATED     - fade in/out following the game bit, set/clear it at the end
 *   3 TIMED     - time-based fade into a malloc'd per-vertex buffer
 * placement.modeFlags bit 2 enables the placement sfx on a gate transition.
 */
#include "main/dll/mmp_moonrock.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"

extern uint GameBit_Get(int eventId);

extern void* mapGetBlock(int idx);

extern void objRenderFn_8003b8f4(f32);

extern int objPosToMapBlockIdx(double x, double y, double z);

typedef struct AlphaanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gateGameBit;  /* 0x18: gate bit (-1 = none) */
    s16 doneGameBit;  /* 0x1A: set/cleared when the fade completes (-1 = none) */
    u8 alphaFrom;     /* 0x1C: start alpha level */
    u8 alphaTo;       /* 0x1D: target alpha level */
    u8 active;        /* 0x1E */
    u8 fadeStep;      /* 0x1F: per-step alpha delta (signed) */
    u8 modeFlags;     /* 0x20: bits 0-1 mode, bit 2 sfx-on-transition */
    u8 pad21[0x22 - 0x21];
    u16 fadeMax;      /* 0x22: TIMED-mode fade ceiling */
    u16 sfxId;        /* 0x24 */
    u8 pad26[0x28 - 0x26];
} AlphaanimatorPlacement;

STATIC_ASSERT(offsetof(AlphaanimatorPlacement, gateGameBit) == 0x18);
STATIC_ASSERT(offsetof(AlphaanimatorPlacement, doneGameBit) == 0x1A);
STATIC_ASSERT(offsetof(AlphaanimatorPlacement, alphaFrom) == 0x1C);
STATIC_ASSERT(offsetof(AlphaanimatorPlacement, modeFlags) == 0x20);
STATIC_ASSERT(offsetof(AlphaanimatorPlacement, fadeMax) == 0x22);
STATIC_ASSERT(offsetof(AlphaanimatorPlacement, sfxId) == 0x24);
STATIC_ASSERT(sizeof(AlphaanimatorPlacement) == 0x28);

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);
STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);
STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern void GameBit_Set(int eventId, int value);
extern int FUN_80017af0();
extern int FUN_8005337c();
extern int FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern undefined8 FUN_8028682c();
extern int FUN_80286878();

extern void mm_free(void* p);

extern f32 lbl_803E3F78;
extern u8 framesThisStep;
extern f32 timeDelta;
extern void Sfx_PlayFromObject(int* obj, int id);
extern void* mmAlloc(int size, int align, int tag);
extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;

#define ALPHAANIM_MODE_ONESHOT 0  /* step to target, set game bit, count done */
#define ALPHAANIM_MODE_PINGPONG 1 /* bounce between the two alpha levels */
#define ALPHAANIM_MODE_GATED 2    /* fade tracking the game bit, set/clear at end */
#define ALPHAANIM_MODE_TIMED 3    /* time-based fade into the per-vertex buffer */
#define ALPHAANIM_NO_GAMEBIT -1   /* placement.gateGameBit/doneGameBit: no game bit */

void alphaanimator_free(int* obj)
{
    AlphaAnimatorState* state = (AlphaAnimatorState*)((GameObject*)obj)->extra;
    void* buf = state->buf;
    if (buf != NULL) mm_free(buf);
}

void FUN_80192488(void)
{
    int texV;
    int ctxHi;
    int block;
    int polyIdx;
    int cell;
    uint gameBit;
    int texU;
    int ctxLo;
    int mapId;
    int placement;
    int vtxIdx;
    int vtx;
    undefined8 pair;

    pair = FUN_8028682c();
    ctxHi = (int)((ulonglong)pair >> 0x20);
    ctxLo = (int)pair;
    placement = *(int*)(ctxHi + 0x4c);
    block = FUN_8005b398((double)*(float*)(ctxHi + 0xc), (double)*(float*)(ctxHi + 0x10));
    block = FUN_8005af70(block);
    if (block == 0)
    {
        *(undefined*)(ctxLo + 0x10) = 1;
    }
    else
    {
        polyIdx = FUN_80017af0(0xe);
        if ((polyIdx != 0) &&
            (placement = FUN_8005337c(-*(int*)(polyIdx + *(short*)(placement + 0x18) * 4)), placement != 0))
        {
            for (polyIdx = 0; polyIdx < (int)(uint) * (byte*)(block + 0xa2); polyIdx++)
            {
                cell = FUN_800600e4(block, polyIdx);
                vtx = cell;
                for (vtxIdx = 0; vtxIdx < (int)(uint) * (byte*)(cell + 0x41); vtxIdx++)
                {
                    if (*(int*)(vtx + 0x24) == placement)
                    {
                        texU = (uint) * (ushort*)(placement + 10) << 6;
                        texV = (uint) * (ushort*)(placement + 0xc) << 6;
                        if (*(byte*)(vtx + 0x2a) == 0xff)
                        {
                            texU = FUN_80056448((int)*(char*)(ctxLo + 0x11), (int)*(char*)(ctxLo + 0x12), texU,
                                                 texV);
                            *(char*)(vtx + 0x2a) = (char)texU;
                        }
                        else
                        {
                            mapId = *(int*)(*(int*)(ctxHi + 0x4c) + 0x14);
                            if ((mapId == TEXSCROLL_GAMEBIT_GATED_MAP_A) || (mapId == TEXSCROLL_GAMEBIT_GATED_MAP_B))
                            {
                                gameBit = GameBit_Get(*(uint*)(ctxLo + 8));
                                if (gameBit != 0)
                                {
                                    FUN_80056418((uint) * (byte*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                                 (int)*(char*)(ctxLo + 0x12), texU, texV);
                                }
                            }
                            else
                            {
                                FUN_80056418((uint) * (byte*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                             (int)*(char*)(ctxLo + 0x12), texU, texV);
                            }
                        }
                    }
                    vtx += 8;
                }
            }
        }
    }
    FUN_80286878();
    return;
}

void waveanimator_update(void);

void alphaanimator_hitDetect(void)
{
}

void alphaanimator_release(void)
{
}

void alphaanimator_initialise(void)
{
}

void visanimator_free(void);

int alphaanimator_getExtraSize(void) { return sizeof(AlphaAnimatorState); }
int alphaanimator_getObjectTypeId(void) { return 0x0; }
int groundanimator_getExtraSize(void);

#pragma scheduling off
void alphaanimator_init(int* obj)
{
    *(s8*)&((AlphaAnimatorState*)((GameObject*)obj)->extra)->prevGate = -1;
}

#pragma scheduling on
#pragma peephole off
void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 vis = visible;
    if (vis != 0) objRenderFn_8003b8f4(lbl_803E3F78);
}

void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#pragma scheduling off
void alphaanimator_update(int* obj)
{
    int* placement;
    AlphaAnimatorState* state;
    int mode;
    void* block;
    f32 fadeRate;
    placement = (int*)((GameObject*)obj)->anim.placementData;
    state = (AlphaAnimatorState*)((GameObject*)obj)->extra;
    mode = ((AlphaanimatorPlacement*)placement)->modeFlags & 3;
    block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                            (double)((GameObject*)obj)->anim.localPosY,
                                            (double)((GameObject*)obj)->anim.localPosZ));
    if (block == NULL)
    {
        state->doneCount = 0;
        return;
    }
    if ((((MapBlockData*)block)->unk4 & 8) == 0)
    {
        return;
    }
    if (state->vertCount == 0)
    {
        state->active = ((AlphaanimatorPlacement*)placement)->active;
        if (state->vertCount == 0)
        {
            state->active = 0;
        }
        if ((s8)state->active == 0)
        {
            return;
        }
        state->fadeB = state->fadeA = lbl_803E3F7C;
        state->fadeMax = (f32)(u32)((AlphaanimatorPlacement*)placement)->fadeMax;
        if (((AlphaanimatorPlacement*)placement)->gateGameBit == ALPHAANIM_NO_GAMEBIT)
        {
            state->gateVal = 1;
        }
        else
        {
            *(s8*)&state->gateVal = (s8)GameBit_Get(((AlphaanimatorPlacement*)placement)->gateGameBit);
        }
        state->alphaLevel = ((AlphaanimatorPlacement*)placement)->alphaFrom;
        if (((AlphaanimatorPlacement*)placement)->doneGameBit != ALPHAANIM_NO_GAMEBIT && GameBit_Get(((AlphaanimatorPlacement*)placement)->doneGameBit) != 0)
        {
            state->alphaLevel = ((AlphaanimatorPlacement*)placement)->alphaTo;
            state->fadeA = lbl_803E3F78 + state->fadeMax;
            state->gateVal = 1;
        }
        if (mode == ALPHAANIM_MODE_TIMED)
        {
            state->buf = mmAlloc(state->vertCount << 2, 5, 0);
        }
        ((MapBlockData*)block)->unk4 = ((MapBlockData*)block)->unk4 ^ 1;
        ((MapBlockData*)block)->unk4 = ((MapBlockData*)block)->unk4 ^ 1;
    }
    if ((s8)state->active == 0)
    {
        return;
    }
    if (mode == ALPHAANIM_MODE_GATED)
    {
        *(s8*)&state->gateVal = (s8)GameBit_Get(((AlphaanimatorPlacement*)placement)->gateGameBit);
        if ((s8)state->doneCount > 2 &&
            (s8)state->gateVal != (s8)state->prevGate)
        {
            if ((((AlphaanimatorPlacement*)placement)->modeFlags >> 2) != 0)
            {
                Sfx_PlayFromObject(obj, ((AlphaanimatorPlacement*)placement)->sfxId);
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
            *(s8*)&state->gateVal = (s8)GameBit_Get(((AlphaanimatorPlacement*)placement)->gateGameBit);
            if ((s8)state->gateVal == 0)
            {
                return;
            }
            if ((((AlphaanimatorPlacement*)placement)->modeFlags >> 2) != 0)
            {
                Sfx_PlayFromObject(obj, ((AlphaanimatorPlacement*)placement)->sfxId);
            }
        }
    }
    switch (mode)
    {
    case ALPHAANIM_MODE_ONESHOT:
        if (((AlphaanimatorPlacement*)placement)->alphaFrom > ((AlphaanimatorPlacement*)placement)->alphaTo)
        {
            state->alphaLevel =
                (s16)(state->alphaLevel - (s8)((AlphaanimatorPlacement*)placement)->fadeStep * framesThisStep);
            if (state->alphaLevel <= ((AlphaanimatorPlacement*)placement)->alphaTo)
            {
                state->alphaLevel = ((AlphaanimatorPlacement*)placement)->alphaFrom;
                if (((AlphaanimatorPlacement*)placement)->doneGameBit != ALPHAANIM_NO_GAMEBIT)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)placement)->doneGameBit, 1);
                }
                state->doneCount += 1;
            }
        }
        else
        {
            state->alphaLevel =
                (s16)(state->alphaLevel + (s8)((AlphaanimatorPlacement*)placement)->fadeStep * framesThisStep);
            if (state->alphaLevel >= ((AlphaanimatorPlacement*)placement)->alphaTo)
            {
                state->alphaLevel = ((AlphaanimatorPlacement*)placement)->alphaFrom;
                if (((AlphaanimatorPlacement*)placement)->doneGameBit != ALPHAANIM_NO_GAMEBIT)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)placement)->doneGameBit, 1);
                }
                state->doneCount += 1;
            }
        }
        break;
    case ALPHAANIM_MODE_PINGPONG:
        if (((AlphaanimatorPlacement*)placement)->alphaFrom > ((AlphaanimatorPlacement*)placement)->alphaTo)
        {
            state->alphaLevel =
                (s16)(state->alphaLevel - (s8)((AlphaanimatorPlacement*)placement)->fadeStep * framesThisStep);
            if (state->alphaLevel < ((AlphaanimatorPlacement*)placement)->alphaTo)
            {
                state->alphaLevel =
                    (s16)(((AlphaanimatorPlacement*)placement)->alphaFrom -
                        (((AlphaanimatorPlacement*)placement)->alphaTo - state->alphaLevel));
            }
        }
        else
        {
            state->alphaLevel =
                (s16)(state->alphaLevel + (s8)((AlphaanimatorPlacement*)placement)->fadeStep * framesThisStep);
            if (state->alphaLevel > ((AlphaanimatorPlacement*)placement)->alphaFrom)
            {
                state->alphaLevel =
                    (s16)(((AlphaanimatorPlacement*)placement)->alphaTo +
                        (state->alphaLevel - ((AlphaanimatorPlacement*)placement)->alphaTo));
            }
        }
        break;
    case ALPHAANIM_MODE_GATED:
        if ((s8)state->gateVal != 0)
        {
            if (((AlphaanimatorPlacement*)placement)->alphaFrom > ((AlphaanimatorPlacement*)placement)->alphaTo)
            {
                state->alphaLevel =
                    (s16)(state->alphaLevel - (s8)((AlphaanimatorPlacement*)placement)->fadeStep * framesThisStep);
                if (state->alphaLevel > ((AlphaanimatorPlacement*)placement)->alphaTo)
                {
                    return;
                }
                state->alphaLevel = ((AlphaanimatorPlacement*)placement)->alphaTo;
                if (((AlphaanimatorPlacement*)placement)->doneGameBit != ALPHAANIM_NO_GAMEBIT)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)placement)->doneGameBit, 1);
                }
                state->doneCount += 1;
            }
            else
            {
                state->alphaLevel =
                    (s16)(state->alphaLevel + (s8)((AlphaanimatorPlacement*)placement)->fadeStep * framesThisStep);
                if (state->alphaLevel < ((AlphaanimatorPlacement*)placement)->alphaTo)
                {
                    return;
                }
                state->alphaLevel = ((AlphaanimatorPlacement*)placement)->alphaTo;
                if (((AlphaanimatorPlacement*)placement)->doneGameBit != ALPHAANIM_NO_GAMEBIT)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)placement)->doneGameBit, 1);
                }
                state->doneCount += 1;
            }
        }
        else
        {
            if (((AlphaanimatorPlacement*)placement)->alphaFrom > ((AlphaanimatorPlacement*)placement)->alphaTo)
            {
                state->alphaLevel =
                    (s16)(state->alphaLevel + (s8)((AlphaanimatorPlacement*)placement)->fadeStep * framesThisStep);
                if (state->alphaLevel < ((AlphaanimatorPlacement*)placement)->alphaFrom)
                {
                    return;
                }
                state->alphaLevel = ((AlphaanimatorPlacement*)placement)->alphaFrom;
                if (((AlphaanimatorPlacement*)placement)->doneGameBit != ALPHAANIM_NO_GAMEBIT)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)placement)->doneGameBit, 0);
                }
                state->doneCount += 1;
            }
            else
            {
                state->alphaLevel =
                    (s16)(state->alphaLevel - (s8)((AlphaanimatorPlacement*)placement)->fadeStep * framesThisStep);
                if (state->alphaLevel > ((AlphaanimatorPlacement*)placement)->alphaFrom)
                {
                    return;
                }
                state->alphaLevel = ((AlphaanimatorPlacement*)placement)->alphaFrom;
                if (((AlphaanimatorPlacement*)placement)->doneGameBit != ALPHAANIM_NO_GAMEBIT)
                {
                    GameBit_Set(((AlphaanimatorPlacement*)placement)->doneGameBit, 0);
                }
                state->doneCount += 1;
            }
        }
        break;
    case ALPHAANIM_MODE_TIMED:
        {
            s32 step = (s8)((AlphaanimatorPlacement*)placement)->fadeStep;
            if (step < 0)
            {
                step = -step;
            }
            fadeRate = (f32)step;
        }
        fadeRate = fadeRate / lbl_803E3F80;
        state->fadeA =
            fadeRate * timeDelta + state->fadeA;
        if (state->fadeA > state->fadeMax)
        {
            state->fadeA = state->fadeMax;
            GameBit_Set(((AlphaanimatorPlacement*)placement)->doneGameBit, 1);
            state->doneCount += 1;
        }
        state->fadeB = state->fadeA - lbl_803E3F84;
        break;
    }
}
