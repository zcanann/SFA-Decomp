/* DLL 0x137 - AlphaAnimator [80192394-801923C4) */
#include "main/dll/mmp_moonrock.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"

extern uint GameBit_Get(int eventId);

extern void* mapGetBlock(int idx);

extern void objRenderFn_8003b8f4(f32);

#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"

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

/* waveanimator_getExtraSize == 0x3c (also the shared wave-grid config fed
 * to fn_801923F8; the grid/color/phase tables live in the lbl_803DDAEC/F0/F4
 * globals). */

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017af0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();

extern void mm_free(void* p);

extern f32 lbl_803E3F78;
extern u8 framesThisStep;
extern f32 timeDelta;
extern void Sfx_PlayFromObject(int* obj, int id);
extern void* mmAlloc(int size, int align, int tag);
extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;

void alphaanimator_free(int* obj)
{
    AlphaAnimatorState* o = (AlphaAnimatorState*)((int**)obj)[0xb8 / 4];
    void* p = o->buf;
    if (p != NULL) mm_free(p);
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
            for (polyIdx = 0; polyIdx < (int)(uint) * (byte*)(block + 0xa2); polyIdx = polyIdx + 1)
            {
                cell = FUN_800600e4(block, polyIdx);
                vtx = cell;
                for (vtxIdx = 0; vtxIdx < (int)(uint) * (byte*)(cell + 0x41); vtxIdx = vtxIdx + 1)
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
                            if ((mapId == 0x49b2f) || (mapId == 0x49b67))
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
                    vtx = vtx + 8;
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

int alphaanimator_getExtraSize(void) { return 0x1c; }
int alphaanimator_getObjectTypeId(void) { return 0x0; }
int groundanimator_getExtraSize(void);

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

void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#pragma scheduling off
void alphaanimator_update(int* obj)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    int* d;
    AlphaAnimatorState* s;
    int mode;
    void* block;
    f32 sp;
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
        s->fadeA = lbl_803E3F7C;
        s->fadeB = lbl_803E3F7C;
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
            s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1C;
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
                s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1C;
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
                s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1C;
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
                if (s->alphaLevel > ((AlphaanimatorPlacement*)d)->unk1C)
                {
                    return;
                }
            }
            else
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel + (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
                if (s->alphaLevel < ((AlphaanimatorPlacement*)d)->unk1D)
                {
                    return;
                }
            }
            s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1C;
            if (((AlphaanimatorPlacement*)d)->unk1A != -1)
            {
                GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 1);
            }
            s->doneCount += 1;
        }
        else
        {
            if (((AlphaanimatorPlacement*)d)->unk1C > ((AlphaanimatorPlacement*)d)->unk1D)
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel + (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
                if (s->alphaLevel < ((AlphaanimatorPlacement*)d)->unk1D)
                {
                    return;
                }
            }
            else
            {
                s->alphaLevel =
                    (s16)(s->alphaLevel - (s8)((AlphaanimatorPlacement*)d)->unk1F * framesThisStep);
                if (s->alphaLevel > ((AlphaanimatorPlacement*)d)->unk1C)
                {
                    return;
                }
            }
            s->alphaLevel = ((AlphaanimatorPlacement*)d)->unk1C;
            if (((AlphaanimatorPlacement*)d)->unk1A != -1)
            {
                GameBit_Set(((AlphaanimatorPlacement*)d)->unk1A, 0);
            }
            s->doneCount += 1;
        }
        break;
    case 3:
        sp = (f32)(s8)((AlphaanimatorPlacement*)d)->unk1F;
        if ((s8)((AlphaanimatorPlacement*)d)->unk1F < 0)
        {
            sp = (f32)(-(s8)((AlphaanimatorPlacement*)d)->unk1F);
        }
        s->fadeA =
            sp / lbl_803E3F80 * timeDelta + s->fadeA;
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
