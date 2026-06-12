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
#include "main/dll/MMP/mmp_barrel.h"
#include "main/game_object.h"
#include "global.h"


typedef struct AlphaanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s8 unk1C;
    s8 unk1D;
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

/* alphaanimator_getExtraSize == 0x1c. */


STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

/* groundanimator_getExtraSize == 0x30. */
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

/* visanimator_getExtraSize == 0x5. */


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

void alphaanimator_free(int* obj)
{
    AlphaAnimatorState* o = (AlphaAnimatorState*)((int**)obj)[0xb8 / 4];
    void* p = o->buf;
    if (p != NULL) mm_free(p);
}

/*
 * --INFO--
 *
 * Function: FUN_80192488
 * EN v1.0 Address: 0x80192488
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x801924D0
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80192488(void)
{
    int iVar1;
    int iVar2;
    int iVar3;
    int iVar4;
    int iVar5;
    uint uVar6;
    int iVar7;
    int iVar8;
    int iVar9;
    int iVar10;
    int iVar11;
    int iVar12;
    undefined8 uVar13;

    uVar13 = FUN_8028682c();
    iVar2 = (int)((ulonglong)uVar13 >> 0x20);
    iVar8 = (int)uVar13;
    iVar10 = *(int*)(iVar2 + 0x4c);
    iVar3 = FUN_8005b398((double)*(float*)(iVar2 + 0xc), (double)*(float*)(iVar2 + 0x10));
    iVar3 = FUN_8005af70(iVar3);
    if (iVar3 == 0)
    {
        *(undefined*)(iVar8 + 0x10) = 1;
    }
    else
    {
        iVar4 = FUN_80017af0(0xe);
        if ((iVar4 != 0) &&
            (iVar10 = FUN_8005337c(-*(int*)(iVar4 + *(short*)(iVar10 + 0x18) * 4)), iVar10 != 0))
        {
            for (iVar4 = 0; iVar4 < (int)(uint) * (byte*)(iVar3 + 0xa2); iVar4 = iVar4 + 1)
            {
                iVar5 = FUN_800600e4(iVar3, iVar4);
                iVar12 = iVar5;
                for (iVar11 = 0; iVar11 < (int)(uint) * (byte*)(iVar5 + 0x41); iVar11 = iVar11 + 1)
                {
                    if (*(int*)(iVar12 + 0x24) == iVar10)
                    {
                        iVar7 = (uint) * (ushort*)(iVar10 + 10) << 6;
                        iVar1 = (uint) * (ushort*)(iVar10 + 0xc) << 6;
                        if (*(byte*)(iVar12 + 0x2a) == 0xff)
                        {
                            iVar7 = FUN_80056448((int)*(char*)(iVar8 + 0x11), (int)*(char*)(iVar8 + 0x12), iVar7,
                                                 iVar1);
                            *(char*)(iVar12 + 0x2a) = (char)iVar7;
                        }
                        else
                        {
                            iVar9 = *(int*)(*(int*)(iVar2 + 0x4c) + 0x14);
                            if ((iVar9 == 0x49b2f) || (iVar9 == 0x49b67))
                            {
                                uVar6 = GameBit_Get(*(uint*)(iVar8 + 8));
                                if (uVar6 != 0)
                                {
                                    FUN_80056418((uint) * (byte*)(iVar12 + 0x2a), (int)*(char*)(iVar8 + 0x11),
                                                 (int)*(char*)(iVar8 + 0x12), iVar7, iVar1);
                                }
                            }
                            else
                            {
                                FUN_80056418((uint) * (byte*)(iVar12 + 0x2a), (int)*(char*)(iVar8 + 0x11),
                                             (int)*(char*)(iVar8 + 0x12), iVar7, iVar1);
                            }
                        }
                    }
                    iVar12 = iVar12 + 8;
                }
            }
        }
    }
    FUN_80286878();
    return;
}


/* Trivial 4b 0-arg blr leaves. */
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


/* 8b "li r3, N; blr" returners. */
int alphaanimator_getExtraSize(void) { return 0x1c; }
int alphaanimator_getObjectTypeId(void) { return 0x0; }
int groundanimator_getExtraSize(void);

/* Pattern wrappers. */

/* 16b chained patterns. */
#pragma scheduling off
void alphaanimator_init(int* obj)
{
    s8 v = -1;
    *(s8*)&((AlphaAnimatorState*)((int**)obj)[0xb8 / 4])->prevGate = v;
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3F70;
extern f32 lbl_803E3F78;

#pragma scheduling on
#pragma peephole off
void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F78);
}

void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


extern u8 framesThisStep;


extern f32 timeDelta;


extern void Sfx_PlayFromObject(int* obj, int id);
extern void* mmAlloc(int size, int align, int tag);

extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;

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
    if (mode == 0)
    {
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
    }
    else if (mode == 1)
    {
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
    }
    else if (mode == 2)
    {
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
    }
    else
    {
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
    }
}

extern f32 lbl_803E3F40;

