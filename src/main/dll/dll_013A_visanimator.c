/* DLL 0x013A (visanimator) — Visibility animator object [0x8019423C-0x80194408). */
#pragma scheduling off
#pragma peephole off
#include "main/dll/mmp_moonrock.h"
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"


extern uint GameBit_Get(int eventId);


extern void* mapGetBlock(int idx);


#pragma scheduling reset
#pragma peephole reset

#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/dll/MMP/mmp_barrel.h"
#include "main/game_object.h"
#include "global.h"


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

extern int FUN_80017af0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();


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


void visanimator_free(void)
{
}

void visanimator_render(void)
{
}

void visanimator_hitDetect(void)
{
}

void visanimator_release(void)
{
}

void visanimator_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int waveanimator_getExtraSize(void);
int visanimator_getExtraSize(void) { return 0x5; }
int visanimator_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
u8 groundanimator_modelMtxFn(int* obj);


#pragma peephole off
#pragma scheduling off
void visanimator_init(int* obj, int* desc)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    VisAnimatorState* vstate;
    u32 gate;
    u8 tmp;
    int sv;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    vstate = (VisAnimatorState*)((int**)obj)[0xB8 / 4];
    sv = *(s8*)((char*)desc + 0x1B);
    vstate->visBit = (s8)sv;
    vstate->gateMask = (u8)(1 << *(u8*)&((WaveanimatorObjectDef*)desc)->spanX);
    gate = (u32)GameBit_Get(((WaveanimatorObjectDef*)desc)->originX);
    if ((vstate->gateMask & gate) != 0)
    {
        vstate->visBit = vstate->visBit ^ 1;
    }
    mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                    (double)((GameObject*)obj)->anim.localPosY,
                                    (double)((GameObject*)obj)->anim.localPosZ));
    gate = (u32)GameBit_Get(((WaveanimatorObjectDef*)desc)->originX);
    tmp = (u8)(vstate->gateMask & gate);
    vstate->gateNow = tmp;
    vstate->gatePrev = tmp;
    vstate->flags |= 1;
}

void visanimator_update(int* obj)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    int* state = ((int**)obj)[0x4C / 4];
    VisAnimatorState* vstate = (VisAnimatorState*)((int**)obj)[0xB8 / 4];
    int idx = objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                  (double)((GameObject*)obj)->anim.localPosY,
                                  (double)((GameObject*)obj)->anim.localPosZ);
    if (mapGetBlock(idx) == NULL)
    {
        vstate->flags |= 1;
        return;
    }
    {
        int gate = GameBit_Get(*(s16*)((char*)state + 0x18));
        vstate->gateNow = (u8)(vstate->gateMask & gate);
        if (vstate->gatePrev != vstate->gateNow)
        {
            vstate->visBit = (s8)(vstate->visBit ^ 1);
            vstate->flags |= 1;
        }
        vstate->gatePrev = vstate->gateNow;
        if (vstate->flags & 1)
        {
            vstate->flags &= ~1;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

extern void* lbl_803DDAEC;
#pragma scheduling off
#pragma peephole off

#pragma scheduling off
#pragma peephole off

#pragma scheduling off
#pragma peephole off

#pragma scheduling off
#pragma peephole off

#pragma scheduling off
#pragma peephole off

