#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/dll/MMP/mmp_barrel.h"
#include "main/game_object.h"
#include "global.h"

typedef struct WaveanimatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 originX;
    s16 originY;
    s8 spanX;
    s8 spanY;
    s16 modelVariant;
    s8 unk20;
    s8 period;
    s8 gridN;
    u8 pad23[0x25 - 0x23];
    u8 unk25;
    u8 radius;
    u8 yOffset;
} WaveanimatorObjectDef;


typedef struct GroundanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 pad23[0x25 - 0x23];
    u8 unk25;
    u8 pad26[0x28 - 0x26];
} GroundanimatorPlacement;


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
typedef struct WaveAnimatorState
{
    int originX; /* 0x00 */
    int originY; /* 0x04 */
    int spanX; /* 0x08 */
    int spanY; /* 0x0c */
    f32 ampX; /* 0x10 */
    f32 ampY; /* 0x14 */
    int unk18; /* 0x18 */
    int period; /* 0x1c */
    int gridN; /* 0x20 */
    f32 minHeight; /* 0x24 */
    f32 maxHeight; /* 0x28 */
    f32 scaleA; /* 0x2c */
    f32 scaleB; /* 0x30 */
    u8 flags; /* 0x34: 1 = scale pending, 2 = func0B latch */
    u8 pad35[7];
} WaveAnimatorState;

STATIC_ASSERT (
sizeof
(WaveAnimatorState)
==
0x3C
);

/* alphaanimator_getExtraSize == 0x1c. */
typedef struct AlphaAnimatorState
{
    int vertCount; /* 0x00 */
    f32 fadeA; /* 0x04 */
    f32 fadeB; /* 0x08 */
    f32 fadeMax; /* 0x0c */
    void* buf; /* 0x10: mode-3 per-vertex alpha buffer */
    s16 alphaLevel; /* 0x14 */
    u8 active; /* 0x16 */
    u8 gateVal; /* 0x17 */
    u8 doneCount; /* 0x18 */
    u8 prevGate; /* 0x19 */
    u8 pad1A[2];
} AlphaAnimatorState;

STATIC_ASSERT (
sizeof
(AlphaAnimatorState)
==
0x1C
);

/* groundanimator_getExtraSize == 0x30. */
STATIC_ASSERT (
sizeof
(GroundAnimatorState)
==
0x30
);

/* visanimator_getExtraSize == 0x5. */
typedef struct VisAnimatorState
{
    u8 flags; /* 0x00: 1 = refresh pending */
    s8 visBit; /* 0x01 */
    u8 gateNow; /* 0x02 */
    u8 gatePrev; /* 0x03 */
    u8 gateMask; /* 0x04 */
} VisAnimatorState;

STATIC_ASSERT (
sizeof
(VisAnimatorState)
==
0x5
);

extern undefined4 FUN_80006824();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern int FUN_80017a90();
extern undefined4 FUN_80017a98();
extern int FUN_80017af0();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern int FUN_800480a0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern undefined4 FUN_8005ff38();
extern undefined4 FUN_8005ff90();
extern uint FUN_80060058();
extern int FUN_80060064();
extern undefined4 FUN_800600b4();
extern int FUN_800600c4();
extern int FUN_800600e4();
extern undefined4 FUN_800631d4();
extern int FUN_80063298();
extern undefined4 FUN_801a8ae8();
extern undefined4 FUN_801a8b20();
extern undefined4 FUN_80242178();
extern uint FUN_80286810();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286820();
extern undefined8 FUN_8028682c();
extern uint FUN_80286840();
extern undefined4 TRKNubMainLoop();
extern undefined4 FUN_80286868();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c4();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de768;
extern undefined4 DAT_803de76c;
extern undefined4 DAT_803de770;
extern undefined4 DAT_803de774;
extern f64 DOUBLE_803e4c00;
extern f64 DOUBLE_803e4c20;
extern f64 DOUBLE_803e4c28;
extern f64 DOUBLE_803e4c38;
extern f64 DOUBLE_803e4c60;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E4BDC;
extern f32 lbl_803E4BE8;
extern f32 lbl_803E4BEC;
extern f32 lbl_803E4BF0;
extern f32 lbl_803E4BF4;
extern f32 lbl_803E4BF8;
extern f32 lbl_803E4BFC;
extern f32 lbl_803E4C08;
extern f32 lbl_803E4C10;
extern f32 lbl_803E4C14;
extern f32 lbl_803E4C18;
extern f32 lbl_803E4C1C;
extern f32 lbl_803E4C30;
extern f32 lbl_803E4C40;
extern f32 lbl_803E4C44;
extern f32 lbl_803E4C48;
extern f32 lbl_803E4C4C;
extern f32 lbl_803E4C50;
extern f32 lbl_803E4C54;
extern f32 lbl_803E4C58;
extern f32 lbl_803E4C5C;

/*
 * --INFO--
 *
 * Function: waveanimator_func0B
 * EN v1.0 Address: 0x801923C4
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801923CC
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void waveanimator_func0B(int* obj)
{
    WaveAnimatorState* p = (WaveAnimatorState*)((int**)obj)[0xb8 / 4];
    p->flags |= 2;
}

u8 wallanimator_func0B(int* obj)
{
    int* p = ((int**)obj)[0xb8 / 4];
    return *p >= WALLANIMATOR_DONE_TIMER;
}
#pragma scheduling reset
#pragma peephole reset

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
void waveanimator_update(void)
{
}

void waveanimator_release(void)
{
}

void waveanimator_initialise(void)
{
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
int waveanimator_getExtraSize(void) { return 0x3c; }
int waveanimator_getObjectTypeId(void) { return 0x0; }
int alphaanimator_getExtraSize(void) { return 0x1c; }
int alphaanimator_getObjectTypeId(void) { return 0x0; }
int groundanimator_getExtraSize(void) { return 0x30; }
int hitanimator_getExtraSize(void) { return 0x4; }
int visanimator_getExtraSize(void) { return 0x5; }
int visanimator_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
u8 groundanimator_modelMtxFn(int* obj) { return *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x2b); }

/* 16b chained patterns. */
#pragma scheduling off
void alphaanimator_init(int* obj)
{
    s8 v = -1;
    *(s8*)&((AlphaAnimatorState*)((int**)obj)[0xb8 / 4])->prevGate = v;
}
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3F70;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F78;
extern f32 lbl_803E3FC4;
#pragma peephole off
void waveanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F70);
}

void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3F78);
}

void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3FC4);
}
#pragma peephole reset

/* wall variant: hashes lha to byte */
#pragma peephole off
u8 wallanimator_modelMtxFn(int* obj) { return (u8) * (s16*)((char*)((int**)obj)[0x4c / 4] + 0x1c); }

void waveanimator_setScale(int* obj, f32 fval)
{
    WaveAnimatorState* p = (WaveAnimatorState*)((int**)obj)[0xb8 / 4];
    p->flags |= 1;
    p->scaleB = fval;
}
#pragma peephole reset

extern f32 lbl_803E3F98;
#pragma scheduling off
u8 groundanimator_func0B(int* obj)
{
    GroundAnimatorState * p1 = (GroundAnimatorState*)((int**)obj)[0xB8 / 4];
    f32 v = p1->sinkDepth;
    int* p2 = ((int**)obj)[0x4C / 4];
    u8 byte = *(u8*)((char*)p2 + 0x20);
    return v > lbl_803E3F98 * (f32)byte;
}
#pragma scheduling reset

extern int objPosToMapBlockIdx(double x, double y, double z);
extern void* mapGetBlock(int idx);
extern void fn_801923F8(int* cfg);
extern void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate,
                                   HitAnimatorPlacement* desc);
extern int fn_80065640(void);
extern void fn_80065574(int a, int b, int c);
extern u8 lbl_803DDAE8;
#pragma peephole off
#pragma scheduling off
void waveanimator_init(int* obj, int* desc)
{
    WaveAnimatorState* vstate = (WaveAnimatorState*)((int**)obj)[0xB8 / 4];
    f32 fz;
    vstate->unk18 = ((WaveanimatorObjectDef*)desc)->unk20;
    vstate->originX = ((WaveanimatorObjectDef*)desc)->originX;
    vstate->originY = ((WaveanimatorObjectDef*)desc)->originY;
    vstate->spanX = ((WaveanimatorObjectDef*)desc)->spanX;
    vstate->spanY = ((WaveanimatorObjectDef*)desc)->spanY;
    vstate->ampX = (f32) * (s8*)((char*)desc + 0x1E);
    vstate->ampY = (f32) * (s8*)((char*)desc + 0x1F);
    vstate->period = ((WaveanimatorObjectDef*)desc)->period;
    vstate->gridN = ((WaveanimatorObjectDef*)desc)->gridN;
    fz = lbl_803E3F70;
    vstate->scaleA = fz;
    vstate->scaleB = fz;
    if (lbl_803DDAE8 == 0)
    {
        fn_801923F8((int*)vstate);
    }
    ObjGroup_AddObject(obj, 27);
    lbl_803DDAE8++;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void hitanimator_update(HitAnimatorObject* obj)
{
    HitAnimatorPlacement* setup = (HitAnimatorPlacement*)obj->objAnim.placementData;
    HitAnimatorState* state = obj->state;
    void* block;
    block = mapGetBlock(objPosToMapBlockIdx(
        (double)obj->objAnim.localPosX,
        (double)obj->objAnim.localPosY,
        (double)obj->objAnim.localPosZ));
    if (block == NULL)
    {
        state->flags &= ~HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
        return;
    }
    state->gameBitValue = (u8)GameBit_Get(setup->gameBit);
    if (state->previousGameBitValue != state->gameBitValue)
    {
        state->activeBit = state->activeBit ^ 1;
        if (setup->toggleMode == 1)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        }
        if ((setup->flags & HITANIMATOR_SETUP_FLAG_SOUND) != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
        }
        if ((setup->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
        }
    }
    state->previousGameBitValue = state->gameBitValue;
    if ((setup->flags & HITANIMATOR_SETUP_FLAG_SOUND) != 0)
    {
        if (fn_80065640() != 0)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
        }
        if ((state->flags & HITANIMATOR_STATE_FLAG_SOUND_PENDING) != 0)
        {
            if (fn_80065640() == 0)
            {
                fn_80065574(setup->soundId, (int)obj->objAnim.parent, state->activeBit);
                state->flags &= ~HITANIMATOR_STATE_FLAG_SOUND_PENDING;
            }
        }
    }
    if ((setup->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0)
    {
        if (setup->blockEffectId != 0)
        {
            if ((state->flags & HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING) != 0)
            {
                hitAnimatorFn_80193dbc(block, obj, state, setup);
                state->flags &= ~HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E3FB8;
#pragma peephole off
#pragma scheduling off
void groundanimator_init(int* obj, int* desc)
{
    GroundAnimatorState * vstate = (GroundAnimatorState*)((int**)obj)[0xB8 / 4];
    vstate->modelVariant = (u8)((WaveanimatorObjectDef*)desc)->modelVariant;
    vstate->yOffset = (f32)((WaveanimatorObjectDef*)desc)->yOffset;
    vstate->lastDepth = lbl_803E3FB8;
    vstate->radius = (f32)((WaveanimatorObjectDef*)desc)->radius;
    if (((WaveanimatorObjectDef*)desc)->unk25 != 0)
    {
        if (GameBit_Get(((WaveanimatorObjectDef*)desc)->originX) != 0)
        {
            vstate->sinkDepth = lbl_803E3F98 * (f32) * (u8*)&((WaveanimatorObjectDef*)desc)->unk20;
            vstate->flags |= 2;
        }
        ObjGroup_AddObject(obj, 49);
        if (*(u8*)&((WaveanimatorObjectDef*)desc)->period > 1)
        {
            *(u8*)&((WaveanimatorObjectDef*)desc)->period = 0;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void hitanimator_init(HitAnimatorObject* obj, HitAnimatorPlacement* desc)
{
    HitAnimatorState* state = obj->state;
    void* block;
    u8 g;
    s8 init_bit;
    init_bit = (s8)(desc->flags & HITANIMATOR_SETUP_FLAG_INITIAL_INVERT);
    state->activeBit = init_bit;
    state->flags = 0;
    if (GameBit_Get(desc->gameBit) != 0)
    {
        state->activeBit = state->activeBit ^ 1;
        if (desc->toggleMode == 1)
        {
            state->flags |= HITANIMATOR_STATE_FLAG_TOGGLE_PENDING;
        }
    }
    block = mapGetBlock(objPosToMapBlockIdx(
        (double)obj->objAnim.localPosX,
        (double)obj->objAnim.localPosY,
        (double)obj->objAnim.localPosZ));
    if (block != NULL)
    {
        if ((desc->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0 && desc->blockEffectId != 0)
        {
            hitAnimatorFn_80193dbc(block, obj, state, desc);
        }
    }
    state->flags |= HITANIMATOR_STATE_FLAG_SOUND_PENDING;
    if ((desc->flags & HITANIMATOR_SETUP_FLAG_BLOCK_UPDATE) != 0)
    {
        state->flags |= HITANIMATOR_STATE_FLAG_BLOCK_UPDATE_PENDING;
    }
    g = (u8)GameBit_Get(desc->gameBit);
    state->gameBitValue = g;
    state->previousGameBitValue = g;
    obj->objectFlags |= HITANIMATOR_OBJECT_FLAGS_ENABLED;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void visanimator_init(int* obj, int* desc)
{
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
extern void* lbl_803DDAF0;
extern void* lbl_803DDAF4;
#pragma peephole off
#pragma scheduling off
void waveanimator_free(int* obj)
{
    if (--lbl_803DDAE8 == 0)
    {
        if (lbl_803DDAF4 != NULL) mm_free(lbl_803DDAF4);
        if (lbl_803DDAF0 != NULL) mm_free(lbl_803DDAF0);
        if (lbl_803DDAEC != NULL) mm_free(lbl_803DDAEC);
    }
    ObjGroup_RemoveObject(obj, 27);
}
#pragma scheduling reset
#pragma peephole reset
extern u8 lbl_803DDAF8;
extern u8 framesThisStep;
#pragma scheduling off
#pragma peephole off
void waveanimator_hitDetect(int* obj)
{
    int i;
    int j;
    int off;
    WaveAnimatorState* w;
    if (lbl_803DDAF8 != 0)
    {
        return;
    }
    w = (WaveAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    off = 0;
    for (i = 0; i < w->gridN; i++)
    {
        for (j = 0; j < w->gridN; j++)
        {
            ((s16*)lbl_803DDAF0)[off] += framesThisStep >> 1;
            while (((s16*)lbl_803DDAF0)[off] >= w->period)
            {
                ((s16*)lbl_803DDAF0)[off] -= w->period;
            }
            ((s16*)lbl_803DDAF0)[off + 1] += framesThisStep >> 1;
            while (((s16*)lbl_803DDAF0)[off + 1] >= w->period)
            {
                ((s16*)lbl_803DDAF0)[off + 1] -= w->period;
            }
            off += 2;
        }
    }
    lbl_803DDAF8 = 1;
}

extern void* mapBlockFn_800606ec(void* block, int idx);
extern int mapBlockFn_80060678(void* entry);
extern void* fn_800606DC(void* block, int idx);
extern void fn_800605F0(void* cell, void* out);
extern void fn_8006058C(void* cell, void* in);
#pragma scheduling off
#pragma peephole off
void groundanimator_free(int* obj, int flag)
{
    GroundAnimatorState * w;
    int* r21;
    void* block;
    void* entry;
    void* vtx;
    int blkIdx;
    int mid;
    int inner;
    int off;
    int midoff;
    int innoff;
    int* cell;
    f32 local[2];
    w = (GroundAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    r21 = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    if (flag == 0)
    {
        block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                                (double)((GameObject*)obj)->anim.localPosY,
                                                (double)((GameObject*)obj)->anim.localPosZ));
        if (block != NULL)
        {
            off = 0;
            for (blkIdx = 0; blkIdx < ((MapBlockData*)block)->unk9A; blkIdx++)
            {
                entry = mapBlockFn_800606ec(block, blkIdx);
                if (((GroundanimatorPlacement*)r21)->unk25 == mapBlockFn_80060678(entry))
                {
                    midoff = off;
                    for (mid = *(u16*)entry; mid < ((MapBlockData*)block)->unk14; mid++)
                    {
                        vtx = fn_800606DC(block, mid);
                        innoff = midoff;
                        for (inner = 0; inner < 3; inner++)
                        {
                            cell = (int*)((char*)((MapBlockData*)block)->unk58 +
                                *(u16*)vtx * 6);
                            fn_800605F0(cell, local);
                            if (w->heightBuf != 0)
                            {
                                local[1] = (f32) * (s16*)((char*)w->heightBuf + innoff);
                                fn_8006058C(cell, local);
                            }
                            innoff += 2;
                            midoff += 2;
                            off += 2;
                            vtx = (char*)vtx + 2;
                        }
                    }
                }
            }
        }
    }
    if (w->falloffBuf != 0)
    {
        mm_free((void*)w->falloffBuf);
    }
    ObjGroup_RemoveObject(obj, 0x31);
}

extern f32 lbl_803E3FA8;
extern f32 lbl_803E3FAC;
extern f32 lbl_803E3FB0;
extern f32 lbl_803E3FB4;
extern f32 lbl_803E3FBC;
extern f32 timeDelta;
extern void fn_801A80F0(int* e, int arg);
#pragma scheduling off
#pragma peephole off
f32 groundanimator_setScale(int* obj, int* target)
{
    GroundAnimatorState * g;
    int* r31;
    f32 dy;
    f32 dx;
    f32 dz;
    f32 r;
    g = (GroundAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    r31 = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    dy = *(f32*)((char*)target + 0x10) - ((GameObject*)obj)->anim.localPosY;
    if (dy < lbl_803E3FA8 || dy > lbl_803E3FAC)
    {
        return lbl_803E3FB0;
    }
    dx = *(f32*)((char*)target + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dz = *(f32*)((char*)target + 0x14) - ((GameObject*)obj)->anim.localPosZ;
    r = lbl_803E3FB4 + g->radius;
    if (dx * dx + dz * dz > r * r)
    {
        return lbl_803E3FB8;
    }
    if (g->sinkDepth >= lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r31)->unk20)
    {
        if (g->linkedObj != 0)
        {
            int* e = (int*)g->linkedObj;
            g->sinkDepth = lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r31)->unk20;
            if (*(s16*)((char*)e + 0x46) == 0x519)
            {
                fn_801A80F0(e, 0);
            }
            else
            {
                (*(code*)(*(int*)(*(int*)((char*)e + 0x68)) + 0x24))(e, 0);
            }
        }
    }
    g->sinkDepth = lbl_803E3FBC * timeDelta + g->sinkDepth;
    g->flags = g->flags | 4;
    return g->radius *
        (g->sinkDepth / (lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r31)->unk20));
}

extern float fastFloorf(float x);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3FC0;
#pragma scheduling off
#pragma peephole off
void fn_801932C8(int* obj, GroundAnimatorState* p2, int* p3)
{
    void* block;
    void* entry;
    void* vtx;
    int blkIdx;
    int mid;
    int inner;
    int foff;
    int ix;
    int iz;
    f32 fracX;
    f32 fracZ;
    f32 radsq;
    f32 clampMax;
    f32 vpos[3];
    block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                            (double)((GameObject*)obj)->anim.localPosY,
                                            (double)((GameObject*)obj)->anim.localPosZ));
    if (block == NULL)
    {
        return;
    }
    if ((((MapBlockData*)block)->unk4 & 8) == 0)
    {
        return;
    }
    ix = (int)fastFloorf((((GameObject*)obj)->anim.localPosX - playerMapOffsetX) / lbl_803E3FC0);
    iz = (int)fastFloorf((((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ) / lbl_803E3FC0);
    fracX = ((GameObject*)obj)->anim.localPosX - (lbl_803E3FC0 * (f32)ix + playerMapOffsetX);
    fracZ = ((GameObject*)obj)->anim.localPosZ - (lbl_803E3FC0 * (f32)iz + playerMapOffsetZ);
    p2->entryCount = 0;
    radsq = p2->radius * p2->radius;
    foff = 0;
    for (blkIdx = 0; blkIdx < ((MapBlockData*)block)->unk9A; blkIdx++)
    {
        entry = mapBlockFn_800606ec(block, blkIdx);
        if (*(u8*)((char*)p3 + 0x25) == mapBlockFn_80060678(entry))
        {
            mid = *(u16*)entry;
            clampMax = lbl_803E3FC4;
            for (; mid < ((MapBlockData*)block)->unk14; mid++)
            {
                vtx = fn_800606DC(block, mid);
                for (inner = 0; inner < 3; inner++)
                {
                    void* cell = (char*)((MapBlockData*)block)->unk58 + *(u16*)vtx * 6;
                    f32 dx;
                    f32 dz;
                    f32 d;
                    fn_800605F0(cell, vpos);
                    dx = vpos[0] - fracX;
                    dz = vpos[2] - fracZ;
                    d = (dx * dx + dz * dz) / radsq;
                    if (d > clampMax)
                    {
                        d = clampMax;
                    }
                    d = d * d;
                    ((f32*)p2->falloffBuf)[foff] = clampMax - d;
                    *(s16*)((char*)p2->heightBuf + foff * 2) = (int)vpos[1];
                    foff++;
                    vtx = (char*)vtx + 2;
                }
            }
            p2->blockEntries[(p2->entryCount)++] = (s16)blkIdx;
        }
    }
}

extern int* Obj_GetPlayerObject(void);
extern int fn_80060688(void* block, int v);
extern void fn_801A80C4(void* o, f32 x, f32 y, f32 z);
extern void Sfx_PlayFromObject(int* obj, int id);
extern void* getTrickyObject(void);
extern void objRenderFn_80041018(int* obj);
extern void DCStoreRangeNoSync(void* addr, int len);
extern void* mmAlloc(int size, int align, int tag);
extern u16 lbl_803DBDF0[];
#pragma scheduling off
#pragma peephole off
void groundanimator_update(int* obj)
{
    GroundAnimatorState * g;
    int* r20;
    s8 bi;
    void* block;
    void* near;
    void* entry;
    void* vtx;
    int blkIdx;
    int mid;
    int inner;
    int foff;
    int hoff;
    int oldbit;
    int allow;
    void* tricky;
    f32 nd;
    f32 vbuf[2];
    Obj_GetPlayerObject();
    g = (GroundAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    r20 = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    if (((GroundanimatorPlacement*)r20)->unk25 == 0)
    {
        return;
    }
    bi = objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                             (double)((GameObject*)obj)->anim.localPosY,
                             (double)((GameObject*)obj)->anim.localPosZ);
    oldbit = g->flags & 1;
    if (bi > -1)
    {
        g->flags = g->flags | 1;
    }
    else
    {
        g->flags = g->flags & ~1;
    }
    if ((g->flags & 1) != oldbit)
    {
        g->dirtyFrames = 2;
    }
    if ((g->flags & 1) == 0)
    {
        return;
    }
    if ((g->flags & 1) != 0 && *(void**)&g->falloffBuf == NULL)
    {
        int p;
        block = mapGetBlock(bi);
        g->vertCount = (s16)(fn_80060688(block, ((GroundanimatorPlacement*)r20)->unk25) * 3);
        if (g->vertCount > 0)
        {
            p = (int)mmAlloc(g->vertCount * 6, 5, 0);
            g->falloffBuf = p;
            g->heightBuf = p + g->vertCount * 4;
            fn_801932C8(obj, g, r20);
        }
    }
    if (g->vertCount == 0)
    {
        return;
    }
    if (((GroundanimatorPlacement*)r20)->unk22 == 0)
    {
        if (*(void**)&g->linkedObj == NULL)
        {
            nd = lbl_803E3F98;
            g->linkedObj = (int)ObjGroup_FindNearestObject(4, obj, &nd);
            near = (void*)g->linkedObj;
            if (g->linkedObj != 0)
            {
                if (*(s16*)((char*)near + 0x46) == 0x519)
                {
                    if ((g->flags & 2) == 0)
                    {
                        fn_801A80F0(near, 1);
                    }
                    fn_801A80C4(near, ((GameObject*)obj)->anim.localPosX,
                                ((GameObject*)obj)->anim.localPosY - g->yOffset,
                                ((GameObject*)obj)->anim.localPosZ);
                }
                else
                {
                    if ((g->flags & 2) == 0)
                    {
                        (*(code*)(*(int*)(*(int*)((char*)near + 0x68)) + 0x24))(near, 1);
                    }
                    (*(code*)(*(int*)(*(int*)((char*)near + 0x68)) + 0x38))(
                        near, ((GameObject*)obj)->anim.localPosX,
                        ((GameObject*)obj)->anim.localPosY - g->yOffset,
                        ((GameObject*)obj)->anim.localPosZ);
                }
            }
        }
        else if ((*(u16*)((char*)g->linkedObj + 0xb0) & 0x40) != 0)
        {
            g->linkedObj = 0;
        }
    }
    block = mapGetBlock(bi);
    if (block == NULL)
    {
        return;
    }
    if ((((MapBlockData*)block)->unk4 & 8) == 0)
    {
        return;
    }
    if (g->sinkDepth > lbl_803E3FB0)
    {
        if ((g->flags & 4) != 0)
        {
            g->flags = g->flags & ~4;
        }
        else if (g->sinkDepth <
            lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r20)->unk20)
        {
            g->sinkDepth = g->sinkDepth - timeDelta;
            if (g->sinkDepth < lbl_803E3FB0)
            {
                g->sinkDepth = lbl_803E3FB0;
            }
        }
        if (g->sinkDepth != g->lastDepth)
        {
            g->dirtyFrames = 2;
            g->lastDepth = g->sinkDepth;
        }
        if (g->dirtyFrames != 0)
        {
            f32 lim = lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r20)->unk20;
            g->dirtyFrames = g->dirtyFrames - 1;
            if (g->lastDepth > lim)
            {
                g->lastDepth = lim;
                g->sinkDepth = lim;
                if (g->linkedObj != 0 && *(int*)((char*)g->linkedObj + 0xb8) != 0)
                {
                    if (*(s16*)((char*)g->linkedObj + 0x46) == 0x519)
                    {
                        fn_801A80F0((void*)g->linkedObj, 0);
                    }
                    else
                    {
                        (*(code*)(*(int*)(*(int*)((char*)g->linkedObj + 0x68)) + 0x24))((void*)g->linkedObj, 0);
                    }
                }
                GameBit_Set(((GroundanimatorPlacement*)r20)->unk18, 1);
                g->flags = g->flags | 2;
                Sfx_PlayFromObject(obj, lbl_803DBDF0[((GroundanimatorPlacement*)r20)->unk21]);
            }
            foff = 0;
            hoff = 0;
            for (blkIdx = 0; blkIdx < g->entryCount; blkIdx++)
            {
                entry = mapBlockFn_800606ec(block, g->blockEntries[blkIdx]);
                for (mid = *(u16*)entry; mid < *(u16*)((char*)entry + 0x14); mid++)
                {
                    vtx = fn_800606DC(block, mid);
                    for (inner = 0; inner < 3; inner++)
                    {
                        if (*(f32*)((char*)g->falloffBuf + foff) > lbl_803E3FB0)
                        {
                            void* cell = (char*)((MapBlockData*)block)->unk58 + *(u16*)vtx * 6;
                            f32 fv = (f32) * (s16*)((char*)g->heightBuf + hoff);
                            fn_800605F0(cell, &vbuf[1]);
                            vbuf[0] = fv - (g->lastDepth / lbl_803E3F98) *
                                *(f32*)((char*)g->falloffBuf + foff);
                            fn_8006058C(cell, &vbuf[1]);
                        }
                        foff += 4;
                        hoff += 2;
                        vtx = (char*)vtx + 2;
                    }
                }
            }
            DCStoreRangeNoSync((void*)((MapBlockData*)block)->unk58,
                               ((MapBlockData*)block)->unk90 * 6);
        }
    }
    if (((GroundanimatorPlacement*)r20)->unk1A == -1)
    {
        allow = 1;
    }
    else
    {
        allow = GameBit_Get(((GroundanimatorPlacement*)r20)->unk1A) != 0;
    }
    if ((g->flags & 2) == 0 && allow != 0)
    {
        tricky = getTrickyObject();
        if (tricky != NULL && GameBit_Get(0x4e4) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x10;
        }
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8;
        if (tricky != NULL && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
        {
            (*(code*)(*(int*)(*(int*)((char*)tricky + 0x68)) + 0x28))(tricky, obj, 1, 1);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8;
    }
    objRenderFn_80041018(obj);
}

extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;

void alphaanimator_update(int* obj)
{
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
                s->doneCount = s->doneCount + 1;
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
                s->doneCount = s->doneCount + 1;
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
            s->doneCount = s->doneCount + 1;
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
            s->doneCount = s->doneCount + 1;
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
            s->doneCount = s->doneCount + 1;
        }
        s->fadeB = s->fadeA - lbl_803E3F84;
    }
}

extern f32 lbl_803E3F40;
extern f32 lbl_803E3F44;
extern f32 lbl_803E3F48;
extern f32 lbl_803E3F4C;
extern f32 lbl_803E3F50;
extern f32 lbl_803E3F54;
extern f32 lbl_803E3F58;
extern f32 lbl_803E3F5C;
extern f32 lbl_803E3F60;
extern f32 lbl_803E3F64;
extern f32 mathSinf(f32);

void fn_801923F8(int* cfgArg)
{
    int i;
    int j;
    int x;
    int stepX;
    int y;
    int stepY;
    int flat;
    int fi;
    int bi;
    int hi;
    f32 c48;
    f32 c4C;
    f32 z;
    WaveAnimatorState* cfg = (WaveAnimatorState*)cfgArg;

    lbl_803DDAF4 = mmAlloc(4 * cfg->period * cfg->period, 0xFFFFFF, 0);
    lbl_803DDAEC = mmAlloc(3 * cfg->period * cfg->period, 0xFFFFFF, 0);

    x = cfg->originX;
    stepX = (s32)((lbl_803E3F40 * (f32)cfg->spanX) / (f32)cfg->period);
    y = cfg->originY;
    stepY = (s32)((lbl_803E3F40 * (f32)cfg->spanY) / (f32)cfg->period);

    z = lbl_803E3F44;
    cfg->maxHeight = z;
    cfg->minHeight = z;

    flat = 0;
    c48 = lbl_803E3F48;
    c4C = lbl_803E3F4C;
    for (i = 0; i < cfg->period; i++)
    {
        f32 xv = c48 * (f32)x;
        for (j = 0; j < cfg->period; j++)
        {
            f32 s1 = mathSinf((c48 * (f32)y) / c4C);
            f32 a = cfg->ampY * s1;
            f32 s2 = mathSinf(xv / c4C);
            ((f32*)lbl_803DDAF4)[flat] = cfg->ampX * s2 + a;
            if (((f32*)lbl_803DDAF4)[flat] < cfg->minHeight)
            {
                cfg->minHeight = ((f32*)lbl_803DDAF4)[flat];
            }
            if (((f32*)lbl_803DDAF4)[flat] > cfg->maxHeight)
            {
                cfg->maxHeight = ((f32*)lbl_803DDAF4)[flat];
            }
            y += stepY;
            flat++;
        }
        x += stepX;
    }

    {
        f32 negMin = -cfg->minHeight;
        f32 zero2;
        fi = 0;
        bi = 0;
        zero2 = lbl_803E3F44;
        for (i = 0; i < cfg->period; i++)
        {
            for (j = 0; j < cfg->period; j++)
            {
                f32 v = ((f32*)lbl_803DDAF4)[fi];
                if (v < zero2)
                {
                    f32 t = (v - cfg->minHeight) / negMin;
                    ((s8*)lbl_803DDAEC)[bi] = (s32)(lbl_803E3F54 * t + lbl_803E3F50);
                    ((s8*)lbl_803DDAEC)[bi + 1] = (s32)(lbl_803E3F5C * t + lbl_803E3F58);
                    ((s8*)lbl_803DDAEC)[bi + 2] = (s32)(lbl_803E3F64 * t + lbl_803E3F60);
                }
                else
                {
                    ((s8*)lbl_803DDAEC)[bi] = 255;
                    ((s8*)lbl_803DDAEC)[bi + 1] = 255;
                    ((s8*)lbl_803DDAEC)[bi + 2] = 255;
                }
                fi++;
                bi += 3;
            }
        }
    }

    lbl_803DDAF0 = mmAlloc(4 * cfg->gridN * cfg->gridN, 0xFFFFFF, 0);
    hi = 0;
    for (i = 0; i < cfg->gridN; i++)
    {
        for (j = 0; j < cfg->gridN; j++)
        {
            ((s16*)lbl_803DDAF0)[hi] = (s16)(i * 10);
            ((s16*)lbl_803DDAF0)[hi + 1] = (s16)(j * 10);
            hi += 2;
        }
    }
}

extern char* fn_8006070C(void* block, int idx);
extern u8* Shader_getLayer(char* s, int layer);

void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate, HitAnimatorPlacement* desc)
{
    int i;
    char* m;

    if ((desc->flags & 0x10) == 0)
    {
        for (i = 0; i < ((MapBlockData*)block)->unk9A; i++)
        {
            m = (char*)mapBlockFn_800606ec(block, i);
            if (desc->blockEffectId == mapBlockFn_80060678(m))
            {
                if (vstate->activeBit != 0)
                {
                    *(int*)(m + 0x10) &= ~2;
                    if ((desc->flags & 0x2) != 0)
                    {
                        *(int*)(m + 0x10) &= ~1;
                    }
                }
                else
                {
                    *(int*)(m + 0x10) |= 2;
                    if ((desc->flags & 0x2) != 0)
                    {
                        *(int*)(m + 0x10) |= 1;
                    }
                }
            }
        }
    }
    if ((desc->flags & 0x2) != 0)
    {
        for (i = 0; i < *((u8*)block + 0xa2); i++)
        {
            char* s = fn_8006070C(block, i);
            u8* layer = Shader_getLayer(s, 0);
            if (desc->blockEffectId == layer[5])
            {
                if (vstate->activeBit != 0)
                {
                    *(int*)(s + 0x3c) &= ~2;
                }
                else
                {
                    *(int*)(s + 0x3c) |= 2;
                }
            }
        }
    }
}
