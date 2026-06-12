/* === moved from main/dll/mmp_moonrock.c [80192394-801923C4) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/dll/mmp_moonrock.h"

typedef struct WaveanimatorState
{
    u8 pad0[0x34 - 0x0];
    u8 unk34;
    u8 pad35[0x36 - 0x35];
    u8 unk36;
    u8 unk37;
    u8 unk38;
    u8 pad39[0x40 - 0x39];
} WaveanimatorState;


extern uint GameBit_Get(int eventId);


extern void* mapGetBlock(int idx);
















void waveanimator_modelMtxFn(int obj, int a, int b, int c);



extern f32 lbl_803E3F30;
extern void objRenderFn_8003b8f4(f32);


#pragma scheduling reset
#pragma peephole reset

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

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

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

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

/* groundanimator_getExtraSize == 0x30. */
STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

/* visanimator_getExtraSize == 0x5. */
typedef struct VisAnimatorState
{
    u8 flags; /* 0x00: 1 = refresh pending */
    s8 visBit; /* 0x01 */
    u8 gateNow; /* 0x02 */
    u8 gatePrev; /* 0x03 */
    u8 gateMask; /* 0x04 */
} VisAnimatorState;

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017af0();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
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
void waveanimator_func0B(int* obj);

#pragma scheduling reset
#pragma peephole reset

extern void mm_free(void* p);

void alphaanimator_free(int* obj);

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

void waveanimator_release(void);

void waveanimator_initialise(void);

void alphaanimator_hitDetect(void);

void alphaanimator_release(void);

void alphaanimator_initialise(void);

void visanimator_free(void);

void visanimator_render(void);

void visanimator_hitDetect(void);

void visanimator_release(void);

void visanimator_initialise(void);

/* 8b "li r3, N; blr" returners. */
int waveanimator_getExtraSize(void);
int waveanimator_getObjectTypeId(void);
int alphaanimator_getExtraSize(void);
int alphaanimator_getObjectTypeId(void);
int groundanimator_getExtraSize(void);
int hitanimator_getExtraSize(void) { return 0x4; }
int visanimator_getExtraSize(void);
int visanimator_getObjectTypeId(void);

/* Pattern wrappers. */
u8 groundanimator_modelMtxFn(int* obj);

/* 16b chained patterns. */
#pragma scheduling off
void alphaanimator_init(int* obj);
#pragma scheduling reset

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3F70;
extern f32 lbl_803E3F78;
extern f32 lbl_803E3FC4;
#pragma peephole off
void waveanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void alphaanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
#pragma peephole reset

/* wall variant: hashes lha to byte */
#pragma peephole off
u8 wallanimator_modelMtxFn(int* obj);

void waveanimator_setScale(int* obj, f32 fval);
#pragma peephole reset

extern f32 lbl_803E3F98;
#pragma scheduling off
u8 groundanimator_func0B(int* obj);
#pragma scheduling reset

extern void fn_801923F8(int* cfg);
extern void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate,
                                   HitAnimatorPlacement* desc);
extern int fn_80065640(void);
extern void fn_80065574(int a, int b, int c);
extern u8 lbl_803DDAE8;
#pragma peephole off
#pragma scheduling off
void waveanimator_init(int* obj, int* desc);
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void hitanimator_update(HitAnimatorObject* obj)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
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
void groundanimator_init(int* obj, int* desc);
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void hitanimator_init(HitAnimatorObject* obj, HitAnimatorPlacement* desc)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
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
void visanimator_init(int* obj, int* desc);

void visanimator_update(int* obj);
#pragma scheduling reset
#pragma peephole reset

extern void* lbl_803DDAEC;
extern void* lbl_803DDAF0;
extern void* lbl_803DDAF4;
#pragma peephole off
#pragma scheduling off
void waveanimator_free(int* obj);
#pragma scheduling reset
#pragma peephole reset
extern u8 lbl_803DDAF8;
extern u8 framesThisStep;
#pragma scheduling off
#pragma peephole off
void waveanimator_hitDetect(int* obj);

extern void* mapBlockFn_800606ec(void* block, int idx);
extern int mapBlockFn_80060678(void* entry);
extern void* fn_800606DC(void* block, int idx);
extern void fn_800605F0(void* cell, void* out);
extern void fn_8006058C(void* cell, void* in);
#pragma scheduling off
#pragma peephole off
void groundanimator_free(int* obj, int flag);

extern f32 lbl_803E3FA8;
extern f32 lbl_803E3FAC;
extern f32 lbl_803E3FB0;
extern f32 lbl_803E3FB4;
extern f32 lbl_803E3FBC;
extern f32 timeDelta;
extern void fn_801A80F0(int* e, int arg);
#pragma scheduling off
#pragma peephole off
f32 groundanimator_setScale(int* obj, int* target);

extern float fastFloorf(float x);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3FC0;
#pragma scheduling off
#pragma peephole off
void fn_801932C8(int* obj, GroundAnimatorState* p2, int* p3);

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
void groundanimator_update(int* obj);

extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;

void alphaanimator_update(int* obj);

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

void fn_801923F8(int* cfgArg);

extern u8* Shader_getLayer(char* s, int layer);

void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate, HitAnimatorPlacement* desc)
{
    extern char* fn_8006070C(void* block, int idx); /* #57 */
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
