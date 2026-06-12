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
int groundanimator_getExtraSize(void) { return 0x30; }
int hitanimator_getExtraSize(void);
int visanimator_getExtraSize(void);
int visanimator_getObjectTypeId(void);

/* Pattern wrappers. */
u8 groundanimator_modelMtxFn(int* obj) { return *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x2b); }

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

void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3FC4);
}
#pragma peephole reset

/* wall variant: hashes lha to byte */
#pragma peephole off
u8 wallanimator_modelMtxFn(int* obj);

void waveanimator_setScale(int* obj, f32 fval);
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
void hitanimator_update(HitAnimatorObject* obj);
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
void hitanimator_init(HitAnimatorObject* obj, HitAnimatorPlacement* desc);
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
void groundanimator_free(int* obj, int flag)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
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
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
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
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
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
            g->dirtyFrames -= 1;
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

void hitAnimatorFn_80193dbc(void* block, HitAnimatorObject* obj, HitAnimatorState* vstate, HitAnimatorPlacement* desc);
