/* DLL 0x0138 (groundanimator) - Ground animator object [0x80193100-0x80193DBC). */
#include "main/dll/mmp_moonrock.h"
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"
extern void* mapGetBlock(int i);
extern void objRenderFn_8003b8f4(f32);
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"
#include "main/gamebits.h"
#include "dolphin/os/OSCache.h"
#include "main/mm.h"
#include "main/track_dolphin.h"
#include "main/dll/fx_800944A0_shared.h"

typedef struct GroundanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 sunkGameBit;
    s16 enableGameBit;
    u8 pad1C[0x20 - 0x1C];
    u8 maxSinkDepth;
    u8 sfxIndex;
    u8 unk22;
    u8 pad23[0x25 - 0x23];
    u8 blockId;
    u8 pad26[0x28 - 0x26];
} GroundanimatorPlacement;

/* waveanimator_getExtraSize == 0x3c (also the shared wave-grid config fed
 * to fn_801923F8; the grid/color/phase tables live in the lbl_803DDAEC/F0/F4
 * globals). */

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern int FUN_80017af0();
extern int ObjGroup_FindNearestObject();
extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();
extern int FUN_8005337c();
extern u32 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern u64 FUN_8028682c();
extern u32 FUN_80286878();

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E3FC4;
extern const f32 lbl_803E3F98;
extern void fn_801923F8(int* cfg);
extern const f32 lbl_803E3FB8;
extern void* mapBlockFn_800606ec(int* obj, int idx);
extern int mapBlockFn_80060678(void* entry);

extern void fn_800605F0(void* cell, void* out);
extern void fn_8006058C(void* cell, void* in);
extern f32 lbl_803E3FA8;
extern const f32 lbl_803E3FAC;
extern const f32 lbl_803E3FB0;
extern const f32 lbl_803E3FB4;
extern const f32 lbl_803E3FBC;
extern void fn_801A80F0(int* e, int arg);
extern float fastFloorf(float x);
extern const f32 lbl_803E3FC0;

extern int fn_80060688(void* block, int v);
extern void fn_801A80C4(void* o, f32 x, f32 y, f32 z);
extern void Sfx_PlayFromObject(int* obj, int id);
extern void* getTrickyObject(void);
extern void objRenderFn_80041018(int* obj);
extern u16 lbl_803DBDF0;

void FUN_80192488(void)
{
    int texV;
    int ctxHi;
    int block;
    int polyIdx;
    int cell;
    u32 gameBit;
    int texU;
    int ctxLo;
    int mapId;
    int placement;
    int vtxIdx;
    int vtx;
    u64 pair;

    pair = FUN_8028682c();
    ctxHi = (int)((u64)pair >> 0x20);
    ctxLo = pair;
    placement = *(int*)(ctxHi + 0x4c);
    block = FUN_8005b398((double)*(float*)(ctxHi + 0xc), (double)*(float*)(ctxHi + 0x10));
    block = FUN_8005af70(block);
    if (block == 0)
    {
        *(u8*)(ctxLo + 0x10) = 1;
    }
    else
    {
        polyIdx = FUN_80017af0(0xe);
        if ((polyIdx != 0) &&
            (placement = FUN_8005337c(-*(int*)(polyIdx + *(short*)(placement + 0x18) * 4)), placement != 0))
        {
            for (polyIdx = 0; polyIdx < (int)(u32) * (u8*)(block + 0xa2); polyIdx = polyIdx + 1)
            {
                cell = FUN_800600e4(block, polyIdx);
                vtx = cell;
                for (vtxIdx = 0; vtxIdx < (int)(u32) * (u8*)(cell + 0x41); vtxIdx = vtxIdx + 1)
                {
                    if (*(int*)(vtx + 0x24) == placement)
                    {
                        texU = (u32) * (u16*)(placement + 10) << 6;
                        texV = (u32) * (u16*)(placement + 0xc) << 6;
                        if (*(u8*)(vtx + 0x2a) == 0xff)
                        {
                            texU = FUN_80056448((int)*(char*)(ctxLo + 0x11), (int)*(char*)(ctxLo + 0x12), texU,
                                                 texV);
                            *(char*)(vtx + 0x2a) = texU;
                        }
                        else
                        {
                            mapId = *(int*)(*(int*)(ctxHi + 0x4c) + 0x14);
                            if ((mapId == 0x49b2f) || (mapId == 0x49b67))
                            {
                                gameBit = GameBit_Get(*(u32*)(ctxLo + 8));
                                if (gameBit != 0)
                                {
                                    FUN_80056418((u32) * (u8*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                                 (int)*(char*)(ctxLo + 0x12), texU, texV);
                                }
                            }
                            else
                            {
                                FUN_80056418((u32) * (u8*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
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

int groundanimator_getExtraSize(void) { return 0x30; }
int hitanimator_getExtraSize(void);

u8 groundanimator_modelMtxFn(int* obj) { return *(u8*)((char*)(int*)((GameObject*)obj)->extra + 0x2b); }

#pragma peephole off
void groundanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3FC4);
}

#pragma scheduling off
#pragma peephole on
u8 groundanimator_func0B(int* obj)
{
    GroundAnimatorState * state = (GroundAnimatorState*)((int**)obj)[0xB8 / 4];
    f32 depth = state->sinkDepth;
    int* placement = ((int**)obj)[0x4C / 4];
    u8 maxDepth = ((GroundanimatorPlacement*)placement)->maxSinkDepth;
    return depth > lbl_803E3F98 * maxDepth;
}

#pragma peephole off
void groundanimator_init(int* obj, int* desc)
{
    GroundAnimatorState * vstate = (GroundAnimatorState*)((int**)obj)[0xB8 / 4];
    vstate->modelVariant = (u8)((WaveanimatorObjectDef*)desc)->modelVariant;
    vstate->yOffset = (f32)((WaveanimatorObjectDef*)desc)->yOffset;
    vstate->lastDepth = lbl_803E3FB8;
    vstate->radius = (f32)((WaveanimatorObjectDef*)desc)->radius;
    if (((WaveanimatorObjectDef*)desc)->sinkEnable != 0)
    {
        if (GameBit_Get(((WaveanimatorObjectDef*)desc)->originX) != 0)
        {
            vstate->sinkDepth = lbl_803E3F98 * (f32) * (u8*)&((WaveanimatorObjectDef*)desc)->sinkDepthScale;
            vstate->flags |= 2;
        }
        ObjGroup_AddObject(obj, 49);
        if (*(u8*)&((WaveanimatorObjectDef*)desc)->period > 1)
        {
            *(u8*)&((WaveanimatorObjectDef*)desc)->period = 0;
        }
    }
}

void groundanimator_free(int* obj, int flag)
{
    extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z); /* #57 */
    void* entry;
    void* vtx;
    int innoff;
    int midoff;
    int off;
    int blkIdx;
    int mid;
    int inner;
    void* block;
    GroundAnimatorState * w;
    int* r21;
    void* nv;
    int* cell;
    f32 local[4];
    w = (GroundAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    r21 = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    if (flag == 0)
    {
        block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                                (double)((GameObject*)obj)->anim.localPosY,
                                                (double)((GameObject*)obj)->anim.localPosZ));
        if (block != NULL)
        {
            for (blkIdx = 0, off = 0; blkIdx < ((MapBlockData*)block)->unk9A; blkIdx++)
            {
                entry = mapBlockFn_800606ec(block, blkIdx);
                if (((GroundanimatorPlacement*)r21)->blockId == mapBlockFn_80060678(entry))
                {
                    for (mid = *(u16*)entry, midoff = off; mid < *(u16*)((char*)entry + 0x14); mid++)
                    {
                        nv = fn_800606DC(block, mid);
                        for (inner = 0, vtx = nv, innoff = midoff; inner < 3; inner++)
                        {
                            cell = (int*)((char*)((MapBlockData*)block)->unk58 +
                                *(u16*)vtx * 6);
                            fn_800605F0(cell, local);
                            if (*(void**)&w->heightBuf != NULL)
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
    if (*(void**)&w->falloffBuf != NULL)
    {
        mm_free((void*)w->falloffBuf);
    }
    ObjGroup_RemoveObject(obj, 0x31);
}

f32 groundanimator_setScale(int* obj, int* target)
{
    int* r31;
    GroundAnimatorState * g;
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
    r = r * r;
    if (dx * dx + dz * dz > r)
    {
        return lbl_803E3FB8;
    }
    if (g->sinkDepth >= lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r31)->maxSinkDepth)
    {
        if (*(void**)&g->linkedObj != NULL)
        {
            int* e;
            g->sinkDepth = lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r31)->maxSinkDepth;
            e = (int*)g->linkedObj;
            switch (((GameObject*)e)->anim.seqId)
            {
            case 0x519:
                fn_801A80F0(e, 0);
                break;
            default:
                (*(VtableFn*)(*(int*)(*(int*)((char*)e + 0x68)) + 0x24))(e, 0);
                break;
            }
        }
    }
    g->sinkDepth = lbl_803E3FBC * timeDelta + g->sinkDepth;
    g->flags = g->flags | 4;
    return g->radius *
        (g->sinkDepth / (lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r31)->maxSinkDepth));
}

void fn_801932C8(int* obj, GroundAnimatorState* state, int* placement)
{
    extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z); /* #57 */
    void* block;
    void* entry;
    void* vtx;
    int mid;
    int inner;
    int ix;
    int fallInn;
    int htInn;
    int fallMid;
    int htMid;
    int fallOff;
    int htOff;
    int iz;
    int blkIdx;
    f32 fracX;
    f32 clampMax;
    f32 fracZ;
    f32 radsq;
    f32 vpos[3];
    block = mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                            (double)((GameObject*)obj)->anim.localPosY,
                                            (double)((GameObject*)obj)->anim.localPosZ));
    if (block == NULL || (((MapBlockData*)block)->unk4 & 8) == 0)
    {
        return;
    }
    ix = fastFloorf((((GameObject*)obj)->anim.localPosX - playerMapOffsetX) / lbl_803E3FC0);
    iz = fastFloorf((((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ) / lbl_803E3FC0);
    fracX = ((GameObject*)obj)->anim.localPosX - (lbl_803E3FC0 * ix + playerMapOffsetX);
    fracZ = ((GameObject*)obj)->anim.localPosZ - (lbl_803E3FC0 * iz + playerMapOffsetZ);
    fallOff = 0;
    state->entryCount = 0;
    radsq = state->radius * state->radius;
    htOff = fallOff;
    for (blkIdx = 0; blkIdx < ((MapBlockData*)block)->unk9A; blkIdx++)
    {
        entry = mapBlockFn_800606ec(block, blkIdx);
        if (((GroundanimatorPlacement*)placement)->blockId == mapBlockFn_80060678(entry))
        {
            mid = *(u16*)entry;
            fallMid = fallOff;
            fallMid |= fallOff;
            htMid = htOff;
            htMid |= htOff;
            clampMax = lbl_803E3FC4;
            for (; mid < ((MapBlockData*)block)->unk14; mid++)
            {
                vtx = fn_800606DC(block, mid);
                fallInn = fallMid;
                htInn = htMid;
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
                    *(f32*)((char*)state->falloffBuf + fallInn) = clampMax - d;
                    *(s16*)((char*)state->heightBuf + htInn) = vpos[1];
                    fallInn += 4;
                    htInn += 2;
                    fallMid += 4;
                    htMid += 2;
                    fallOff += 4;
                    htOff += 2;
                    vtx = (char*)vtx + 2;
                }
            }
            state->blockEntries[(state->entryCount)++] = blkIdx;
        }
    }
}

#pragma fp_contract off
void groundanimator_update(int* obj)
{
    extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z); /* #57 */
    int foff;
    int hoff;
    int hoffVtx;
    u8 oldbit;
    int blkIdx;
    void* tricky;
    u8 allow;
    int mid;
    int inner;
    GroundAnimatorState * g;
    int* r20;
    void* entry;
    void* near;
    int hoffEntry;
    int foffEntry;
    int foffVtx;
    f32 nd;
    void* vtx;
    void* block;
    s8 bi;
    f32 vbuf[3];
    Obj_GetPlayerObject();
    g = (GroundAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    r20 = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    if (((GroundanimatorPlacement*)r20)->blockId == 0)
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
        g->vertCount = (s16)(fn_80060688(block, ((GroundanimatorPlacement*)r20)->blockId) * 3);
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
            g->linkedObj = ObjGroup_FindNearestObject(4, obj, &nd);
            near = (void*)g->linkedObj;
            if (near != NULL)
            {
                switch (((GameObject*)g->linkedObj)->anim.seqId)
                {
                case 0x519:
                    if ((g->flags & 2) == 0)
                    {
                        fn_801A80F0(near, 1);
                    }
                    fn_801A80C4(near, ((GameObject*)obj)->anim.localPosX,
                                ((GameObject*)obj)->anim.localPosY - g->yOffset,
                                ((GameObject*)obj)->anim.localPosZ);
                    break;
                default:
                    if ((g->flags & 2) == 0)
                    {
                        (*(VtableFn*)(*(int*)(*(int*)((char*)near + 0x68)) + 0x24))(near, 1);
                    }
                    (*(VtableFn*)(*(int*)(*(int*)((char*)near + 0x68)) + 0x38))(
                        near, ((GameObject*)obj)->anim.localPosX,
                        ((GameObject*)obj)->anim.localPosY - g->yOffset,
                        ((GameObject*)obj)->anim.localPosZ);
                    break;
                }
            }
        }
        else if ((((GameObject*)g->linkedObj)->objectFlags & 0x40) != 0)
        {
            g->linkedObj = 0;
        }
    }
    block = mapGetBlock(bi);
    if (block == NULL || (((MapBlockData*)block)->unk4 & 8) == 0)
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
            lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r20)->maxSinkDepth)
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
            f32 lim;
            g->dirtyFrames -= 1;
            if (g->lastDepth >
                (lim = lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)r20)->maxSinkDepth))
            {
                g->lastDepth = lim;
                g->sinkDepth = lim;
                if (*(void**)&g->linkedObj != NULL && *(void**)((char*)g->linkedObj + 0xb8) != NULL)
                {
                    switch (((GameObject*)g->linkedObj)->anim.seqId)
                    {
                    case 0x519:
                        fn_801A80F0((void*)g->linkedObj, 0);
                        break;
                    default:
                        (*(VtableFn*)(*(int*)(*(int*)((char*)g->linkedObj + 0x68)) + 0x24))((void*)g->linkedObj, 0);
                        break;
                    }
                }
                GameBit_Set(((GroundanimatorPlacement*)r20)->sunkGameBit, 1);
                g->flags = g->flags | 2;
                Sfx_PlayFromObject(obj, (&lbl_803DBDF0)[((GroundanimatorPlacement*)r20)->sfxIndex]);
            }
            foff = hoff = 0;
            for (blkIdx = 0; blkIdx < g->entryCount; blkIdx++)
            {
                entry = mapBlockFn_800606ec(block, g->blockEntries[blkIdx]);
                foffEntry = foff;
                hoffEntry = hoff;
                for (mid = *(u16*)entry; mid < *(u16*)((char*)entry + 0x14); mid++)
                {
                    vtx = fn_800606DC(block, mid);
                    foffVtx = foffEntry;
                    hoffVtx = hoffEntry;
                    for (inner = 0; inner < 3; inner++)
                    {
                        if (*(f32*)((char*)g->falloffBuf + foffVtx) > lbl_803E3FB0)
                        {
                            void* cell = (char*)((MapBlockData*)block)->unk58 + *(u16*)vtx * 6;
                            fn_800605F0(cell, vbuf);
                            vbuf[1] = (f32) * (s16*)((char*)g->heightBuf + hoffVtx) -
                                (g->lastDepth / lbl_803E3F98) *
                                *(f32*)((char*)g->falloffBuf + foffVtx);
                            fn_8006058C(cell, vbuf);
                        }
                        foffVtx += 4;
                        hoffVtx += 2;
                        foffEntry += 4;
                        hoffEntry += 2;
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
    if (((GroundanimatorPlacement*)r20)->enableGameBit == -1 ||
        GameBit_Get(((GroundanimatorPlacement*)r20)->enableGameBit) != 0)
    {
        allow = 1;
    }
    else
    {
        allow = 0;
    }
    if ((g->flags & 2) == 0 && allow != 0)
    {
        tricky = getTrickyObject();
        if (tricky != NULL && GameBit_Get(0x4e4) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED;
        if (tricky != NULL && (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
        {
            (*(VtableFn*)(*(int*)(*(int*)((char*)tricky + 0x68)) + 0x28))(tricky, obj, 1, 1);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
    }
    objRenderFn_80041018(obj);
}

void fn_801923F8(int* cfgArg);
