/*
 * DLL 0x0138 (groundanimator) — terrain-deformation object [0x80193100-0x80193DBC).
 *
 * Sinks the map-block ground mesh under the object: at init it allocates a
 * per-vertex falloff/height buffer for the matching block entries (placement
 * entryGroup selects the entry group) and snapshots the original vertex heights.
 * While active it tracks the nearest group-4 object (the player's mount, anim
 * seqId 0x519, or a generic linked object dispatched through its dll vtable)
 * and drives sinkDepth toward the placement's max depth (maxDepth), then rewrites
 * the block vertices each dirty frame and flushes the range with
 * DCStoreRangeNoSync. On reaching full depth it sets the placement game bit
 * (completionBit) and plays an SFX (lbl_803DBDF0[sfxIndex]). Activation is gated by
 * placement game bit gateBit (-1 = always); the hitbox-mode bit toggles feed the
 * Tricky interaction (group bit 0x4e4). State layout: groundanimator_state.h.
 */
#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "main/map_block.h"
#include "main/dll/groundanimator_state.h"

typedef struct GroundanimatorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 completionBit;
    s16 gateBit;
    u8 pad1C[0x20 - 0x1C];
    u8 maxDepth;
    u8 sfxIndex;
    u8 unk22;
    u8 pad23[0x25 - 0x23];
    u8 entryGroup;
    u8 pad26[0x28 - 0x26];
} GroundanimatorPlacement;

#define GROUNDANIMATOR_FLAG_ON_MAP 0x1
#define GROUNDANIMATOR_FLAG_DONE 0x2
#define GROUNDANIMATOR_FLAG_PRESSED 0x4

STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void* mapGetBlock(int idx);
extern void* mapBlockFn_800606ec(void* block, int idx);
extern int mapBlockFn_80060678(void* entry);
extern void* fn_800606DC(void* block, int idx);
extern void fn_800605F0(void* cell, void* out);
extern void fn_8006058C(void* cell, void* in);
extern int fn_80060688(void* block, int v);
extern int* ObjGroup_FindNearestObject();
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void ObjGroup_AddObject(int* obj, int group);
extern int* Obj_GetPlayerObject(void);
extern void* getTrickyObject(void);
extern void fn_801A80F0(int* e, int arg);
extern void fn_801A80C4(void* o, f32 x, f32 y, f32 z);
extern void Sfx_PlayFromObject(int* obj, int id);
extern void objRenderFn_8003b8f4(f32);
extern void objRenderFn_80041018(int* obj);
extern void DCStoreRangeNoSync(void* addr, int len);
extern void* mmAlloc(int size, int align, int tag);
extern void mm_free(void* p);
extern float fastFloorf(float x);
extern f32 timeDelta;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern u16 lbl_803DBDF0[4];
extern const f32 lbl_803E3F98;
extern f32 lbl_803E3FA8;
extern const f32 lbl_803E3FAC;
extern const f32 lbl_803E3FB0;
extern const f32 lbl_803E3FB4;
extern const f32 lbl_803E3FB8;
extern const f32 lbl_803E3FBC;
extern const f32 lbl_803E3FC0;
extern f32 lbl_803E3FC4;

#pragma scheduling on
#pragma peephole on
int groundanimator_getExtraSize(void) { return 0x30; }

u8 groundanimator_modelMtxFn(int* obj) { return *(u8*)((char*)((GameObject*)obj)->extra + 0x2b); }

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
    GroundAnimatorState * state = (GroundAnimatorState*)((GameObject*)obj)->extra;
    f32 depth = state->sinkDepth;
    int* placement = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    u8 maxDepth = *(u8*)((char*)placement + 0x20);
    return depth > lbl_803E3F98 * (f32)maxDepth;
}

#pragma peephole off
void groundanimator_init(int* obj, int* desc)
{
    GroundAnimatorState * state = (GroundAnimatorState*)((GameObject*)obj)->extra;
    state->modelVariant = (u8)((WaveanimatorObjectDef*)desc)->modelVariant;
    state->yOffset = (f32)((WaveanimatorObjectDef*)desc)->yOffset;
    state->lastDepth = lbl_803E3FB8;
    state->radius = (f32)((WaveanimatorObjectDef*)desc)->radius;
    if (((WaveanimatorObjectDef*)desc)->unk25 != 0)
    {
        if (GameBit_Get(((WaveanimatorObjectDef*)desc)->originX) != 0)
        {
            state->sinkDepth = lbl_803E3F98 * (f32) * (u8*)&((WaveanimatorObjectDef*)desc)->unk20;
            state->flags |= GROUNDANIMATOR_FLAG_DONE;
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
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    GroundAnimatorState * state;
    int* placement;
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
    f32 local[4];
    state = (GroundAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    placement = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
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
                if (((GroundanimatorPlacement*)placement)->entryGroup == mapBlockFn_80060678(entry))
                {
                    midoff = off;
                    for (mid = *(u16*)entry; mid < *(u16*)((char*)entry + 0x14); mid++)
                    {
                        vtx = fn_800606DC(block, mid);
                        innoff = midoff;
                        for (inner = 0; inner < 3; inner++)
                        {
                            cell = (int*)((char*)((MapBlockData*)block)->unk58 +
                                *(u16*)vtx * 6);
                            fn_800605F0(cell, local);
                            if (*(void**)&state->heightBuf != NULL)
                            {
                                local[1] = (f32) * (s16*)((char*)state->heightBuf + innoff);
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
    if (*(void**)&state->falloffBuf != NULL)
    {
        mm_free((void*)state->falloffBuf);
    }
    ObjGroup_RemoveObject(obj, 0x31);
}

f32 groundanimator_setScale(int* obj, int* target)
{
    int* placement;
    GroundAnimatorState * state;
    f32 dy;
    f32 dx;
    f32 dz;
    f32 r;
    state = (GroundAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    placement = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    dy = *(f32*)((char*)target + 0x10) - ((GameObject*)obj)->anim.localPosY;
    if (dy < lbl_803E3FA8 || dy > lbl_803E3FAC)
    {
        return lbl_803E3FB0;
    }
    dx = *(f32*)((char*)target + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dz = *(f32*)((char*)target + 0x14) - ((GameObject*)obj)->anim.localPosZ;
    r = lbl_803E3FB4 + state->radius;
    r = r * r;
    if (dx * dx + dz * dz > r)
    {
        return lbl_803E3FB8;
    }
    if (state->sinkDepth >= lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)placement)->maxDepth)
    {
        if (*(void**)&state->linkedObj != NULL)
        {
            int* e;
            state->sinkDepth = lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)placement)->maxDepth;
            e = (int*)state->linkedObj;
            switch (((GameObject*)e)->anim.seqId)
            {
            case 0x519:
                fn_801A80F0(e, 0);
                break;
            default:
                (*(code*)(*(int*)(*(int*)&((GameObject*)e)->anim.dll) + 0x24))(e, 0);
                break;
            }
        }
    }
    state->sinkDepth = lbl_803E3FBC * timeDelta + state->sinkDepth;
    state->flags = state->flags | GROUNDANIMATOR_FLAG_PRESSED;
    return state->radius *
        (state->sinkDepth / (lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)placement)->maxDepth));
}

void fn_801932C8(int* obj, GroundAnimatorState* state, int* placement)
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
    state->entryCount = 0;
    radsq = state->radius * state->radius;
    foff = 0;
    for (blkIdx = 0; blkIdx < ((MapBlockData*)block)->unk9A; blkIdx++)
    {
        entry = mapBlockFn_800606ec(block, blkIdx);
        if (*(u8*)((char*)placement + 0x25) == mapBlockFn_80060678(entry))
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
                    ((f32*)state->falloffBuf)[foff] = clampMax - d;
                    *(s16*)((char*)state->heightBuf + foff * 2) = (int)vpos[1];
                    foff++;
                    vtx = (char*)vtx + 2;
                }
            }
            state->blockEntries[(state->entryCount)++] = (s16)blkIdx;
        }
    }
}

#pragma fp_contract off
void groundanimator_update(int* obj)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    GroundAnimatorState * state;
    int* placement;
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
    u8 oldbit;
    u8 allow;
    void* tricky;
    f32 zero;
    f32 nd;
    f32 vbuf[2];
    Obj_GetPlayerObject(); /* discarded: side-effect call seeding the player-object cache */
    state = (GroundAnimatorState*)*(int*)&((GameObject*)obj)->extra;
    placement = (int*)*(int*)&((GameObject*)obj)->anim.placementData;
    if (((GroundanimatorPlacement*)placement)->entryGroup == 0)
    {
        return;
    }
    bi = objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                             (double)((GameObject*)obj)->anim.localPosY,
                             (double)((GameObject*)obj)->anim.localPosZ);
    oldbit = state->flags & GROUNDANIMATOR_FLAG_ON_MAP;
    if (bi > -1)
    {
        state->flags = state->flags | GROUNDANIMATOR_FLAG_ON_MAP;
    }
    else
    {
        state->flags = state->flags & ~GROUNDANIMATOR_FLAG_ON_MAP;
    }
    if ((state->flags & GROUNDANIMATOR_FLAG_ON_MAP) != oldbit)
    {
        state->dirtyFrames = 2;
    }
    if ((state->flags & GROUNDANIMATOR_FLAG_ON_MAP) == 0)
    {
        return;
    }
    if ((state->flags & GROUNDANIMATOR_FLAG_ON_MAP) != 0 && *(void**)&state->falloffBuf == NULL)
    {
        int p;
        block = mapGetBlock(bi);
        state->vertCount = (s16)(fn_80060688(block, ((GroundanimatorPlacement*)placement)->entryGroup) * 3);
        if (state->vertCount > 0)
        {
            p = (int)mmAlloc(state->vertCount * 6, 5, 0);
            state->falloffBuf = p;
            state->heightBuf = p + state->vertCount * 4;
            fn_801932C8(obj, state, placement);
        }
    }
    if (state->vertCount == 0)
    {
        return;
    }
    if (((GroundanimatorPlacement*)placement)->unk22 == 0)
    {
        if (*(void**)&state->linkedObj == NULL)
        {
            nd = lbl_803E3F98;
            state->linkedObj = (int)ObjGroup_FindNearestObject(4, obj, &nd);
            near = (void*)state->linkedObj;
            if (near != NULL)
            {
                if (((GameObject*)near)->anim.seqId == 0x519)
                {
                    if ((state->flags & GROUNDANIMATOR_FLAG_DONE) == 0)
                    {
                        fn_801A80F0(near, 1);
                    }
                    fn_801A80C4(near, ((GameObject*)obj)->anim.localPosX,
                                ((GameObject*)obj)->anim.localPosY - state->yOffset,
                                ((GameObject*)obj)->anim.localPosZ);
                }
                else
                {
                    if ((state->flags & GROUNDANIMATOR_FLAG_DONE) == 0)
                    {
                        (*(code*)(*(int*)(*(int*)&((GameObject*)near)->anim.dll) + 0x24))(near, 1);
                    }
                    (*(code*)(*(int*)(*(int*)&((GameObject*)near)->anim.dll) + 0x38))(
                        near, ((GameObject*)obj)->anim.localPosX,
                        ((GameObject*)obj)->anim.localPosY - state->yOffset,
                        ((GameObject*)obj)->anim.localPosZ);
                }
            }
        }
        else if ((((GameObject*)state->linkedObj)->objectFlags & 0x40) != 0)
        {
            state->linkedObj = 0;
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
    if (state->sinkDepth > lbl_803E3FB0)
    {
        if ((state->flags & GROUNDANIMATOR_FLAG_PRESSED) != 0)
        {
            state->flags = state->flags & ~GROUNDANIMATOR_FLAG_PRESSED;
        }
        else if (state->sinkDepth <
            lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)placement)->maxDepth)
        {
            state->sinkDepth = state->sinkDepth - timeDelta;
            if (state->sinkDepth < lbl_803E3FB0)
            {
                state->sinkDepth = lbl_803E3FB0;
            }
        }
        if (state->sinkDepth != state->lastDepth)
        {
            state->dirtyFrames = 2;
            state->lastDepth = state->sinkDepth;
        }
        if (state->dirtyFrames != 0)
        {
            f32 lim;
            state->dirtyFrames -= 1;
            lim = lbl_803E3F98 * (f32)(u32)((GroundanimatorPlacement*)placement)->maxDepth;
            if (state->lastDepth > lim)
            {
                state->lastDepth = lim;
                state->sinkDepth = lim;
                if (*(void**)&state->linkedObj != NULL && ((GameObject*)state->linkedObj)->extra != NULL)
                {
                    if (((GameObject*)state->linkedObj)->anim.seqId == 0x519)
                    {
                        fn_801A80F0((void*)state->linkedObj, 0);
                    }
                    else
                    {
                        (*(code*)(*(int*)(*(int*)&((GameObject*)state->linkedObj)->anim.dll) + 0x24))((void*)state->linkedObj, 0);
                    }
                }
                GameBit_Set(((GroundanimatorPlacement*)placement)->completionBit, 1);
                state->flags = state->flags | GROUNDANIMATOR_FLAG_DONE;
                Sfx_PlayFromObject(obj, lbl_803DBDF0[((GroundanimatorPlacement*)placement)->sfxIndex]);
            }
            foff = 0;
            hoff = 0;
            zero = lbl_803E3FB0;
            for (blkIdx = 0; blkIdx < state->entryCount; blkIdx++)
            {
                entry = mapBlockFn_800606ec(block, state->blockEntries[blkIdx]);
                for (mid = *(u16*)entry; mid < *(u16*)((char*)entry + 0x14); mid++)
                {
                    vtx = fn_800606DC(block, mid);
                    for (inner = 0; inner < 3; inner++)
                    {
                        if (*(f32*)((char*)state->falloffBuf + foff) > zero)
                        {
                            void* cell = (char*)((MapBlockData*)block)->unk58 + *(u16*)vtx * 6;
                            fn_800605F0(cell, &vbuf[1]);
                            vbuf[0] = (f32) * (s16*)((char*)state->heightBuf + hoff) -
                                (state->lastDepth / lbl_803E3F98) *
                                *(f32*)((char*)state->falloffBuf + foff);
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
    if (((GroundanimatorPlacement*)placement)->gateBit == -1)
    {
        allow = 1;
    }
    else
    {
        allow = GameBit_Get(((GroundanimatorPlacement*)placement)->gateBit) != 0 ? 1 : 0;
    }
    if ((state->flags & GROUNDANIMATOR_FLAG_DONE) == 0 && allow != 0)
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
            (*(code*)(*(int*)(*(int*)&((GameObject*)tricky)->anim.dll) + 0x28))(tricky, obj, 1, 1);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8;
    }
    objRenderFn_80041018(obj);
}
