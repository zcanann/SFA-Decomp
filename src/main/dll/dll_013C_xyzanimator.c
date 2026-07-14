/*
 * xyzanimator (DLL 0x13C) - drives a smooth offset animation of a map
 * block's vertices/edges along the X/Y/Z axes.
 *
 * On first update the object copies the source map block's vertex and
 * edge positions into a freshly mmAlloc'd buffer (fn_80194964), then on
 * each tick walks an offset vec toward the placement's per-axis targets
 * and writes the displaced positions back into the live block
 * (fn_80194C40). The placement animation mode selects the drive style:
 *   0/4 = one-shot toward target (sets the completion game bit),
 *   1   = looping (per-axis wrap), 2 = game-bit gated forward/reverse.
 * A game bit gates whether the animation runs.
 */
#include "main/audio/sfx.h"
#include "main/lightmap_api.h"
#include "main/pi_dolphin_api.h"
#include "main/game_object.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/mm.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/map_block.h"
#include "dolphin/os/OSCache.h"
#include "main/object_descriptor.h"
#include "main/track_dolphin_api.h"

typedef struct MapBlockHdr
{
    u16 start;
    u16 pad1[2];
    s16 posA;
    s16 posB;
} MapBlockHdr;

typedef struct VertexS16
{
    s16 x;
    s16 y;
    s16 z;
} VertexS16;

typedef struct EdgeVerts
{
    u8 pad[6];
    s16 v0x;
    s16 v0y;
    s16 v0z;
    s16 v1x;
    s16 v1y;
    s16 v1z;
} EdgeVerts;

#define XYZANIMATOR_OBJGROUP 0x51

/* .sdata2 float constants owned by this TU: lbl_803E4000 = 0.0 default;
 * lbl_803E4008 = per-axis offset scale; lbl_803E4018 = per-tick step multiplier;
 * lbl_803E4004 value unconfirmed. */
extern f32 lbl_803E4000;
extern f32 lbl_803E4004;
extern f32 lbl_803E4008;
extern const f32 lbl_803E4018;

extern int return0_80060B90(void* blk);
extern u32 mapBlockFn_80060678(int* block);
extern void* mapBlockFn_800606ec(int* block, int idx);

f32 objFn_801948c0(u8* obj, u8 coord)
{
    XyzAnimatorState* state;

    if (obj == NULL || (state = (XyzAnimatorState*)((GameObject*)obj)->extra, state == NULL))
    {
        return lbl_803E4000;
    }
    switch (coord)
    {
    case 1:
        return ((GameObject*)obj)->anim.localPosX + state->offsetX;
    case 2:
        return state->offsetX;
    case 3:
        return ((GameObject*)obj)->anim.localPosY + state->offsetY;
    case 4:
        return state->offsetY;
    case 5:
        return ((GameObject*)obj)->anim.localPosZ + state->offsetZ;
    case 6:
        return state->offsetZ;
    }
    return lbl_803E4000;
}

#pragma opt_lifetimes off
void fn_80194964(XyzAnimatorPlacement* setup, XyzAnimatorState* state, int block)
{
    int edgeOffset[1];
    int coordOffset[1];
    int triangleOffset[1];
    int blockIndex;
    int triangle;
    int blockEnd;
    u16* mapBlock;
    int blockLayer;
    int edge[1];
    int edgeIdx[1];
    VertexS16* vtx;

    edgeOffset[0] = 0;
    blockIndex = 0;
    coordOffset[0] = 0;
    triangleOffset[0] = coordOffset[0];
    for (; blockIndex < (int)(u32)((MapBlockData*)block)->polyGroupCount; blockIndex++)
    {
        mapBlock = mapBlockFn_800606ec((int*)block, blockIndex);
        blockLayer = mapBlockFn_80060678((int*)mapBlock);
        if ((int)setup->blockLayer == blockLayer)
        {
            *(s16*)(state->posABuffer + coordOffset[0]) = ((MapBlockHdr*)mapBlock)->posA;
            *(s16*)(state->posBBuffer + coordOffset[0]) = ((MapBlockHdr*)mapBlock)->posB;
            coordOffset[0] += 2;
            blockEnd = mapBlock[10];
            triangle = *mapBlock;
            edgeOffset[0] = triangleOffset[0];
            for (; triangle < blockEnd; triangle++)
            {
                int o6;
                int o12;
                mapBlock = fn_800606DC((int*)block, triangle);
                vtx = (VertexS16*)(((MapBlockData*)block)->vertices + (u32)*mapBlock * 6);
                *(s16*)(state->dataBuffer + edgeOffset[0]) = vtx->x;
                *(s16*)(state->dataBuffer + edgeOffset[0] + 2) = vtx->y;
                *(s16*)(state->dataBuffer + edgeOffset[0] + 4) = vtx->z;
                o6 = edgeOffset[0] + 6;
                vtx = (VertexS16*)(((MapBlockData*)block)->vertices + mapBlock[1] * 6);
                *(s16*)(state->dataBuffer + o6) = vtx->x;
                *(s16*)(state->dataBuffer + o6 + 2) = vtx->y;
                *(s16*)(state->dataBuffer + o6 + 4) = vtx->z;
                o12 = o6 + 6;
                vtx = (VertexS16*)(((MapBlockData*)block)->vertices + mapBlock[2] * 6);
                *(s16*)(state->dataBuffer + o12) = vtx->x;
                *(s16*)(state->dataBuffer + o12 + 2) = vtx->y;
                *(s16*)(state->dataBuffer + o12 + 4) = vtx->z;
                edgeOffset[0] += 0x12;
                triangleOffset[0] += 0x12;
            }
        }
    }
    edge[0] = 0;
    edgeIdx[0] = edge[0];
    for (; edgeIdx[0] < (int)(u32)((MapBlockData*)block)->edgeCount; edgeIdx[0]++)
    {
        blockIndex = (int)fn_800606FC((int*)block, edgeIdx[0]);
        *(s16*)(state->edgeV0xBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v0x;
        *(s16*)(state->edgeV1xBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v1x;
        *(s16*)(state->edgeV0yBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v0y;
        *(s16*)(state->edgeV1yBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v1y;
        *(s16*)(state->edgeV0zBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v0z;
        *(s16*)(state->edgeV1zBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v1z;
        edge[0] += 2;
    }
}
#pragma opt_lifetimes reset

#pragma opt_dead_assignments off
#pragma opt_loop_invariants off
void fn_80194C40(XyzAnimatorPlacement* def, XyzAnimatorState* state, int block)
{
    VertexS16* vtx;
    int vertexOffset[1];
    int vertexIndex;
    int blockIndex;
    int blockLayer;
    int edgeOffset;
    u16* mapBlock;
    f32 scale;
    int triangle;
    u16 blockEnd;
    int edgeIndex;
    int coordOffset[1];
    void* shader;

    blockIndex = 0;
    coordOffset[0] = 0;
    vertexOffset[0] = coordOffset[0];
    for (; blockIndex < (int)(u32)((MapBlockData*)block)->polyGroupCount; blockIndex++)
    {
        mapBlock = mapBlockFn_800606ec((int*)block, blockIndex);
        blockLayer = mapBlockFn_80060678((int*)mapBlock);
        if ((int)def->blockLayer == blockLayer)
        {
            ((MapBlockHdr*)mapBlock)->posA = (s16)(state->offsetY + (f32) * (s16*)(state->posABuffer + coordOffset[0]));
            ((MapBlockHdr*)mapBlock)->posB = (s16)(state->offsetY + (f32) * (s16*)(state->posBBuffer + coordOffset[0]));
            coordOffset[0] += 2;
            blockEnd = mapBlock[10];
            triangle = *mapBlock;
            vertexIndex = vertexOffset[0];
            scale = lbl_803E4008;
            for (; triangle < (int)(u32)blockEnd; triangle++)
            {
                mapBlock = fn_800606DC((int*)block, triangle);
                edgeOffset = vertexIndex;
                for (edgeIndex = 3; edgeIndex != 0; edgeIndex--)
                {
                    vtx = (VertexS16*)(((MapBlockData*)block)->vertices + (u32)*mapBlock * 6);
                    vtx->x = (s16)(scale * state->offsetX + (f32) * (s16*)(state->dataBuffer + edgeOffset));
                    vtx->y = (s16)(scale * state->offsetY + (f32) * (s16*)(state->dataBuffer + edgeOffset + 2));
                    vtx->z = (s16)(scale * state->offsetZ + (f32) * (s16*)(state->dataBuffer + edgeOffset + 4));
                    edgeOffset += 6;
                    vertexIndex += 6;
                    vertexOffset[0] += 6;
                    mapBlock++;
                }
            }
        }
    }
    DCStoreRange((void*)((MapBlockData*)block)->vertices, (u32)((MapBlockData*)block)->vertexCount * 6);
    edgeIndex = 0;
    edgeOffset = edgeIndex;
    for (; edgeIndex < (int)(u32)((MapBlockData*)block)->edgeCount; edgeIndex++)
    {
        vertexOffset[0] = (int)fn_800606FC((int*)block, edgeIndex);
        shader = fn_8006070C((MapBlockData*)block, *(u8*)(vertexOffset[0] + 0x13));
        shader = Shader_getLayer(shader, 0);
        if ((int)*(u8*)((int)shader + 5) == def->blockLayer)
        {
            scale = lbl_803E4008;
            ((EdgeVerts*)vertexOffset[0])->v0x =
                (s16)(scale * state->offsetX + (f32) * (s16*)(state->edgeV0xBuffer + edgeOffset));
            ((EdgeVerts*)vertexOffset[0])->v1x =
                (s16)(scale * state->offsetX + (f32) * (s16*)(state->edgeV1xBuffer + edgeOffset));
            ((EdgeVerts*)vertexOffset[0])->v0y =
                (s16)(scale * state->offsetY + (f32) * (s16*)(state->edgeV0yBuffer + edgeOffset));
            ((EdgeVerts*)vertexOffset[0])->v1y =
                (s16)(scale * state->offsetY + (f32) * (s16*)(state->edgeV1yBuffer + edgeOffset));
            ((EdgeVerts*)vertexOffset[0])->v0z =
                (s16)(scale * state->offsetZ + (f32) * (s16*)(state->edgeV0zBuffer + edgeOffset));
            ((EdgeVerts*)vertexOffset[0])->v1z =
                (s16)(scale * state->offsetZ + (f32) * (s16*)(state->edgeV1zBuffer + edgeOffset));
        }
        edgeOffset += 2;
    }
    *(int*)block = return0_80060B90((void*)block);
}
#pragma opt_loop_invariants reset
#pragma opt_dead_assignments reset

int XyzAnimator_getExtraSize(void)
{
    return 0x50;
}

void XyzAnimator_free(GameObject* obj, int flag)
{
    int block;
    XyzAnimatorState* state;
    XyzAnimatorPlacement* setup;
    f32 zero;

    state = (XyzAnimatorState*)(obj)->extra;
    setup = *(XyzAnimatorPlacement**)&(obj)->anim.placementData;
    zero = lbl_803E4000;
    state->offsetX = zero;
    state->offsetY = zero;
    state->offsetZ = zero;
    if (flag == 0)
    {
        block = objPosToMapBlockIdx((double)(obj)->anim.localPosX, (double)(obj)->anim.localPosY,
                                    (double)(obj)->anim.localPosZ);
        block = (int)mapGetBlock(block);
        if (((void*)block != NULL) && (state->vertexCount != 0))
        {
            fn_80194C40(setup, state, block);
        }
    }
    if (*(void**)&state->dataBuffer != NULL)
    {
        mm_free(*(void**)&state->dataBuffer);
    }
    ObjGroup_RemoveObject((int)obj, XYZANIMATOR_OBJGROUP);
}

void XyzAnimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4004);
}

void XyzAnimator_update(GameObject* obj)
{
    u8* setup = *(u8**)&obj->anim.placementData;
    u8* state = obj->extra;
    int block;
    u8* row;
    int i;
    int done;
    int alloc, stride;
    int t;

    block = (int)mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
    if ((u32)block == 0)
    {
        ((XyzAnimatorState*)state)->loopCount = 0;
        goto no_update;
    }
    if ((((MapBlockData*)block)->flags4 & 8) == 0)
    {
        goto no_update;
    }
    if (((XyzAnimatorState*)state)->vertexCount == 0)
    {
        for (i = 0; i < ((MapBlockData*)block)->polyGroupCount; i++)
        {
            row = mapBlockFn_800606ec((int*)block, i);
            t = mapBlockFn_80060678((int*)row);
            if (((XyzAnimatorPlacement*)setup)->blockLayer == t)
            {
                ((XyzAnimatorState*)state)->rowCount++;
                ((XyzAnimatorState*)state)->vertexCount += (*(u16*)(row + 0x14) - *(u16*)(row + 0));
            }
        }
        if (((XyzAnimatorState*)state)->vertexCount == 0)
        {
            goto no_update;
        }
        ((XyzAnimatorState*)state)->vertexCount *= 3;
        if (((XyzAnimatorPlacement*)setup)->triggerGameBit == -1)
        {
            ((XyzAnimatorState*)state)->gameBitValue = 1;
        }
        else
        {
            ((XyzAnimatorState*)state)->gameBitValue = mainGetBit(((XyzAnimatorPlacement*)setup)->triggerGameBit);
        }
        ((XyzAnimatorState*)state)->unk8 = ((MapBlockData*)block)->edgeCount;
        ((XyzAnimatorState*)state)->offsetX = (f32)((XyzAnimatorPlacement*)setup)->startX;
        ((XyzAnimatorState*)state)->offsetY = (f32)((XyzAnimatorPlacement*)setup)->startY;
        ((XyzAnimatorState*)state)->offsetZ = (f32)((XyzAnimatorPlacement*)setup)->startZ;
        if (((XyzAnimatorPlacement*)setup)->doneGameBit != -1 &&
            mainGetBit(((XyzAnimatorPlacement*)setup)->doneGameBit) != 0)
        {
            ((XyzAnimatorState*)state)->offsetX = (f32)((XyzAnimatorPlacement*)setup)->targetX;
            ((XyzAnimatorState*)state)->offsetY = (f32)((XyzAnimatorPlacement*)setup)->targetY;
            ((XyzAnimatorState*)state)->offsetZ = (f32)((XyzAnimatorPlacement*)setup)->targetZ;
            ((XyzAnimatorState*)state)->gameBitValue = 1;
        }
        t = ((XyzAnimatorState*)state)->vertexCount * 6 + ((XyzAnimatorState*)state)->rowCount * 0xc;
        t = t + ((XyzAnimatorState*)state)->unk8 * 0xc;
        alloc = (int)mmAlloc(t, 5, 0);
        ((XyzAnimatorState*)state)->dataBuffer = alloc;
        stride = ((XyzAnimatorState*)state)->rowCount * 2;
        alloc = alloc + ((XyzAnimatorState*)state)->vertexCount * 6;
        ((XyzAnimatorState*)state)->unk18 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk1C = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->posABuffer = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->posBBuffer = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk20 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk24 = alloc;
        alloc = alloc + stride;
        stride = ((XyzAnimatorState*)state)->unk8 * 2;
        ((XyzAnimatorState*)state)->edgeV0xBuffer = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->edgeV1xBuffer = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->edgeV0yBuffer = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->edgeV1yBuffer = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->edgeV0zBuffer = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->edgeV1zBuffer = alloc;
        fn_80194964((XyzAnimatorPlacement*)setup, (XyzAnimatorState*)state, block);
        if (((XyzAnimatorPlacement*)setup)->mode != 4)
        {
            fn_80194C40((XyzAnimatorPlacement*)setup, (XyzAnimatorState*)state, block);
            ((MapBlockData*)block)->flags4 = ((MapBlockData*)block)->flags4 ^ 1;
            fn_80194C40((XyzAnimatorPlacement*)setup, (XyzAnimatorState*)state, block);
            ((MapBlockData*)block)->flags4 = ((MapBlockData*)block)->flags4 ^ 1;
        }
    }
    if (((XyzAnimatorPlacement*)setup)->mode == 2)
    {
        t = mainGetBit(((XyzAnimatorPlacement*)setup)->triggerGameBit);
        if (((XyzAnimatorState*)state)->gameBitValue != t)
        {
            ((XyzAnimatorState*)state)->gameBitValue = t;
            if (t == 0)
            {
                if (((XyzAnimatorPlacement*)setup)->doneGameBit > -1)
                {
                    mainSetBits(((XyzAnimatorPlacement*)setup)->doneGameBit, 0);
                }
            }
            if (((XyzAnimatorState*)state)->loopCount > 2)
            {
                ((XyzAnimatorState*)state)->loopCount = 0;
            }
        }
        if (((XyzAnimatorState*)state)->loopCount > 2)
        {
            goto no_update;
        }
        if (((XyzAnimatorState*)state)->loopSfxId != 0)
        {
            Sfx_KeepAliveLoopedObjectSound((u32)obj, ((XyzAnimatorState*)state)->loopSfxId);
        }
    }
    else
    {
        if (((XyzAnimatorState*)state)->loopCount > 2)
        {
            goto no_update;
        }
        if (((XyzAnimatorState*)state)->gameBitValue == 0)
        {
            ((XyzAnimatorState*)state)->gameBitValue = mainGetBit(((XyzAnimatorPlacement*)setup)->triggerGameBit);
            if (((XyzAnimatorState*)state)->gameBitValue == 0)
            {
                goto no_update;
            }
        }
    }
    switch (((XyzAnimatorPlacement*)setup)->mode)
    {
    case 0:
    case 4:
        done = 0;
        if (((XyzAnimatorPlacement*)setup)->startX > ((XyzAnimatorPlacement*)setup)->targetX)
        {
            ((XyzAnimatorState*)state)->offsetX =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedX * timeDelta) -
                  ((XyzAnimatorState*)state)->offsetX);
            if (((XyzAnimatorState*)state)->offsetX <= (f32)((XyzAnimatorPlacement*)setup)->targetX)
            {
                ((XyzAnimatorState*)state)->offsetX = (f32)((XyzAnimatorPlacement*)setup)->targetX;
                done = 1;
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->offsetX =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedX * timeDelta) +
                ((XyzAnimatorState*)state)->offsetX;
            if (((XyzAnimatorState*)state)->offsetX >= (f32)((XyzAnimatorPlacement*)setup)->targetX)
            {
                ((XyzAnimatorState*)state)->offsetX = (f32)((XyzAnimatorPlacement*)setup)->targetX;
                done = 1;
            }
        }
        if (((XyzAnimatorPlacement*)setup)->startY > ((XyzAnimatorPlacement*)setup)->targetY)
        {
            ((XyzAnimatorState*)state)->offsetY =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedY * timeDelta) -
                  ((XyzAnimatorState*)state)->offsetY);
            if (((XyzAnimatorState*)state)->offsetY <= (f32)((XyzAnimatorPlacement*)setup)->targetY)
            {
                ((XyzAnimatorState*)state)->offsetY = (f32)((XyzAnimatorPlacement*)setup)->targetY;
                done += 1;
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->offsetY =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedY * timeDelta) +
                ((XyzAnimatorState*)state)->offsetY;
            if (((XyzAnimatorState*)state)->offsetY >= (f32)((XyzAnimatorPlacement*)setup)->targetY)
            {
                ((XyzAnimatorState*)state)->offsetY = (f32)((XyzAnimatorPlacement*)setup)->targetY;
                done += 1;
            }
        }
        if (((XyzAnimatorPlacement*)setup)->startZ > ((XyzAnimatorPlacement*)setup)->targetZ)
        {
            ((XyzAnimatorState*)state)->offsetZ =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedZ * timeDelta) -
                  ((XyzAnimatorState*)state)->offsetZ);
            if (((XyzAnimatorState*)state)->offsetZ <= (f32)((XyzAnimatorPlacement*)setup)->targetZ)
            {
                ((XyzAnimatorState*)state)->offsetZ = (f32)((XyzAnimatorPlacement*)setup)->targetZ;
                done += 1;
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->offsetZ =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedZ * timeDelta) +
                ((XyzAnimatorState*)state)->offsetZ;
            if (((XyzAnimatorState*)state)->offsetZ >= (f32)((XyzAnimatorPlacement*)setup)->targetZ)
            {
                ((XyzAnimatorState*)state)->offsetZ = (f32)((XyzAnimatorPlacement*)setup)->targetZ;
                done += 1;
            }
        }
        if (done == 3)
        {
            if (((XyzAnimatorPlacement*)setup)->doneGameBit != -1)
            {
                mainSetBits(((XyzAnimatorPlacement*)setup)->doneGameBit, 1);
            }
            ((XyzAnimatorState*)state)->loopCount += 1;
        }
        break;
    case 1:
        if (((XyzAnimatorPlacement*)setup)->startX > ((XyzAnimatorPlacement*)setup)->targetX)
        {
            ((XyzAnimatorState*)state)->offsetX =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedX * timeDelta) -
                  ((XyzAnimatorState*)state)->offsetX);
            if (((XyzAnimatorState*)state)->offsetX < (f32)((XyzAnimatorPlacement*)setup)->targetX)
            {
                ((XyzAnimatorState*)state)->offsetX =
                    (f32)(((XyzAnimatorPlacement*)setup)->startX -
                          (int)((f32)((XyzAnimatorPlacement*)setup)->targetX - ((XyzAnimatorState*)state)->offsetX));
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->offsetX =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedX * timeDelta) +
                ((XyzAnimatorState*)state)->offsetX;
            if (((XyzAnimatorState*)state)->offsetX > (f32)((XyzAnimatorPlacement*)setup)->startX)
            {
                ((XyzAnimatorState*)state)->offsetX =
                    (f32)(((XyzAnimatorPlacement*)setup)->targetX +
                          (int)(((XyzAnimatorState*)state)->offsetX - (f32)((XyzAnimatorPlacement*)setup)->targetX));
            }
        }
        if (((XyzAnimatorPlacement*)setup)->startY > ((XyzAnimatorPlacement*)setup)->targetY)
        {
            ((XyzAnimatorState*)state)->offsetY =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedY * timeDelta) -
                  ((XyzAnimatorState*)state)->offsetY);
            if (((XyzAnimatorState*)state)->offsetY < (f32)((XyzAnimatorPlacement*)setup)->targetY)
            {
                ((XyzAnimatorState*)state)->offsetY =
                    -(lbl_803E4018 * (f32)(int)((f32)((XyzAnimatorPlacement*)setup)->targetY -
                                                ((XyzAnimatorState*)state)->offsetY) -
                      (f32)((XyzAnimatorPlacement*)setup)->startY);
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->offsetY =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedY * timeDelta) +
                ((XyzAnimatorState*)state)->offsetY;
            if (((XyzAnimatorState*)state)->offsetY > (f32)((XyzAnimatorPlacement*)setup)->startY)
            {
                ((XyzAnimatorState*)state)->offsetY =
                    (f32)(((XyzAnimatorPlacement*)setup)->targetY +
                          (int)(((XyzAnimatorState*)state)->offsetY - (f32)((XyzAnimatorPlacement*)setup)->targetY));
            }
        }
        if (((XyzAnimatorPlacement*)setup)->startZ > ((XyzAnimatorPlacement*)setup)->targetZ)
        {
            ((XyzAnimatorState*)state)->offsetZ =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedZ * timeDelta) -
                  ((XyzAnimatorState*)state)->offsetZ);
            if (((XyzAnimatorState*)state)->offsetZ < (f32)((XyzAnimatorPlacement*)setup)->targetZ)
            {
                ((XyzAnimatorState*)state)->offsetZ =
                    (f32)(((XyzAnimatorPlacement*)setup)->startZ -
                          (int)((f32)((XyzAnimatorPlacement*)setup)->targetZ - ((XyzAnimatorState*)state)->offsetZ));
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->offsetZ =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedZ * timeDelta) +
                ((XyzAnimatorState*)state)->offsetZ;
            if (((XyzAnimatorState*)state)->offsetZ > (f32)((XyzAnimatorPlacement*)setup)->startZ)
            {
                ((XyzAnimatorState*)state)->offsetZ =
                    (f32)(((XyzAnimatorPlacement*)setup)->targetZ +
                          (int)(((XyzAnimatorState*)state)->offsetZ - (f32)((XyzAnimatorPlacement*)setup)->targetZ));
            }
        }
        break;
    case 2:
        done = 0;
        if (((XyzAnimatorState*)state)->gameBitValue != 0)
        {
            if (((XyzAnimatorPlacement*)setup)->startX > ((XyzAnimatorPlacement*)setup)->targetX)
            {
                ((XyzAnimatorState*)state)->offsetX =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedX * timeDelta) -
                      ((XyzAnimatorState*)state)->offsetX);
                if (((XyzAnimatorState*)state)->offsetX <= (f32)((XyzAnimatorPlacement*)setup)->targetX)
                {
                    ((XyzAnimatorState*)state)->offsetX = (f32)((XyzAnimatorPlacement*)setup)->targetX;
                    done = 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->offsetX =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedX * timeDelta) +
                    ((XyzAnimatorState*)state)->offsetX;
                if (((XyzAnimatorState*)state)->offsetX >= (f32)((XyzAnimatorPlacement*)setup)->targetX)
                {
                    ((XyzAnimatorState*)state)->offsetX = (f32)((XyzAnimatorPlacement*)setup)->targetX;
                    done = 1;
                }
            }
            if (((XyzAnimatorPlacement*)setup)->startY > ((XyzAnimatorPlacement*)setup)->targetY)
            {
                ((XyzAnimatorState*)state)->offsetY =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedY * timeDelta) -
                      ((XyzAnimatorState*)state)->offsetY);
                if (((XyzAnimatorState*)state)->offsetY <= (f32)((XyzAnimatorPlacement*)setup)->targetY)
                {
                    ((XyzAnimatorState*)state)->offsetY = (f32)((XyzAnimatorPlacement*)setup)->targetY;
                    done += 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->offsetY =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedY * timeDelta) +
                    ((XyzAnimatorState*)state)->offsetY;
                if (((XyzAnimatorState*)state)->offsetY >= (f32)((XyzAnimatorPlacement*)setup)->targetY)
                {
                    ((XyzAnimatorState*)state)->offsetY = (f32)((XyzAnimatorPlacement*)setup)->targetY;
                    done += 1;
                }
            }
            if (((XyzAnimatorPlacement*)setup)->startZ > ((XyzAnimatorPlacement*)setup)->targetZ)
            {
                ((XyzAnimatorState*)state)->offsetZ =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedZ * timeDelta) -
                      ((XyzAnimatorState*)state)->offsetZ);
                if (((XyzAnimatorState*)state)->offsetZ <= (f32)((XyzAnimatorPlacement*)setup)->targetZ)
                {
                    ((XyzAnimatorState*)state)->offsetZ = (f32)((XyzAnimatorPlacement*)setup)->targetZ;
                    done += 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->offsetZ =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedZ * timeDelta) +
                    ((XyzAnimatorState*)state)->offsetZ;
                if (((XyzAnimatorState*)state)->offsetZ >= (f32)((XyzAnimatorPlacement*)setup)->targetZ)
                {
                    ((XyzAnimatorState*)state)->offsetZ = (f32)((XyzAnimatorPlacement*)setup)->targetZ;
                    done += 1;
                }
            }
            if (done == 3)
            {
                if (((XyzAnimatorPlacement*)setup)->doneGameBit != -1)
                {
                    mainSetBits(((XyzAnimatorPlacement*)setup)->doneGameBit, 1);
                }
                ((XyzAnimatorState*)state)->loopCount += 1;
            }
        }
        else
        {
            if (((XyzAnimatorPlacement*)setup)->startX > ((XyzAnimatorPlacement*)setup)->targetX)
            {
                ((XyzAnimatorState*)state)->offsetX =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedX * timeDelta) +
                    ((XyzAnimatorState*)state)->offsetX;
                if (((XyzAnimatorState*)state)->offsetX >= (f32)((XyzAnimatorPlacement*)setup)->startX)
                {
                    ((XyzAnimatorState*)state)->offsetX = (f32)((XyzAnimatorPlacement*)setup)->startX;
                    done = 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->offsetX =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedX * timeDelta) -
                      ((XyzAnimatorState*)state)->offsetX);
                if (((XyzAnimatorState*)state)->offsetX <= (f32)((XyzAnimatorPlacement*)setup)->startX)
                {
                    ((XyzAnimatorState*)state)->offsetX = (f32)((XyzAnimatorPlacement*)setup)->startX;
                    done = 1;
                }
            }
            if (((XyzAnimatorPlacement*)setup)->startY > ((XyzAnimatorPlacement*)setup)->targetY)
            {
                ((XyzAnimatorState*)state)->offsetY =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedY * timeDelta) +
                    ((XyzAnimatorState*)state)->offsetY;
                if (((XyzAnimatorState*)state)->offsetY >= (f32)((XyzAnimatorPlacement*)setup)->startY)
                {
                    ((XyzAnimatorState*)state)->offsetY = (f32)((XyzAnimatorPlacement*)setup)->startY;
                    done += 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->offsetY =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedY * timeDelta) -
                      ((XyzAnimatorState*)state)->offsetY);
                if (((XyzAnimatorState*)state)->offsetY <= (f32)((XyzAnimatorPlacement*)setup)->startY)
                {
                    ((XyzAnimatorState*)state)->offsetY = (f32)((XyzAnimatorPlacement*)setup)->startY;
                    done += 1;
                }
            }
            if (((XyzAnimatorPlacement*)setup)->startZ > ((XyzAnimatorPlacement*)setup)->targetZ)
            {
                ((XyzAnimatorState*)state)->offsetZ =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedZ * timeDelta) +
                    ((XyzAnimatorState*)state)->offsetZ;
                if (((XyzAnimatorState*)state)->offsetZ >= (f32)((XyzAnimatorPlacement*)setup)->startZ)
                {
                    ((XyzAnimatorState*)state)->offsetZ = (f32)((XyzAnimatorPlacement*)setup)->startZ;
                    done += 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->offsetZ =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->speedZ * timeDelta) -
                      ((XyzAnimatorState*)state)->offsetZ);
                if (((XyzAnimatorState*)state)->offsetZ <= (f32)((XyzAnimatorPlacement*)setup)->startZ)
                {
                    ((XyzAnimatorState*)state)->offsetZ = (f32)((XyzAnimatorPlacement*)setup)->startZ;
                    done += 1;
                }
            }
            if (done == 3)
            {
                ((XyzAnimatorState*)state)->loopCount += 1;
            }
        }
        break;
    }
    fn_80194C40((XyzAnimatorPlacement*)setup, (XyzAnimatorState*)state, block);
no_update:
    return;
}

void XyzAnimator_init(GameObject* obj)
{
    int inner = *(int*)&(obj)->extra;
    int id;
    ObjGroup_AddObject((int)obj, XYZANIMATOR_OBJGROUP);
    id = *(int*)(*(int*)&(obj)->anim.placementData + 0x14);
    switch (id)
    {
    case 0x46406:
    case 0x4BAB1:
        ((XyzAnimatorState*)inner)->loopSfxId = 0x7d;
        break;
    case 0x49275:
    case 0x49CB7:
    case 0x4C797:
        ((XyzAnimatorState*)inner)->loopSfxId = 0x4b7;
        break;
    }
}

ObjectDescriptor gXYZAnimatorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)XyzAnimator_init,
    (ObjectDescriptorCallback)XyzAnimator_update,
    0,
    (ObjectDescriptorCallback)XyzAnimator_render,
    (ObjectDescriptorCallback)XyzAnimator_free,
    0,
    XyzAnimator_getExtraSize,
};
