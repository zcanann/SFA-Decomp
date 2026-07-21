/*
 * xyzanimator (DLL 0x13C) - drives a smooth offset animation of a map
 * block's vertices/edges along the X/Y/Z axes.
 *
 * On first update the object copies the source map block's vertex and
 * edge positions into a freshly mmAlloc'd buffer (XyzAnimator_captureGeometry), then on
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
#include "main/object_render.h"
#include "main/map_block.h"
#include "dolphin/os/OSCache.h"
#include "main/object_descriptor.h"
#include "main/track_dolphin_api.h"
#include "main/track_dolphin_sky_api.h"
#include "main/dll/xyzanimator_api.h"

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


f32 objFn_801948c0(GameObject* obj, u8 coord)
{
    XyzAnimatorState* state;

    if (obj == NULL || (state = (XyzAnimatorState*)obj->extra, state == NULL))
    {
        return 0.0f;
    }
    switch (coord)
    {
    case 1:
        return obj->anim.localPosX + state->offsetX;
    case 2:
        return state->offsetX;
    case 3:
        return obj->anim.localPosY + state->offsetY;
    case 4:
        return state->offsetY;
    case 5:
        return obj->anim.localPosZ + state->offsetZ;
    case 6:
        return state->offsetZ;
    }
    return 0.0f;
}

void XyzAnimator_captureGeometry(XyzAnimatorPlacement* setup, XyzAnimatorState* state, int block)
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
    MapBlockData* mb = (MapBlockData*)block;

    edgeOffset[0] = 0;
    edge[0] = 0;
    blockIndex = 0;
    coordOffset[0] = 0;
    triangleOffset[0] = coordOffset[0];
    for (; blockIndex < (int)(u32)mb->polyGroupCount; blockIndex++)
    {
        mapBlock = mapBlockGetPolygonGroup((void*)block, blockIndex);
        blockLayer = mapBlockGetPolygonGroupType(mapBlock);
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
                mapBlock = mapBlockGetPolygon((int*)block, triangle);
                vtx = (VertexS16*)(mb->vertices + (u32)*mapBlock * 6);
                *(s16*)(state->dataBuffer + edgeOffset[0]) = vtx->x;
                *(s16*)(state->dataBuffer + edgeOffset[0] + 2) = vtx->y;
                *(s16*)(state->dataBuffer + edgeOffset[0] + 4) = vtx->z;
                o6 = edgeOffset[0] + 6;
                vtx = (VertexS16*)(mb->vertices + mapBlock[1] * 6);
                *(s16*)(state->dataBuffer + o6) = vtx->x;
                *(s16*)(state->dataBuffer + o6 + 2) = vtx->y;
                *(s16*)(state->dataBuffer + o6 + 4) = vtx->z;
                o12 = o6 + 6;
                vtx = (VertexS16*)(mb->vertices + mapBlock[2] * 6);
                *(s16*)(state->dataBuffer + o12) = vtx->x;
                *(s16*)(state->dataBuffer + o12 + 2) = vtx->y;
                *(s16*)(state->dataBuffer + o12 + 4) = vtx->z;
                edgeOffset[0] += 0x12;
                triangleOffset[0] += 0x12;
            }
        }
    }
    edgeIdx[0] = 0;
    edge[0] = edgeIdx[0];
    for (; edgeIdx[0] < (int)(u32)mb->edgeCount; edgeIdx[0]++)
    {
        blockIndex = (int)mapBlockGetEdge((int*)block, edgeIdx[0]);
        *(s16*)(state->edgeV0xBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v0x;
        *(s16*)(state->edgeV1xBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v1x;
        *(s16*)(state->edgeV0yBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v0y;
        *(s16*)(state->edgeV1yBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v1y;
        *(s16*)(state->edgeV0zBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v0z;
        *(s16*)(state->edgeV1zBuffer + edge[0]) = ((EdgeVerts*)blockIndex)->v1z;
        edge[0] += 2;
    }
}

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
    setup = (XyzAnimatorPlacement*)obj->anim.placementData;
    zero = 0.0f;
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
    if ((void*)state->dataBuffer != NULL)
    {
        mm_free((void*)state->dataBuffer);
    }
    ObjGroup_RemoveObject((int)obj, XYZANIMATOR_OBJGROUP);
}

void XyzAnimator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void fn_80194C40(XyzAnimatorPlacement* def, XyzAnimatorState* state, int block)
{
    VertexS16* vtx;
    MapBlockData* mb = (MapBlockData*)block;
    int vertexOffset[1];
    int vertexIndex;
    int blockIndex;
    int blockLayer;
    int edgeOffset;
    u16* mapBlock;
    f32 scale;
    int triangle;
    int blockEnd;
    int edgeIndex;
    int coordOffset[1];
    void* shader;

    blockIndex = 0;
    coordOffset[0] = 0;
    vertexOffset[0] = coordOffset[0];
    for (; blockIndex < (int)(u32)mb->polyGroupCount; blockIndex++)
    {
        mapBlock = mapBlockGetPolygonGroup((void*)block, blockIndex);
        blockLayer = mapBlockGetPolygonGroupType(mapBlock);
        if ((int)def->blockLayer == blockLayer)
        {
            ((MapBlockHdr*)mapBlock)->posA = (s16)(state->offsetY + (f32) * (s16*)(state->posABuffer + coordOffset[0]));
            ((MapBlockHdr*)mapBlock)->posB = (s16)(state->offsetY + (f32) * (s16*)(state->posBBuffer + coordOffset[0]));
            coordOffset[0] += 2;
            blockEnd = mapBlock[10];
            triangle = *mapBlock;
            vertexIndex = vertexOffset[0];
            scale = 8.0f;
            for (; triangle < blockEnd; triangle++)
            {
                mapBlock = mapBlockGetPolygon((int*)block, triangle);
                edgeOffset = vertexIndex;
                for (edgeIndex = 3; edgeIndex != 0; edgeIndex--)
                {
                    vtx = (VertexS16*)(mb->vertices + (u32)*mapBlock * 6);
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
    DCStoreRange((void*)mb->vertices, (u32)mb->vertexCount * 6);
    edgeIndex = 0;
    edgeOffset = edgeIndex;
    for (; edgeIndex < (int)(u32)mb->edgeCount; edgeIndex++)
    {
        vertexOffset[0] = (int)mapBlockGetEdge((int*)block, edgeIndex);
        shader = mapBlockGetShader((MapBlockData*)block, *(u8*)(vertexOffset[0] + 0x13));
        shader = Shader_getLayer(shader, 0);
        if ((int)*(u8*)((int)shader + 5) == def->blockLayer)
        {
            scale = 8.0f;
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

void XyzAnimator_update(GameObject* obj)
{
    XyzAnimatorPlacement* setup = (XyzAnimatorPlacement*)obj->anim.placementData;
    XyzAnimatorState* state = (XyzAnimatorState*)obj->extra;
    int block;
    u8* row;
    int i;
    int done;
    int alloc, stride;
    int t;

    block = (int)mapGetBlock(objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ));
    if ((u32)block == 0)
    {
        state->loopCount = 0;
        return;
    }
    if ((((MapBlockData*)block)->flags4 & 8) == 0)
    {
        return;
    }
    if (state->vertexCount == 0)
    {
        for (i = 0; i < ((MapBlockData*)block)->polyGroupCount; i++)
        {
            row = mapBlockGetPolygonGroup((void*)block, i);
            t = mapBlockGetPolygonGroupType(row);
            if (setup->blockLayer == t)
            {
                state->rowCount++;
                state->vertexCount += (*(u16*)(row + 0x14) - *(u16*)(row + 0));
            }
        }
        if (state->vertexCount == 0)
        {
            return;
        }
        state->vertexCount *= 3;
        if (setup->triggerGameBit == -1)
        {
            state->gameBitValue = 1;
        }
        else
        {
            state->gameBitValue = mainGetBit(setup->triggerGameBit);
        }
        state->edgeCount = ((MapBlockData*)block)->edgeCount;
        state->offsetX = (f32)setup->startX;
        state->offsetY = (f32)setup->startY;
        state->offsetZ = (f32)setup->startZ;
        if (setup->doneGameBit != -1 &&
            mainGetBit(setup->doneGameBit) != 0)
        {
            state->offsetX = (f32)setup->targetX;
            state->offsetY = (f32)setup->targetY;
            state->offsetZ = (f32)setup->targetZ;
            state->gameBitValue = 1;
        }
        t = state->vertexCount * 6 + state->rowCount * 0xc;
        t = t + state->edgeCount * 0xc;
        alloc = (int)mmAlloc(t, 5, 0);
        state->dataBuffer = alloc;
        stride = state->rowCount * 2;
        alloc = alloc + state->vertexCount * 6;
        state->unk18 = alloc;
        alloc = alloc + stride;
        state->unk1C = alloc;
        alloc = alloc + stride;
        state->posABuffer = alloc;
        alloc = alloc + stride;
        state->posBBuffer = alloc;
        alloc = alloc + stride;
        state->unk20 = alloc;
        alloc = alloc + stride;
        state->unk24 = alloc;
        alloc = alloc + stride;
        stride = state->edgeCount * 2;
        state->edgeV0xBuffer = alloc;
        alloc = alloc + stride;
        state->edgeV1xBuffer = alloc;
        alloc = alloc + stride;
        state->edgeV0yBuffer = alloc;
        alloc = alloc + stride;
        state->edgeV1yBuffer = alloc;
        alloc = alloc + stride;
        state->edgeV0zBuffer = alloc;
        alloc = alloc + stride;
        state->edgeV1zBuffer = alloc;
        XyzAnimator_captureGeometry(setup, state, block);
        if (setup->mode != 4)
        {
            fn_80194C40(setup, state, block);
            ((MapBlockData*)block)->flags4 = ((MapBlockData*)block)->flags4 ^ 1;
            fn_80194C40(setup, state, block);
            ((MapBlockData*)block)->flags4 = ((MapBlockData*)block)->flags4 ^ 1;
        }
    }
    if (setup->mode == 2)
    {
        t = mainGetBit(setup->triggerGameBit);
        if (state->gameBitValue != t)
        {
            state->gameBitValue = t;
            if (t == 0)
            {
                if (setup->doneGameBit > -1)
                {
                    mainSetBits(setup->doneGameBit, 0);
                }
            }
            if (state->loopCount > 2)
            {
                state->loopCount = 0;
            }
        }
        if (state->loopCount > 2)
        {
            return;
        }
        if (state->loopSfxId != 0)
        {
            Sfx_KeepAliveLoopedObjectSound((u32)obj, state->loopSfxId);
        }
    }
    else
    {
        if (state->loopCount > 2)
        {
            return;
        }
        if (state->gameBitValue == 0)
        {
            state->gameBitValue = mainGetBit(setup->triggerGameBit);
            if (state->gameBitValue == 0)
            {
                return;
            }
        }
    }
    switch (setup->mode)
    {
    case 0:
    case 4:
        done = 0;
        if (setup->startX > setup->targetX)
        {
            state->offsetX =
                -(0.1f * ((f32)(int)setup->speedX * timeDelta) -
                  state->offsetX);
            if (state->offsetX <= (f32)setup->targetX)
            {
                state->offsetX = (f32)setup->targetX;
                done = 1;
            }
        }
        else
        {
            state->offsetX =
                0.1f * ((f32)(int)setup->speedX * timeDelta) +
                state->offsetX;
            if (state->offsetX >= (f32)setup->targetX)
            {
                state->offsetX = (f32)setup->targetX;
                done = 1;
            }
        }
        if (setup->startY > setup->targetY)
        {
            state->offsetY =
                -(0.1f * ((f32)(int)setup->speedY * timeDelta) -
                  state->offsetY);
            if (state->offsetY <= (f32)setup->targetY)
            {
                state->offsetY = (f32)setup->targetY;
                done += 1;
            }
        }
        else
        {
            state->offsetY =
                0.1f * ((f32)(int)setup->speedY * timeDelta) +
                state->offsetY;
            if (state->offsetY >= (f32)setup->targetY)
            {
                state->offsetY = (f32)setup->targetY;
                done += 1;
            }
        }
        if (setup->startZ > setup->targetZ)
        {
            state->offsetZ =
                -(0.1f * ((f32)(int)setup->speedZ * timeDelta) -
                  state->offsetZ);
            if (state->offsetZ <= (f32)setup->targetZ)
            {
                state->offsetZ = (f32)setup->targetZ;
                done += 1;
            }
        }
        else
        {
            state->offsetZ =
                0.1f * ((f32)(int)setup->speedZ * timeDelta) +
                state->offsetZ;
            if (state->offsetZ >= (f32)setup->targetZ)
            {
                state->offsetZ = (f32)setup->targetZ;
                done += 1;
            }
        }
        if (done == 3)
        {
            if (setup->doneGameBit != -1)
            {
                mainSetBits(setup->doneGameBit, 1);
            }
            state->loopCount += 1;
        }
        break;
    case 1:
        if (setup->startX > setup->targetX)
        {
            state->offsetX =
                -(0.1f * ((f32)(int)setup->speedX * timeDelta) -
                  state->offsetX);
            if (state->offsetX < (f32)setup->targetX)
            {
                state->offsetX =
                    (f32)(setup->startX -
                          (int)((f32)setup->targetX - state->offsetX));
            }
        }
        else
        {
            state->offsetX =
                0.1f * ((f32)(int)setup->speedX * timeDelta) +
                state->offsetX;
            if (state->offsetX > (f32)setup->startX)
            {
                state->offsetX =
                    (f32)(setup->targetX +
                          (int)(state->offsetX - (f32)setup->targetX));
            }
        }
        if (setup->startY > setup->targetY)
        {
            state->offsetY =
                -(0.1f * ((f32)(int)setup->speedY * timeDelta) -
                  state->offsetY);
            if (state->offsetY < (f32)setup->targetY)
            {
                state->offsetY =
                    -(0.1f * (f32)(int)((f32)setup->targetY -
                                                state->offsetY) -
                      (f32)setup->startY);
            }
        }
        else
        {
            state->offsetY =
                0.1f * ((f32)(int)setup->speedY * timeDelta) +
                state->offsetY;
            if (state->offsetY > (f32)setup->startY)
            {
                state->offsetY =
                    (f32)(setup->targetY +
                          (int)(state->offsetY - (f32)setup->targetY));
            }
        }
        if (setup->startZ > setup->targetZ)
        {
            state->offsetZ =
                -(0.1f * ((f32)(int)setup->speedZ * timeDelta) -
                  state->offsetZ);
            if (state->offsetZ < (f32)setup->targetZ)
            {
                state->offsetZ =
                    (f32)(setup->startZ -
                          (int)((f32)setup->targetZ - state->offsetZ));
            }
        }
        else
        {
            state->offsetZ =
                0.1f * ((f32)(int)setup->speedZ * timeDelta) +
                state->offsetZ;
            if (state->offsetZ > (f32)setup->startZ)
            {
                state->offsetZ =
                    (f32)(setup->targetZ +
                          (int)(state->offsetZ - (f32)setup->targetZ));
            }
        }
        break;
    case 2:
        done = 0;
        if (state->gameBitValue != 0)
        {
            if (setup->startX > setup->targetX)
            {
                state->offsetX =
                    -(0.1f * ((f32)(int)setup->speedX * timeDelta) -
                      state->offsetX);
                if (state->offsetX <= (f32)setup->targetX)
                {
                    state->offsetX = (f32)setup->targetX;
                    done = 1;
                }
            }
            else
            {
                state->offsetX =
                    0.1f * ((f32)(int)setup->speedX * timeDelta) +
                    state->offsetX;
                if (state->offsetX >= (f32)setup->targetX)
                {
                    state->offsetX = (f32)setup->targetX;
                    done = 1;
                }
            }
            if (setup->startY > setup->targetY)
            {
                state->offsetY =
                    -(0.1f * ((f32)(int)setup->speedY * timeDelta) -
                      state->offsetY);
                if (state->offsetY <= (f32)setup->targetY)
                {
                    state->offsetY = (f32)setup->targetY;
                    done += 1;
                }
            }
            else
            {
                state->offsetY =
                    0.1f * ((f32)(int)setup->speedY * timeDelta) +
                    state->offsetY;
                if (state->offsetY >= (f32)setup->targetY)
                {
                    state->offsetY = (f32)setup->targetY;
                    done += 1;
                }
            }
            if (setup->startZ > setup->targetZ)
            {
                state->offsetZ =
                    -(0.1f * ((f32)(int)setup->speedZ * timeDelta) -
                      state->offsetZ);
                if (state->offsetZ <= (f32)setup->targetZ)
                {
                    state->offsetZ = (f32)setup->targetZ;
                    done += 1;
                }
            }
            else
            {
                state->offsetZ =
                    0.1f * ((f32)(int)setup->speedZ * timeDelta) +
                    state->offsetZ;
                if (state->offsetZ >= (f32)setup->targetZ)
                {
                    state->offsetZ = (f32)setup->targetZ;
                    done += 1;
                }
            }
            if (done == 3)
            {
                if (setup->doneGameBit != -1)
                {
                    mainSetBits(setup->doneGameBit, 1);
                }
                state->loopCount += 1;
            }
        }
        else
        {
            if (setup->startX > setup->targetX)
            {
                state->offsetX =
                    0.1f * ((f32)(int)setup->speedX * timeDelta) +
                    state->offsetX;
                if (state->offsetX >= (f32)setup->startX)
                {
                    state->offsetX = (f32)setup->startX;
                    done = 1;
                }
            }
            else
            {
                state->offsetX =
                    -(0.1f * ((f32)(int)setup->speedX * timeDelta) -
                      state->offsetX);
                if (state->offsetX <= (f32)setup->startX)
                {
                    state->offsetX = (f32)setup->startX;
                    done = 1;
                }
            }
            if (setup->startY > setup->targetY)
            {
                state->offsetY =
                    0.1f * ((f32)(int)setup->speedY * timeDelta) +
                    state->offsetY;
                if (state->offsetY >= (f32)setup->startY)
                {
                    state->offsetY = (f32)setup->startY;
                    done += 1;
                }
            }
            else
            {
                state->offsetY =
                    -(0.1f * ((f32)(int)setup->speedY * timeDelta) -
                      state->offsetY);
                if (state->offsetY <= (f32)setup->startY)
                {
                    state->offsetY = (f32)setup->startY;
                    done += 1;
                }
            }
            if (setup->startZ > setup->targetZ)
            {
                state->offsetZ =
                    0.1f * ((f32)(int)setup->speedZ * timeDelta) +
                    state->offsetZ;
                if (state->offsetZ >= (f32)setup->startZ)
                {
                    state->offsetZ = (f32)setup->startZ;
                    done += 1;
                }
            }
            else
            {
                state->offsetZ =
                    -(0.1f * ((f32)(int)setup->speedZ * timeDelta) -
                      state->offsetZ);
                if (state->offsetZ <= (f32)setup->startZ)
                {
                    state->offsetZ = (f32)setup->startZ;
                    done += 1;
                }
            }
            if (done == 3)
            {
                state->loopCount += 1;
            }
        }
        break;
    }
    fn_80194C40(setup, state, block);
    return;
}

void XyzAnimator_init(GameObject* obj)
{
    XyzAnimatorState* inner = (XyzAnimatorState*)obj->extra;
    int id;
    ObjGroup_AddObject((int)obj, XYZANIMATOR_OBJGROUP);
    id = *(int*)(*(int*)&(obj)->anim.placementData + 0x14);
    switch (id)
    {
    case 0x46406:
    case 0x4BAB1:
        inner->loopSfxId = 0x7d;
        break;
    case 0x49275:
    case 0x49CB7:
    case 0x4C797:
        inner->loopSfxId = 0x4b7;
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
