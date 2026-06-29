#include "main/engine_shared.h"

#define VOXMAP_SLOT_COUNT 6
#define VOXMAPS_ROUTE_NODE_CAPACITY 200

#pragma dont_inline on
int* voxmaps_getRouteNode(u8* header, int* nodeBase, u8* bitmap, int d, int e, int f)
{
    int count;
    int e3 = e * 2 + e;
    u8* cur;
    u8* end;
    u8 bits;

    if ((f >> 3) != 0)
    {
        count = (u32)header[e3 + 1] >> 4;
        count |= header[e3 + 2] << 4;
        cur = bitmap + (e * 32 | 0x10);
    }
    else
    {
        count = header[e3];
        count |= (header[e3 + 1] & 0xf) << 8;
        cur = bitmap + e * 32;
    }
    {
        int f2 = f * 2;
        end = bitmap + (e * 32 | (f2 + (d >> 3)));
    }
    while (cur < end)
    {
        bits = *cur;
        while (bits != 0)
        {
            bits &= bits - 1;
            count++;
        }
        cur++;
    }
    bits = *cur;
    bits &= (u8)((u32)0xff >> (8 - (d & 7)));
    while (bits != 0)
    {
        bits &= bits - 1;
        count++;
    }
    return nodeBase + count;
}
#pragma dont_inline reset

s16 Queue_GetCount(RingBufferQueue* queue)
{
    return queue->count;
}

BOOL Queue_IsEmpty(RingBufferQueue* queue)
{
    return queue->count == 0;
}

void Queue_Peek(RingBufferQueue* queue, void* dst)
{
    memcpy(dst, (u8*)queue->data + queue->readIndex * queue->elemSize, queue->elemSize);
}

void Queue_Pop(RingBufferQueue* queue, void* dst)
{
    memcpy(dst, (u8*)queue->data + queue->readIndex * queue->elemSize, queue->elemSize);
    if (++queue->readIndex == queue->capacity)
    {
        queue->readIndex = 0;
    }
    queue->count--;
}

void Queue_Push(RingBufferQueue* queue, void* src)
{
    memcpy((u8*)queue->data + queue->writeIndex * queue->elemSize, src, queue->elemSize);
    if (++queue->writeIndex == queue->capacity)
    {
        queue->writeIndex = 0;
    }
    queue->count++;
}

void Queue_Init(RingBufferQueue* queue, void* data, int capacity, int elemSize)
{
    queue->data = data;
    queue->count = 0;
    queue->capacity = capacity;
    queue->elemSize = elemSize;
    queue->writeIndex = 0;
    queue->readIndex = 0;
}

BOOL Stack_IsEmpty(RingBufferQueue* stack)
{
    return stack->count == 0;
}

BOOL Stack_IsFull(RingBufferQueue* stack)
{
    return stack->count == stack->capacity - 1;
}

void Stack_Pop(RingBufferQueue* stack, void* dst)
{
    if (--stack->writeIndex < 0)
    {
        stack->writeIndex = stack->capacity - 1;
    }
    memcpy(dst, (u8*)stack->data + stack->writeIndex * stack->elemSize, stack->elemSize);
    stack->count--;
}

void Stack_Push(RingBufferQueue* stack, void* src)
{
    memcpy((u8*)stack->data + stack->writeIndex * stack->elemSize, src, stack->elemSize);
    if (++stack->writeIndex == stack->capacity)
    {
        stack->writeIndex = 0;
    }
    stack->count++;
}

void Stack_Free(RingBufferQueue* stack)
{
    mm_free(stack);
}

void voxmaps_freeRouteWork(void** p)
{
    if (p[0] != NULL)
    {
        mm_free(p[0]);
        p[0] = NULL;
    }
}

void voxmaps_allocRouteWork(void** p)
{
    p[0] = mmAlloc(0xe88, 0x10, NULL);
    p[1] = (u8*)p[0] + 0xaf0;
    p[2] = (u8*)p[1] + 0x320;
}

void voxmaps_updateTimers(void)
{
    int* p = gVoxMapsSlotTimers;
    int i;
    for (i = 0; i < VOXMAP_SLOT_COUNT; i++)
    {
        if (*p < 0x3FFFFFFF)
        {
            (*p)++;
        }
        p++;
    }
}

void voxmaps_gridToWorld(f32* out, s16* grid)
{
    int v;
    v = grid[0] * 10 + 5;
    out[0] = v;
    v = grid[1] * 10 + 5;
    out[1] = v;
    v = grid[2] * 10 + 5;
    out[2] = v;
    if (gVoxMapsTransformObj != 0)
    {
        Obj_TransformLocalPointToWorld(out[0], out[1], out[2], out, &out[1], &out[2], gVoxMapsTransformObj);
    }
}

#pragma dont_inline on
void voxmaps_worldToGrid(f32* in, s16* out)
{
    f32 sx, sy, sz;
    int ix, iy, iz;
    sx = in[0];
    sy = in[1];
    sz = in[2];
    if (gVoxMapsTransformObj != 0)
    {
        Obj_TransformWorldPointToLocal(sx, sy, sz, &sx, &sy, &sz, gVoxMapsTransformObj);
    }
    ix = sx;
    iy = sy;
    iz = sz;
    if (sx < 0.0f)
    {
        ix -= 10;
    }
    if (sy < 0.0f)
    {
        iy -= 10;
    }
    if (sz < 0.0f)
    {
        iz -= 10;
    }
    out[0] = ix / 10;
    out[1] = iy / 10;
    out[2] = iz / 10;
}
#pragma dont_inline reset

void voxmaps_resetLoadedMaps(void)
{
    VoxMaps* mgr = &gVoxMaps;
    void** mapBuffer = mgr->mapBuffer;
    int* blockId = mgr->blockId;
    int* timer = mgr->timer;
    u8* b = gVoxMapsSlotInUse;
    VoxMapSlotOrigin* slotOrigin = mgr->slotOrigin;
    int i;
    for (i = 0; i < VOXMAP_SLOT_COUNT; i++)
    {
        if (*mapBuffer != NULL)
        {
            mm_free(*mapBuffer);
            *mapBuffer = NULL;
        }
        *blockId = -2;
        *timer = 0x40000000;
        *b = 0;
        slotOrigin->gridX = 0;
        slotOrigin->gridZ = 0;
        mapBuffer++;
        blockId++;
        timer++;
        b++;
        slotOrigin++;
    }
}

void voxmaps_initialise(void)
{
    VoxMaps* mgr = &gVoxMaps;
    int* p;
    int i;

    loadAssetFileById((void**)&gVoxMapsMapList, 53);
    i = 0;
    p = gVoxMapsMapList;
    while (*p != -1)
    {
        p++;
        i++;
    }
    gVoxMapsMaxMapIndex = i - 1;
    gVoxMapsScratchBuffer = mmAlloc(640, 16, NULL);

    for (i = 0; i < VOXMAP_SLOT_COUNT; i++)
    {
        mgr->mapBuffer[i] = NULL;
        mgr->blockId[i] = -2;
        mgr->timer[i] = 0x40000000;
        gVoxMapsSlotInUse[i] = 0;
        mgr->slotOrigin[i].gridX = 0;
        mgr->slotOrigin[i].gridZ = 0;
    }

    gVoxMapsScratchBufferPtr = *(void* volatile*)&gVoxMapsScratchBuffer;
    gVoxMapsTransformObj = 0;
    gVoxMapsLargeTextures[0] = textureAlloc(64, 64, 4, 0, 0, 0, 0, 0, 0);
    gVoxMapsLargeTextures[1] = textureAlloc(64, 64, 4, 0, 0, 0, 0, 0, 0);
    gVoxMapsSmallTextures[0] = textureAlloc(16, 16, 4, 0, 0, 0, 0, 0, 0);
    gVoxMapsSmallTextures[1] = textureAlloc(16, 16, 4, 0, 0, 0, 0, 0, 0);
}

#pragma opt_propagation off
#pragma opt_strength_reduction off
int* voxmaps_updateActiveMap(VoxPos* obj)
{
    VoxMaps* vm = &gVoxMaps;
    int gridX;
    int gridY;
    int bestVal;
    int i;
    int found;
    int bestSlot;
    int blockId;
    VoxBlock* block;



    int ay = obj->z * 10 + 5 - lbl_803DCDCC;

    gridX = fastFloorf((f32)(obj->x * 10 + 5 - lbl_803DCDC8) / gVoxMapsBlockWorldSize);
    gridY = fastFloorf((f32)ay / gVoxMapsBlockWorldSize);

    vm->blockOriginWorldX = lbl_803DCDC8 + gridX * 640;
    vm->blockOriginWorldZ = lbl_803DCDCC + gridY * 640;
    vm->blockOriginGridX = *(volatile int*)&vm->blockOriginWorldX / 10;
    vm->blockOriginGridZ = *(volatile int*)&vm->blockOriginWorldZ / 10;

    blockId = -1;
    if (mapGetBlockAtPos(gridX, gridY, 0) != NULL)
    {
        block = fn_80059334(gridX, gridY);
        blockId = block->f6;
    }
    if (blockId != -1)
    {
        found = -1;
        for (i = 0; i < VOXMAP_SLOT_COUNT; i++)
        {
            int* row = (int*)((u8*)vm + (i << 2));
            if (blockId == row[12])
            {
                found = i;
                i = VOXMAP_SLOT_COUNT;
            }
        }
        if (found != -1)
        {
            vm->timer[found] = 0;
            vm->f58 = 0;
        }
        else
        {
            int b8;
            int b9;
            bestSlot = -1;
            bestVal = -1;
            for (i = 0; i < VOXMAP_SLOT_COUNT; i++)
            {
                if (gVoxMapsSlotInUse[i] == 0 && vm->timer[i] > bestVal)
                {
                    bestSlot = i;
                    bestVal = vm->timer[i];
                }
            }
            b8 = block->f8;
            b9 = block->f9;
            if (vm->mapBuffer[bestSlot] != NULL)
            {
                int saved = mmSetFreeDelay(0);
                mm_free(vm->mapBuffer[bestSlot]);
                mmSetFreeDelay(saved);
            }
            vm->mapBuffer[bestSlot] = voxLoadVoxMapActual(blockId, bestSlot, b9, b8);
            vm->blockId[bestSlot] = blockId;
            vm->timer[bestSlot] = 0;
            *(s16*)&vm->slotOrigin[bestSlot].gridX = vm->blockOriginGridX;
            *(s16*)&vm->slotOrigin[bestSlot].gridZ = vm->blockOriginGridZ;
            vm->f58 = 0;
        }
    }
    else
    {
        vm->f58 = 0;
    }
    return &vm->blockOriginWorldX;
}
#pragma opt_strength_reduction reset
#pragma opt_propagation reset

int voxmaps_traceLine(VoxPos* start, VoxPos* end, VoxPos* coordOut, u8* occOut, u8 skipFirst)
{
    int stepZ, twiceDx, twiceDy, twiceDz;
    int errXY, errXZ, errYZ;
    int stepsRemaining;
    int localX64, ySlot, localZ64, tileX, tileZ;
    int routeNodeDirty;
    VoxActiveMap* cachedMap;
    VoxState* st;
    int oldTile;
    u8 first;
    VoxPos cur = *start;
    VoxPos found;
    unsigned int skip;
    int stepX, stepY;
    int dx, dy, dz;
    u8* routeNode;

    stepX = 1;
    dx = end->x - cur.x;
    if (dx < 0)
    {
        stepX = -1;
        dx = -dx;
    }
    stepY = 1;
    dy = end->y - cur.y;
    if (dy < 0)
    {
        stepY = -1;
        dy = -dy;
    }
    stepZ = 1;
    dz = end->z - cur.z;
    if (dz < 0)
    {
        stepZ = -1;
        dz = -dz;
    }

    twiceDx = dx * 2;
    errXY = dy - dx;
    twiceDy = dy * 2;
    errXZ = dz - dx;
    twiceDz = dz * 2;
    errYZ = dy - dz;
    stepsRemaining = dx + dy + dz;

    voxmaps_updateActiveMap(&cur);

    st = &gVoxMapsRouteState;
    localX64 = (cur.x - st->originX) & 0x3f;
    tileX = localX64 >> 2;
    localZ64 = (cur.z - st->originZ) & 0x3f;
    tileZ = localZ64 >> 2;
    found = cur;
    cachedMap = NULL;
    first = 1;
    skip = skipFirst;

    while (stepsRemaining-- != 0)
    {
        if (skip != 0 && first != 0)
        {
            first = 0;
        }
        else
        {
            VoxActiveMap* map = st->activeMap;
            if (map != NULL)
            {
                if (map != cachedMap || cur.y != found.y)
                {
                    int y = cur.y;
                    if (y < map->minY)
                    {
                        ySlot = 0;
                    }
                    else if (y >= map->maxY)
                    {
                        ySlot = (map->maxY - 1) - map->minY;
                    }
                    else
                    {
                        ySlot = y - map->minY;
                    }
                    routeNodeDirty = 1;
                    cachedMap = map;
                    found.y = y;
                }
                {
                    u8* bitmap = map->bitmap;
                    unsigned int bit = (bitmap[(ySlot << 5) | ((tileZ << 1) + (tileX >> 3))] >> (tileX & 7)) & 1;
                    if (bit != 0)
                    {
                        unsigned int occ;
                        if (routeNodeDirty != 0)
                        {
                            routeNode = (u8*)voxmaps_getRouteNode(map->header, map->nodeBase, bitmap, tileX, ySlot,
                                                                  tileZ);
                            routeNodeDirty = 0;
                        }
                        occ = (routeNode[localZ64 & 3] >> ((localX64 & 3) << 1)) & 3;
                        if (occ != 0)
                        {
                            if (occOut != NULL)
                            {
                                *occOut = occ;
                            }
                            if (coordOut != NULL)
                            {
                                *coordOut = found;
                            }
                            return 0;
                        }
                    }
                }
            }
        }

        if (errXY < 0)
        {
            if (errXZ < 0)
            {
                found.x = cur.x;
                cur.x = (s16)(cur.x + stepX);
                errXY += twiceDy;
                errXZ += twiceDz;
                oldTile = tileX;
                if (((cur.x - st->originX) >> 6) != 0)
                {
                    voxmaps_updateActiveMap(&cur);
                    cachedMap = NULL;
                }
                localX64 = (cur.x - st->originX) & 0x3f;
                tileX = localX64 >> 2;
                if (tileX != oldTile)
                {
                    routeNodeDirty = 1;
                }
            }
            else
            {
                found.z = cur.z;
                cur.z = (s16)(cur.z + stepZ);
                errXZ -= twiceDx;
                errYZ += twiceDy;
                oldTile = tileZ;
                if (((cur.z - st->originZ) >> 6) != 0)
                {
                    voxmaps_updateActiveMap(&cur);
                    cachedMap = NULL;
                }
                localZ64 = (cur.z - st->originZ) & 0x3f;
                tileZ = localZ64 >> 2;
                if (tileZ != oldTile)
                {
                    routeNodeDirty = 1;
                }
            }
        }
        else
        {
            if (errYZ < 0)
            {
                found.z = cur.z;
                cur.z = (s16)(cur.z + stepZ);
                errXZ -= twiceDx;
                errYZ += twiceDy;
                oldTile = tileZ;
                if (((cur.z - st->originZ) >> 6) != 0)
                {
                    voxmaps_updateActiveMap(&cur);
                    cachedMap = NULL;
                }
                localZ64 = (cur.z - st->originZ) & 0x3f;
                tileZ = localZ64 >> 2;
                if (tileZ != oldTile)
                {
                    routeNodeDirty = 1;
                }
            }
            else
            {
                found.y = cur.y;
                cur.y = (s16)(cur.y + stepY);
                errXY -= twiceDx;
                errYZ -= twiceDz;
            }
        }
    }

    if (coordOut != NULL)
    {
        *coordOut = *end;
    }
    return 1;
}

void* voxLoadVoxMapActual(int mapArg, int slot, int b9, int b8)
{
    char* msg = sVoxmapsRouteNodesListOverflow;
    int count;
    int size;
    int entry;
    VoxMapFile* hdr;

    if (getTableFileEntry(26, mapArg, &entry) == 0)
    {
        OSReport(msg + 0xd0);
        return NULL;
    }
    loadVoxMaps(entry, &count, &size);
    if (count <= 0)
    {
        return NULL;
    }
    if (size > 30720)
    {
        debugPrintf(msg + 0x104);
        return NULL;
    }
    if (size <= 0)
    {
        OSReport(msg + 0x13c);
        return NULL;
    }
    hdr = mmAlloc(size, 16, NULL);
    if (hdr == NULL)
    {
        OSReport(msg + 0x174);
        return NULL;
    }
    loadAndDecompressDataFile(27, hdr, entry, count, 0, 0, 0);
    if (hdr == NULL)
    {
        OSReport(msg + 0x174);
        return NULL;
    }
    hdr->f1c += (int)hdr;
    hdr->f24 += (int)hdr;
    hdr->f14 += (int)hdr;
    hdr->f20 += (int)hdr;
    hdr->f28 += (int)hdr;
    hdr->f18 += (int)hdr;
    return hdr;
}

void fn_800118EC(int a1, VoxBoxArg* a2, int a3)
{
    s16 box[3];
    u16 count = a2->cost + 1;
    box[0] = a2->x;
    box[1] = a2->z;
    box[2] = a2->y;
    box[0] += 2;
    voxmapsFn_80010ff4((struct RouteState*)a1, a2, a3, count, box);
    box[0] -= 4;
    box[1] = a2->z;
    voxmapsFn_80010ff4((struct RouteState*)a1, a2, a3, count, box);
    box[0] += 2;
    box[2] += 2;
    box[1] = a2->z;
    voxmapsFn_80010ff4((struct RouteState*)a1, a2, a3, count, box);
    box[2] -= 4;
    box[1] = a2->z;
    voxmapsFn_80010ff4((struct RouteState*)a1, a2, a3, count, box);
}

static void heapSiftUp(CurveHeapNode* q, int i)
{
    int parent;
    u16 key = q[i].priority;
    u16 val = q[i].value;
    q[0].priority = 0xFFFF;
    while (q[(parent = i >> 1)].priority <= key)
    {
        q[i].value = q[parent].value;
        q[i].priority = q[parent].priority;
        i = parent;
    }
    q[i].priority = key;
    q[i].value = val;
}

void voxmapsFn_80010ff4(struct RouteState* state, VoxBoxArg* srcBox, int parentDir, u16 count, s16* box)
{
    int foundIdx;
    int savedFlag;
    int foundSlot;
    int xbit2;
    CurveHeapNode* q;
    RouteNode* n;
    u8 occ[3][4];
    int dxh;
    int dyh;
    int nodeCount;
    int key;
    int oldp;
    int dx;
    int dz;
    int xbit2p;
    int zlo;
    int zlo1;
    u8* p;
    int col;
    int blocked;
    int voxX;
    int voxZ;
    VoxState* vs;
    int shift;
    int dir;
    int next;
    int chosen;
    int sumCur;
    int sumNext;
    int i;
    int slot;
    int y;

    VoxActiveMap* map;

    if (box[0] == state->tgtX && box[2] == state->tgtY)
    {
        s16 idx = state->nodeCount;
        if (idx == VOXMAPS_ROUTE_NODE_CAPACITY)
        {
            debugPrintf(sVoxmapsRouteNodesListOverflow);
        }
        else
        {
            state->nodeCount++;
            n = &state->nodes[idx];
            n->x = box[0];
            n->z = box[1];
            n->y = box[2];
            n->gCost = count;
            n->parentDir = (u8)(u16)parentDir;
            dxh = n->x - state->tgtX;
            dyh = n->y - state->tgtY;
            n->hCost = (u16)(gVoxMapsHCostScale * sqrtf((f32)(dxh * dxh + dyh * dyh)));
        }
        q = state->queue;
        q[++state->queueCount].value = idx;
        q[state->queueCount].priority = 0xFFFE;
        heapSiftUp(q, state->queueCount);
    }

    vs = &gVoxMapsRouteState;
    dx = box[0] - vs->originX;
    dz = box[2] - vs->originZ;
    if ((dx >> 6) != 0 || (dz >> 6) != 0)
    {
        voxmaps_updateActiveMap((VoxPos*)box);
        dx = box[0] - vs->originX;
        dz = box[2] - vs->originZ;
    }
    map = gVoxMapsRouteState.activeMap;
    if (map == NULL)
    {
        return;
    }

    voxX = (dx & 0x3f) >> 2;
    voxZ = (dz & 0x3f) >> 2;
    shift = voxX & 7;
    xbit2 = (dx & 3) << 1;
    xbit2p = xbit2 + 2;
    zlo = dz & 3;
    zlo1 = zlo + 1;
    col = (voxZ << 1) + (voxX >> 3);

    p = &occ[0][0];
    for (i = 0; i < 3; i++)
    {
        y = i + box[1];
        y = y - 1;
        if (y < map->minY)
        {
            slot = 0;
        }
        else if (y >= map->maxY)
        {
            slot = (map->maxY - 1) - map->minY;
        }
        else
        {
            slot = y - map->minY;
        }
        if (((map->bitmap[(slot << 5) | col] >> shift) & 1) != 0u)
        {
            u8* node = (u8*)voxmaps_getRouteNode(map->header, map->nodeBase, map->bitmap, voxX, slot, voxZ);
            p[0] = (node[zlo] >> xbit2) & 3;
            p[1] = (node[zlo] >> xbit2p) & 3;
            p[2] = (node[zlo1] >> xbit2) & 3;
            p[3] = (node[zlo1] >> xbit2p) & 3;
        }
        else
        {
            p[0] = 0;
            p[1] = 0;
            p[2] = 0;
            p[3] = 0;
        }
        p += 4;
    }

    if (state->mode26 != 0)
    {
        if ((occ[1][0] & 2) || (occ[1][1] & 2) || (occ[1][2] & 2) || (occ[1][3] & 2))
        {
            blocked = 1;
        }
        dir = -1;
    }
    else
    {
        dir = 1;
    }

    for (; dir >= 0; dir--)
    {
        next = dir + 1;
        blocked = 0;
        chosen = dir;
        if ((occ[dir][0] & 2) || (occ[dir][1] & 2) || (occ[dir][2] & 2) || (occ[dir][3] & 2))
        {
            blocked = 1;
            dir = 0;
        }
        if (!blocked)
        {
            if ((occ[next][0] & 2) || (occ[next][1] & 2) || (occ[next][2] & 2) || (occ[next][3] & 2))
            {
                blocked = 1;
                dir = 0;
            }
        }
        if (!blocked)
        {
            sumCur = occ[dir][0];
            sumNext = occ[next][0];
            sumCur += occ[dir][1];
            sumNext += occ[next][1];
            sumCur += occ[dir][2];
            sumNext += occ[next][2];
            sumCur += occ[dir][3];
            sumNext += occ[next][3];
            if (next == 2 && sumNext == 0)
            {
                blocked = 1;
            }
            else
            {
                if (next == 1)
                {
                    if (sumCur >= sumNext)
                    {
                        chosen--;
                    }
                    else
                    {
                        sumCur = sumNext;
                    }
                }
                else
                {
                    if (sumCur > sumNext)
                    {
                        chosen--;
                    }
                    else
                    {
                        sumCur = sumNext;
                    }
                }
                if (sumCur <= 1)
                {
                    blocked = 1;
                }
                else
                {
                    dir = 0;
                }
            }
        }
    }

    if (blocked != 0)
    {
        return;
    }

    box[1] = (s16)(box[1] + chosen);

    foundIdx = -1;
    {
        int boff = 0;
        s16 bz = box[2];
        s16 bx = box[0];
        nodeCount = state->nodeCount;
        for (foundIdx = 0; foundIdx < nodeCount; foundIdx++)
        {
            RouteNode* nn = (RouteNode*)((char*)state->nodes + boff);
            if (nn->x == bx && nn->y == bz)
            {
                savedFlag = nn->flag;
                goto searched;
            }
            boff += 14;
        }
        foundIdx = -1;
    }
searched:
    nodeCount = state->nodeCount;

    if (foundIdx >= 0 && savedFlag == 0)
    {
        n = &state->nodes[foundIdx];
        if (count >= n->gCost)
        {
            return;
        }
        n->parentDir = parentDir;
        n->gCost = count;
        key = (u16)(n->hCost + n->gCost);
        q = state->queue;
        for (slot = 0; slot <= state->queueCount; slot++)
        {
            if ((u16)foundIdx == q[slot].value)
            {
                foundSlot = slot;
                slot = state->queueCount + 1;
            }
        }
        oldp = q[foundSlot].priority;
        q[foundSlot].priority = key;
        if (key < oldp)
        {
            CurveHeap_SiftDown(q, state->queueCount, foundSlot);
        }
        else if (key > oldp)
        {
            heapSiftUp(q, foundSlot);
        }
        return;
    }

    if (foundIdx >= 0)
    {
        return;
    }

    if (nodeCount == VOXMAPS_ROUTE_NODE_CAPACITY)
    {
        debugPrintf(sVoxmapsRouteNodesListOverflow);
        n = NULL;
    }
    else
    {
        n = &state->nodes[state->nodeCount];
        state->nodeCount++;
        n->x = box[0];
        n->z = box[1];
        n->y = box[2];
        n->gCost = count;
        n->parentDir = (u8)(u16)parentDir;
        dxh = n->x - state->tgtX;
        dyh = n->y - state->tgtY;
        n->hCost = (u16)(gVoxMapsHCostScale * sqrtf((f32)(dxh * dxh + dyh * dyh)));
    }

    if (n == NULL)
    {
        debugPrintf(sVoxMapsDebugStrings);
        return;
    }

    if (n->hCost > state->minHCost)
    {
        key = (u16)(n->hCost + n->gCost);
        q = state->queue;
        state->queueCount++;
        q[state->queueCount].value = nodeCount;
        q[state->queueCount].priority = 0xFFFF - key;
        heapSiftUp(q, state->queueCount);
    }
    else
    {
        if (n->hCost < state->minHCost)
        {
            state->minHCost = n->hCost;
        }
        key = (u16)(n->hCost + n->gCost);
        q = state->queue;
        state->queueCount++;
        q[state->queueCount].value = nodeCount;
        q[state->queueCount].priority = 0xFFFF - key;
        heapSiftUp(q, state->queueCount);
    }
}

#pragma dont_inline on
int voxmaps_processRouteQueue(RouteState* state, int count)
{
    int done = 0;
    int ret = 0;
    int nodeIdx;
    CurveHeapNode* queue;
    RouteNode* node;

    while (!done && count != 0)
    {
        queue = state->queue;
        if (state->queueCount == 0)
        {
            nodeIdx = -1;
        }
        else
        {
            nodeIdx = queue[1].value;
            queue[1].priority = queue[state->queueCount].priority;
            queue[1].value = queue[state->queueCount--].value;
            CurveHeap_SiftDown(queue, state->queueCount, 1);
        }
        if (nodeIdx >= 0)
        {
            node = state->nodes + nodeIdx;
            state->cur = nodeIdx;
            if (node->x == state->tgtX && node->y == state->tgtY)
            {
                done = 1;
                ret = 1;
            }
            else
            {
                node->flag = 1;
                fn_800118EC((int)state, (VoxBoxArg*)node, nodeIdx);
            }
        }
        else
        {
            done = 1;
            ret = -1;
        }
        count--;
    }
    return ret;
}
#pragma dont_inline reset

int voxmaps_updateRoutePath(RouteNav* nav, RouteState* state)
{
    RouteNode* node;
    int navState;
    int ret;
    int flag = 0;
    int i;
    s16 out[3];

    navState = nav->navState;
    ret = 0;
    if (navState == 0)
    {
        int pathDirect;

        state->queueCount = 0;
        state->nodeCount = 0;
        for (i = 0; i < VOXMAPS_ROUTE_NODE_CAPACITY; i++)
        {
            state->queue[i].priority = 0;
            state->nodes[i].flag = 0;
        }
        voxmaps_worldToGrid(nav->destPos, &state->startX);
        voxmaps_worldToGrid(nav->curPos, &state->tgtX);
        state->startX &= ~1;
        state->startY &= ~1;
        state->tgtX &= ~1;
        state->tgtY &= ~1;
        if (fn_800119FC(&state->startX, &state->tgtX, out) != 0)
        {
            pathDirect = 1;
        }
        else
        {
            int count;
            state->minHCost = 0x2710;
            count = state->nodeCount;
            if (count == VOXMAPS_ROUTE_NODE_CAPACITY)
            {
                debugPrintf(sVoxmapsRouteNodesListOverflow);
                node = NULL;
            }
            else
            {
                int dx, dz, d2;
                state->nodeCount += 1;
                node = &state->nodes[count];
                node->x = out[0];
                node->z = out[1];
                node->y = out[2];
                node->gCost = 0;
                node->parentDir = 0xff;
                dx = node->x - state->tgtX;
                dz = node->y - state->tgtY;
                d2 = dx * dx + dz * dz;
                node->hCost = (u16)(gVoxMapsHCostScale * sqrtf((f32)d2));
            }
            {
                u16 cost = node->hCost + node->gCost;
                CurveHeapNode* queue = state->queue;

                queue[++state->queueCount].value = (u16)(state->nodeCount - 1);
                queue[state->queueCount].priority = (u16)(0xffff - cost);
                heapSiftUp(queue, state->queueCount);
                state->pathCount = 0;
            }
            pathDirect = 0;
        }
        if (pathDirect != 0)
        {
            nav->tgtPos[0] = nav->curPos[0];
            nav->tgtPos[1] = nav->curPos[1];
            nav->tgtPos[2] = nav->curPos[2];
            ret = 1;
            flag = 1;
        }
        else
        {
            navState = 1;
        }
    }

    if (navState != 0)
    {
        int r;
        ret = 1;
        r = voxmaps_processRouteQueue(state, nav->budget);
        switch (r)
        {
        case 0:
            if (navState++ < nav->maxIters)
            {
            }
            else
            {
                navState = 0;
                if (fn_80011EB0(state, 1) != 0)
                {
                    nav->tgtPos[0] = state->pathPoints[0];
                    nav->tgtPos[1] = state->pathPoints[1];
                    nav->tgtPos[2] = state->pathPoints[2];
                }
                else
                {
                    nav->tgtPos[0] = nav->curPos[0];
                    nav->tgtPos[1] = nav->curPos[1];
                    nav->tgtPos[2] = nav->curPos[2];
                    flag = 1;
                }
            }
            ret = 1;
            break;
        case 1:
            navState = 0;
            if (fn_80011EB0(state, 1) != 0)
            {
                nav->tgtPos[0] = state->pathPoints[0];
                nav->tgtPos[1] = state->pathPoints[1];
                nav->tgtPos[2] = state->pathPoints[2];
            }
            else
            {
                nav->tgtPos[0] = nav->curPos[0];
                nav->tgtPos[1] = nav->curPos[1];
                nav->tgtPos[2] = nav->curPos[2];
                flag = 1;
            }
            ret = 1;
            break;
        case -1:
            navState = 0;
            nav->tgtPos[0] = nav->destPos[0];
            nav->tgtPos[1] = nav->destPos[1];
            nav->tgtPos[2] = nav->destPos[2];
            flag = 1;
            break;
        }
    }

    nav->navState = navState;
    nav->flag25 = flag;
    return ret;
}

int fn_800119FC(s16* dest, s16* start, s16* out)
{
    VoxPos cur = *(VoxPos*)dest;
    VoxPos found;
    VoxState* st;
    int shiftHi;
    int z6lo;
    int z6hi;
    int bitmapCol;
    u8 buf[12];
    int sumA, sumB;
    int adj, blocked;
    int voxXand7;
    int row;
    int slot;
    u8* node;
    int i, next;
    int shiftLo;
    VoxActiveMap* map;
    int voxX6;
    int voxZ6;
    int voxX;
    int voxZ;
    int err, steps;
    int xstep, ystep;
    int dx2, dy2;
    int dx, dy;









    xstep = 2;
    dx = ((VoxPos*)start)->x - cur.x;
    if (dx < 0)
    {
        xstep = -2;
        dx = -dx;
    }
    ystep = 2;
    dy = ((VoxPos*)start)->z - cur.z;
    if (dy < 0)
    {
        ystep = -2;
        dy = -dy;
    }

    dx2 = dx & ~1;
    dy2 = dy & ~1;
    err = (dy >> 1) - (dx >> 1);
    steps = (dx >> 1) + (dy >> 1);

    voxmaps_updateActiveMap(&cur);

    st = &gVoxMapsRouteState;
    voxX6 = (cur.x - st->originX) & 0x3f;
    voxX = voxX6 >> 2;
    voxZ6 = (cur.z - st->originZ) & 0x3f;
    voxZ = voxZ6 >> 2;
    voxXand7 = voxX & 7;
    shiftLo = (voxX6 & 3) << 1;
    shiftHi = shiftLo + 2;
    found = cur;

    while (steps-- != 0)
    {
        map = st->activeMap;
        if (map != NULL)
        {
            z6lo = voxZ6 & 3;
            z6hi = z6lo + 1;
            for (row = 0, bitmapCol = (voxZ << 1) + (voxX >> 3); row < 3; row++)
            {
                int y = row + cur.y;
                y -= 1;
                if (y < map->minY)
                {
                    slot = 0;
                }
                else if (y >= map->maxY)
                {
                    slot = (map->maxY - 1) - map->minY;
                }
                else
                {
                    slot = y - map->minY;
                }
                if (((map->bitmap[(slot << 5) | bitmapCol] >> voxXand7) & 1u) != 0u)
                {
                    node = (u8*)voxmaps_getRouteNode(map->header, map->nodeBase, map->bitmap, voxX, slot, voxZ);
                    buf[row * 4 + 0] = (node[z6lo] >> shiftLo) & 3;
                    buf[row * 4 + 1] = (node[z6lo] >> shiftHi) & 3;
                    buf[row * 4 + 2] = (node[z6hi] >> shiftLo) & 3;
                    buf[row * 4 + 3] = (node[z6hi] >> shiftHi) & 3;
                }
                else
                {
                    buf[row * 4 + 0] = 0;
                    buf[row * 4 + 1] = 0;
                    buf[row * 4 + 2] = 0;
                    buf[row * 4 + 3] = 0;
                }
            }

            i = 1;
            while (i >= 0)
            {
                next = i + 1;
                blocked = 0;
                adj = i;
                if ((buf[i * 4] & 2) || (buf[i * 4 + 1] & 2) || (buf[i * 4 + 2] & 2) || (buf[i * 4 + 3] & 2))
                {
                    blocked = 1;
                }
                if (!blocked)
                {
                    if ((buf[next * 4] & 2) || (buf[next * 4 + 1] & 2) || (buf[next * 4 + 2] & 2) || (buf[next * 4 + 3]
                        & 2))
                    {
                        blocked = 1;
                    }
                }
                if (!blocked)
                {
                    sumA = *(u8*)&buf[i * 4];
                    sumB = *(u8*)&buf[next * 4];
                    sumA += buf[i * 4 + 1];
                    sumB += buf[next * 4 + 1];
                    sumA += buf[i * 4 + 2];
                    sumB += buf[next * 4 + 2];
                    sumA += buf[i * 4 + 3];
                    sumB += buf[next * 4 + 3];
                    if (next == 2 && sumB == 0)
                    {
                        blocked = 1;
                    }
                    else
                    {
                        if (next == 1)
                        {
                            if (sumA >= sumB) adj--;
                            else sumA = sumB;
                        }
                        else
                        {
                            if (sumA > sumB) adj--;
                            else sumA = sumB;
                        }
                        if (sumA <= 1)
                        {
                            blocked = 1;
                        }
                        else
                        {
                            i = 0;
                        }
                    }
                }
                i--;
            }

            if (blocked)
            {
                if (out != NULL)
                {
                    *(VoxPos*)out = found;
                }
                return 0;
            }
            found.y = cur.y = (s16)(cur.y + adj);
        }

        if (err < 0)
        {
            found.x = cur.x;
            cur.x = (s16)(cur.x + xstep);
            err += dy2;
            if (((cur.x - st->originX) >> 6) != 0)
            {
                voxmaps_updateActiveMap(&cur);
            }
            voxX6 = (cur.x - st->originZ) & 0x3f;
            voxX = voxX6 >> 2;
            voxXand7 = voxX & 7;
            shiftLo = (voxX6 & 3) << 1;
            shiftHi = shiftLo + 2;
        }
        else
        {
            found.z = cur.z;
            cur.z = (s16)(cur.z + ystep);
            err -= dx2;
            if (((cur.z - st->originZ) >> 6) != 0)
            {
                voxmaps_updateActiveMap(&cur);
            }
            voxZ6 = (cur.z - st->originZ) & 0x3f;
            voxZ = voxZ6 >> 2;
        }
    }

    if (out != NULL)
    {
        *(VoxPos*)out = *(VoxPos*)start;
    }
    return 1;
}

int fn_80011EB0(RouteState* state, int count)
{
    f32 local[3];
    RouteNode startNode;
    RouteNode* cur;
    int idx;
    RouteNode* cand;
    RouteNode* lastClear;
    int j;
    int i;
    RouteNode* node;

    if (count < 0)
    {
        count = 10;
    }
    i = state->cur;
    node = &state->nodes[i];
    node->parentIdx = 0xff;
    while ((j = node->parentDir) != 0xffu)
    {
        node = &state->nodes[j];
        node->parentIdx = i;
        i = j;
    }

    startNode.x = state->startX;
    startNode.z = state->startZ;
    startNode.y = state->startY;
    startNode.parentIdx = i;
    if (node->parentIdx == 0xff)
    {
        cand = NULL;
    }
    else
    {
        cand = &state->nodes[node->parentIdx];
    }
    lastClear = node;
    cur = &startNode;
    idx = 0;

    while (idx < count && cand != NULL)
    {
        if (cur->x != cand->x || cur->y != cand->y)
        {
            if (fn_800119FC((s16*)cand, (s16*)cur, NULL) == 0)
            {
                local[0] = (f32)(lastClear->x * 10 + 5);
                local[1] = (f32)(lastClear->z * 10 + 5);
                local[2] = (f32)(lastClear->y * 10 + 5);
                if (gVoxMapsTransformObj != 0)
                {
                    Obj_TransformLocalPointToWorld(local[0], local[1], local[2], &local[0], &local[1], &local[2],
                                                   gVoxMapsTransformObj);
                }
                state->pathPoints[idx * 3 + 0] = (f32)((int)local[0] + 5);
                state->pathPoints[idx * 3 + 1] = (f32)(int)
                local[1];
                state->pathPoints[idx++ * 3 + 2] = (f32)((int)local[2] + 5);
                cur = cand;
            }
        }
        lastClear = cand;
        if (cand->parentIdx == 0xff)
        {
            cand = NULL;
        }
        else
        {
            cand = &state->nodes[cand->parentIdx];
        }
    }

    if (idx < count)
    {
        local[0] = (f32)(lastClear->x * 10 + 5);
        local[1] = (f32)(lastClear->z * 10 + 5);
        local[2] = (f32)(lastClear->y * 10 + 5);
        if (gVoxMapsTransformObj != 0)
        {
            Obj_TransformLocalPointToWorld(local[0], local[1], local[2], &local[0], &local[1], &local[2], gVoxMapsTransformObj);
        }
        state->pathPoints[idx * 3 + 0] = (f32)((int)local[0] + 5);
        state->pathPoints[idx * 3 + 1] = (f32)(int)
        local[1];
        state->pathPoints[idx++ * 3 + 2] = (f32)((int)local[2] + 5);
        if (idx >= 10)
        {
            idx = 10;
        }
    }

    state->pathCount = idx;
    state->pad22 = 0;
    return idx;
}
