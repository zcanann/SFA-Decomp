#include "dolphin/os/OSReport.h"
#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "dolphin/gx/GXMisc.h"
#include "main/pi_dolphin.h"
#include "main/newshadows.h"
#include "main/mm.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/os/OSStopwatch.h"
#include "string.h"
#include "main/pad.h"
#include "main/pi_data_file_api.h"
#include "main/pi_flush_api.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/dll/FRONT/n_options.h"
#include "dolphin/os/OSResetSW.h"
#include "dolphin/gx/GXCull.h"
#include "main/track_dolphin_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/os/OSArena.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "dolphin/gx/GXCpu2Efb.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXPerf.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/os/OSTime.h"
#include "dolphin/vi.h"
#include "main/camera.h"
#include "main/debug.h"
#include "main/fileio.h"
#include "main/gameloop_api.h"
#include "main/map_load.h"
#include "main/map_texscroll.h"
#include "main/table_file.h"
#include "main/rcp_dolphin.h"
#include "main/sky_api.h"
#include "main/textrender_api.h"
#include "main/vecmath_distance_api.h"
#include "main/zlb.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "track/intersect_api.h"
#include "track/intersect_depth_read_api.h"
#include "main/objprint_load_api.h"
#include "dolphin/os/OSAlloc.h"
#include "main/objmodel.h"
#include "main/newshadows_texture_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "dolphin/gx/GXBump.h"

extern void* lbl_803DCD10;
extern char* lbl_803DCD08;
extern void* externalFrameBuffer0;
extern void* externalFrameBuffer1;
extern OSThread* lbl_803DCCDC;
extern GXFifoObj* lbl_803DCCD4;
extern void* renderFrameBuffer;
extern char lbl_803DCCC4;
extern f32 lbl_803DCCC0;
extern f32 lbl_803DCCB4;
extern u8 lbl_803DCCB0;
extern volatile int lbl_803DCCAC;
extern u8 lbl_803DCCA7;
extern u8 gVideoBlackScreenFrameCount;
extern u16 lbl_803DB5CE;
extern u8 gLoadingScreenTextures[];
extern OSStopwatch lbl_8035F680;
extern f32 physicsTimeScale;
extern f32 lbl_803DEAA0;
extern f32 lbl_803DEA74;
extern f32 lbl_803DEA7C;
extern u8 lbl_803DB411;
extern RingBufferQueue lbl_8035F730;
extern f32 lbl_803DEA70;
extern f32 lbl_803DEA78;

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} PiWGPipe;
extern volatile PiWGPipe GXWGFifo : (0xCC008000);

int GXFlush_(u8 visible, int unused)
{
    void* fifo_get;
    void* fifo_put;
    void* item[3];
    int s;
    void* next;
    gxSetZMode_(1, GX_LEQUAL, 1);
    GXSetAlphaUpdate(GX_TRUE);
    GXFlush();
    GXGetFifoPtrs(lbl_803DCCD4, &fifo_get, &fifo_put);
    item[0] = fifo_put;
    item[1] = 0;
    item[2] = renderFrameBuffer;
    s = OSDisableInterrupts();
    Queue_Push(&lbl_8035F730, item);
    if (lbl_803DCCA7 == 0)
    {
        GXEnableBreakPt(fifo_put);
        lbl_803DCCA7 = 1;
    }
    OSRestoreInterrupts(s);
    GXSetDrawSync(lbl_803DB5CE);
    GXCopyDisp(renderFrameBuffer, 1);
    GXFlush();
    lbl_803DB5CE = (u16)(lbl_803DB5CE + 1);
    next = renderFrameBuffer == externalFrameBuffer0 ? externalFrameBuffer1 : externalFrameBuffer0;
    renderFrameBuffer = next;
    if (visible != 0 && gVideoBlackScreenFrameCount != 0)
    {
        gVideoBlackScreenFrameCount--;
        if (gVideoBlackScreenFrameCount == 0)
        {
            VISetBlack(0);
            gVideoBlackScreenFrameCount = 0;
        }
    }
    return 0;
}



void videoBlackScreenForFrames(int frameCount)
{
    int frames = frameCount;
    VISetBlack(1);
    VIFlush();
    gVideoBlackScreenFrameCount = frames;
}
void logGpuHang(void)
{
    char* strs = (char*)gLoadingScreenTextures;
    u32 topClks, topPerf0, topClks2, topPerf1;
    u32 botClks, botPerf0, botClks2, botPerf1;
    u32 xfStuck;
    u32 cmdStuck;
    u32 rdIdle;
    u32 cmdIdle;
    u8 cmdRdy;
    u8 readIdle;
    u8 fifoErr;

    GXReadXfRasMetric(&topPerf0, &topClks, &topPerf1, &topClks2);
    GXReadXfRasMetric(&botPerf0, &botClks, &botPerf1, &botClks2);
    xfStuck = (botClks - topClks) == 0;
    cmdStuck = (botPerf0 - topPerf0) == 0;
    rdIdle = (botClks2 - topClks2) != 0;
    cmdIdle = (botPerf1 - topPerf1) != 0;
    GXGetGPStatus(&fifoErr, &fifoErr, &cmdRdy, &readIdle, &fifoErr);
    OSReport(strs + 0x4002c, cmdRdy, readIdle, xfStuck, cmdStuck, rdIdle, cmdIdle);
    if (cmdStuck == 0 && rdIdle != 0)
    {
        OSReport(strs + 0x400fc);
    }
    else if (xfStuck == 0 && cmdStuck != 0 && rdIdle != 0)
    {
        OSReport(strs + 0x4011c);
    }
    else if (readIdle == 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0)
    {
        OSReport(strs + 0x40144);
    }
    else if (cmdRdy != 0 && readIdle != 0 && xfStuck != 0 && cmdStuck != 0 && rdIdle != 0 && cmdIdle != 0)
    {
        OSReport(strs + 0x4016c);
    }
    else
    {
        OSReport(strs + 0x4019c);
    }
}

void gxPerfFn_8004a77c(int enabled)
{
    if ((u8)enabled != 0)
    {
        GXSetGPMetric(GX_PERF0_NONE, GX_PERF1_NONE);
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x2402c004;
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x23000020;
        GXWGFifo.u8 = 0x10;
        GXWGFifo.u16 = 0;
        GXWGFifo.u16 = 0x1006;
        GXWGFifo.u32 = 0x84400;
    }
    else
    {
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x24000000;
        GXWGFifo.u8 = 0x61;
        GXWGFifo.u32 = 0x23000000;
        GXWGFifo.u8 = 0x10;
        GXWGFifo.u16 = 0;
        GXWGFifo.u16 = 0x1006;
        GXWGFifo.u32 = 0;
    }
}
void gxTransformFn_8004a83c(void)
{
    lbl_803DCCB0 = 0;
    gxPerfFn_8004a77c(0);
}

extern char sThreadStateAttrSuspendFormat[];

void waitNextFrame(void)
{
    int lvl;
    u32 frames;

    OSStopStopwatch(&lbl_8035F680);
    lbl_803DCCC0 =
        (u64)OSCheckStopwatch(&lbl_8035F680) / (f32)(u32)((*(u32*)0x800000f8 >> 2) / 1000);
    OSResetStopwatch(&lbl_8035F680);
    OSStartStopwatch(&lbl_8035F680);
    timeDelta = physicsTimeScale * (lbl_803DEAA0 * lbl_803DCCC0);
    if (gDvdErrorPauseActive != 0)
    {
        timeDelta = lbl_803DEA70;
    }
    if (timeDelta > lbl_803DEA74)
    {
        timeDelta = *(f32*)&lbl_803DEA74;
    }
    if (timeDelta > lbl_803DEA7C)
    {
        oneOverTimeDelta = lbl_803DEA78 / timeDelta;
    }
    else
    {
        oneOverTimeDelta = lbl_803DEA78;
    }
    frames = (int)(timeDelta + lbl_803DCCB4) & 0xff;
    framesThisStep = frames;
    lbl_803DCCB4 = (timeDelta + lbl_803DCCB4) - (f32)(u32)framesThisStep;
    lbl_803DB411 = frames;
    if (framesThisStep < 1)
    {
        framesThisStep = 1;
    }
    lvl = OSDisableInterrupts();
    lbl_803DCCDC = OSGetCurrentThread();
    if (lbl_803DCCDC->state != OS_THREAD_STATE_RUNNING)
    {
        OSReport(sThreadStateAttrSuspendFormat, lbl_803DCCDC->state, lbl_803DCCDC->attr,
                 lbl_803DCCDC->suspend);
    }
    if ((u32)Queue_GetCount(&lbl_8035F730) > 1)
    {
        lbl_803DCCAC = 0;
        OSSleepThread((OSThreadQueue*)&lbl_803DCCC4);
    }
    OSRestoreInterrupts(lvl);
    Camera_ApplyFullViewport();
    GXInvalidateVtxCache();
    GXInvalidateTexAll();
}

int pathSearchNodeMatchesTarget(int* ctx, int* ref)
{
    int* node;
    int target;
    target = ctx[4];
    node = (int*)ref[0];
    switch (((s8*)node)[0x19])
    {
    case 0x24:
    {
        u8 idx = ((u8*)ref)[0xc];
        if ((idx & 0x80) == 0)
        {
            if (((u8*)node)[3] != 0)
            {
                return target == ((u8*)node)[3];
            }
            else
            {
                int* p;
                int* arr;
                int i;
                arr = (int*)*(int*)((char*)ctx[0] + (idx << 4));
                for (i = 0, p = arr; i < 4; i++)
                {
                    if ((u32)node[5] == *(u32*)((char*)p + 0x1c))
                    {
                        return target == ((u8*)arr)[i + 4];
                    }
                    p++;
                }
            }
        }
        return 0;
    }
    default:
        return target == (int)node;
    }
}

void pathSearchHeapSiftDown(u8* arr, int size, int idx)
{
    u16* h = (u16*)arr;
    int half;
    u8* childptr;
    u32 key = *(u32*)((int)arr + idx * 8);
    u16 val = h[idx * 4 + 2];
    int child;
    u8* cp;
    half = size >> 1;
    while (idx <= half)
    {
        child = idx + idx;
        if (child < size)
        {
            cp = arr + child * 8;
            if (*(u32*)cp < *(u32*)(cp + 8))
            {
                child++;
            }
        }
        childptr = arr + child * 8;
        if (key >= *(u32*)childptr)
            break;
        *(u32*)(arr + idx * 8) = *(u32*)childptr;
        *(u16*)(arr + idx * 8 + 4) = *(u16*)(childptr + 4);
        idx = child;
    }
    *(u32*)((int)arr + idx * 8) = key;
    h[idx * 4 + 2] = val;
}


extern GXTexObj lbl_803779A0;


int pathSearchNodeMatchesTarget(int* ctx, int* ref);
void pathSearchHeapSiftDown(u8* arr, int size, int idx);
static inline void pathSearchHeapInsert(PathSearch* search, u16 index, u32 pri)
{
    int i;
    u16 idx16;
    u32 key;
    int parent;
    u32* heap;
    u16* hh;
    heap = (u32*)search->heap;
    hh = (u16*)search->heap;
    hh[++search->heapSize * 4 + 2] = index;
    *(u32*)((int)heap + search->heapSize * 8) = pri;
    i = search->heapSize;
    key = *(u32*)((int)heap + i * 8);
    idx16 = hh[i * 4 + 2];
    *heap = -1;
    while (parent = i >> 1, *(u32*)(hh + parent * 4) < key)
    {
        *(u16*)((int)heap + i * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
        *(u32*)((int)heap + i * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
        i = parent;
    }
    *(u32*)((int)heap + i * 8) = key;
    hh[i * 4 + 2] = idx16;
}

static inline int pathSearchFindPointNode(PathSearch* search, PathPoint* point, int* countOut, int* visitedOut)
{
    int index = 0;
    int offset = 0;
    int n;

    *countOut = search->nodeCount;
    for (n = *countOut; n > 0; n--)
    {
        PathSearchNode* scanNode = (PathSearchNode*)((u8*)search->nodes + offset);
        if (scanNode->point == point)
        {
            *visitedOut = scanNode->visited;
            return index;
        }
        offset += 0x10;
        index++;
    }
    return -1;
}

void pathSearchEnqueuePoint(int* q, int* elem, int idx, u32 d, char* obj)
{
    PathSearch* search = (PathSearch*)q;
    PathPoint* point = (PathPoint*)obj;
    int pos;
    u16* hh;
    int cnt2;
    PathSearchNode* node;
    u32* heap;
    int z[2];
    PathSearchNode* node4;
    int visited;
    int cnt;
    if (pathSearchNodeMatchesTarget(q, elem) != 0)
    {
        cnt = search->nodeCount;
        if (cnt != 0xfe)
        {
            node = &search->nodes[search->nodeCount++];
            node->point = point;
            node->routeDistance = d;
            node->parentIndex = (u16)idx;
            node->distanceToTarget = (u32)vec3f_distanceSquared(node->point->position, search->targetPosition);
        }
        pathSearchHeapInsert(search, cnt, 0xfffffffe);
    }
    z[0] = pathSearchFindPointNode(search, point, &cnt2, &visited);
    if (z[0] >= 0 && visited == 0)
    {
        PathSearchNode* node3 = &search->nodes[z[0]];
        if (d < node3->routeDistance)
        {
            u32 newpri;
            int s2;
            int j;
            u16 target;
            u32* entry;
            u32 old;
            node3->parentIndex = idx;
            node3->routeDistance = d;
            newpri = node3->distanceToTarget + node3->routeDistance;
            s2 = search->heapSize;
            heap = (u32*)search->heap;
            hh = (u16*)heap;
            j = 0;
            target = z[0];
            for (; j <= s2; j++)
            {
                if (target == *(u16*)(heap + j * 2 + 1))
                {
                    pos = j;
                    j = s2 + 1;
                }
            }
            entry = heap + pos * 2;
            old = *entry;
            *entry = newpri;
            if (newpri < old)
            {
                pathSearchHeapSiftDown((u8*)heap, s2, pos);
            }
            else if (newpri > old)
            {
                u32 pri = *entry;
                u16 idx16 = ((u16*)entry)[2];
                int parent;
                *heap = -1;
                while (parent = pos >> 1, *(u32*)(hh + parent * 4) < pri)
                {
                    *(u16*)((int)heap + pos * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
                    *(u32*)((int)heap + pos * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
                    pos = parent;
                }
                *(u32*)((int)heap + pos * 8) = pri;
                hh[pos * 4 + 2] = idx16;
            }
        }
    }
    else if (z[0] < 0)
    {
        if (cnt2 == 0xfe)
        {
            node4 = NULL;
        }
        else
        {
            node4 = &search->nodes[search->nodeCount++];
            node4->point = point;
            node4->routeDistance = d;
            node4->parentIndex = (u16)idx;
            node4->distanceToTarget = (u32)vec3f_distanceSquared(node4->point->position, search->targetPosition);
        }
        if (node4 != NULL)
        {
            if (node4->distanceToTarget > search->closestDistance)
            {
                u32 newpri = node4->distanceToTarget + node4->routeDistance;
                pathSearchHeapInsert(search, cnt2, -1 - newpri);
            }
            else
            {
                u32 newpri;
                if (node4->distanceToTarget < search->closestDistance)
                {
                    search->closestDistance = node4->distanceToTarget;
                }
                newpri = node4->distanceToTarget + node4->routeDistance;
                pathSearchHeapInsert(search, cnt2, -1 - newpri);
            }
        }
    }
}

void pathSearchExpandNode(int* q, int* elem, int idx)
{
    u8 mask;
    char* p;
    char* node;
    char* obj;
    int bit;
    int t;
    node = (char*)elem[0];
    if (*(u8*)((char*)q + 0x28) != 0)
    {
        t = *(s8*)(node + 0x1b);
    }
    else
    {
        t = ~*(s8*)(node + 0x1b);
    }
    bit = 0;
    p = node;
    mask = t;
    for (; bit < 4; bit++)
    {
        int nodeId = *(int*)(p + 0x1c);
        if (nodeId > -1 && (mask & (1 << bit)) != 0)
        {
            obj = (char*)(*gRomCurveInterface)->getById(nodeId);
            if (obj != 0)
            {
                switch (*(s8*)(obj + 0x19))
                {
                case 0x24:
                {
                    s16 ev1;
                    s16 ev2;
                    mainGetBit(0x4e2);
                    ev1 = *(s16*)(obj + 0x30);
                    if (ev1 == -1 || mainGetBit(ev1) != 0)
                    {
                        ev2 = *(s16*)(obj + 0x32);
                        if (ev2 == -1 || mainGetBit(ev2) == 0)
                        {
                            if (!(*(s8*)(obj + 0x1a) == 8 && *(s8*)(node + 0x1a) == 9))
                            {
                                f32 d = vec3f_distanceSquared((f32*)(node + 8), (f32*)(obj + 8));
                                pathSearchEnqueuePoint(q, elem, idx, (u32)((f32)(u32)elem[2] + d), obj);
                            }
                        }
                    }
                    break;
                }
                default:
                    lbl_803DCD08 = obj;
                    break;
                }
            }
        }
        p += 4;
    }
}
PathPoint* pathSearchGetNextPoint(PathSearch* search)
{
    PathPoint** path;
    int index = search->pathIndex;
    if (index < search->pathCount)
    {
        path = search->path;
        search->pathIndex++;
        return path[index];
    }
    return NULL;
}

int pathSearchBuildPath(PathSearch* search)
{
    int* p = (int*)search;
    int node;
    u32 cur;
    u32 prev;
    int i;
    int count;
    int* entry;

    prev = p[7];
    node = *p + prev * 0x10;
    *(u8*)(node + 0xd) = 0xff;
    while ((cur = *(u8*)(node + 0xc)) != 0xff)
    {
        node = *p + cur * 0x10;
        *(u8*)(node + 0xd) = prev;
        prev = cur;
    }
    if (*(u8*)(node + 0xd) == 0xff)
    {
        entry = NULL;
    }
    else
    {
        entry = (int*)(*p + (u32) * (u8*)(node + 0xd) * 0x10);
    }
    count = 0;
    i = 0;
    while (entry != NULL)
    {
        *(int*)(p[2] + i) = *entry;
        i += 4;
        count++;
        if (count >= 100)
        {
            entry = NULL;
        }
        else if (*(u8*)((int)entry + 0xd) == 0xff)
        {
            entry = NULL;
        }
        else
        {
            entry = (int*)(*p + (u32) * (u8*)((int)entry + 0xd) * 0x10);
        }
    }
    *(s16*)((int)p + 0x2a) = count;
    *(u16*)(p + 0xb) = 0;
    return count;
}

int pathSearchStep(PathSearch* search, u32 n_)
{
    int n;
    int* q = (int*)search;
    int idx;
    int done;
    int result;
    int* elem;
    int* heap;
    n = n_;
    done = 0;
    result = 0;
    while (done == 0 && n != 0)
    {
        heap = *(int**)((char*)q + 0x4);
        if (*(s16*)((char*)q + 0x22) == 0)
        {
            idx = -1;
        }
        else
        {
            idx = *(u16*)((char*)heap + 0xc);
            *(int*)((char*)heap + 0x8) = *(int*)((int)heap + *(s16*)((char*)q + 0x22) * 8);
            *(u16*)((char*)heap + 0xc) = *(u16*)((char*)heap + (*(s16*)((char*)q + 0x22))-- * 8 + 4);
            pathSearchHeapSiftDown((u8*)heap, *(s16*)((char*)q + 0x22), 1);
        }
        if (idx >= 0)
        {
            elem = (int*)(*(int*)((char*)q + 0) + idx * 16);
            *(int*)((char*)q + 0x1c) = idx;
            if (pathSearchNodeMatchesTarget(q, elem) != 0)
            {
                done = 1;
                result = 1;
            }
            else
            {
                *((u8*)elem + 0xe) = 1;
                pathSearchExpandNode(q, elem, idx);
            }
        }
        else
        {
            done = 1;
            result = -1;
        }
        n--;
    }
    return result;
}

int pathSearchBegin(PathSearch* queue, PathPoint* startPoint, f32* targetPosition, int pathId, u32 routeFlags)
{
    int i;
    PathSearchNode* node;
    PathHeapEntry* heap;
    int nodeCount;
    u32 priority;
    int parent;
    u16 nodeIndex;
    u16* heapHalves;
    u16 startNodeIndex;

    queue->heapSize = 0;
    queue->nodeCount = 0;
    for (i = 0; i < 0xfe; i++)
    {
        queue->heap[i].priority = 0;
        queue->nodes[i].visited = 0;
    }
    queue->startPoint = startPoint;
    queue->targetPosition = targetPosition;
    queue->pathId = pathId;
    queue->routeFlags = routeFlags & 1;
    queue->closestDistance = 10000;
    nodeCount = queue->nodeCount;
    if (nodeCount == 0xfe)
    {
        node = NULL;
    }
    else
    {
        node = &queue->nodes[queue->nodeCount++];
        node->point = startPoint;
        node->routeDistance = 0;
        node->parentIndex = 0xff;
        node->distanceToTarget = (u32)vec3f_distanceSquared(node->point->position, queue->targetPosition);
    }
    i = node->distanceToTarget + node->routeDistance;
    heap = queue->heap;
    heapHalves = (u16*)queue->heap;
    startNodeIndex = queue->nodeCount - 1;
    heapHalves[(++queue->heapSize) * 4 + 2] = startNodeIndex;
    heap[queue->heapSize].priority = -1 - i;
    i = queue->heapSize;
    priority = heap[i].priority;
    nodeIndex = heapHalves[i * 4 + 2];
    heap[0].priority = -1;
    while (parent = i >> 1, *(u32*)(heapHalves + parent * 4) < priority)
    {
        *(u16*)((int)heap + i * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
        *(u32*)((int)heap + i * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
        i = parent;
    }
    heap[i].priority = priority;
    heapHalves[i * 4 + 2] = nodeIndex;
    return 0;
}


void freeAndNull(void** p)
{
    if (*p != NULL)
    {
        mm_free(*p);
        *p = NULL;
    }
}

void trickyVoxAllocFn_8004b5d4(PathSearch* search)
{
    search->nodes = (PathSearchNode*)mmAlloc(0x1960, 0x10, 0);
    search->heap = (PathHeapEntry*)((u8*)search->nodes + 0xfe0);
    search->path = (PathPoint**)((u8*)search->heap + 0x7f0);
}


void allocSomething32bytes(void)
{
    lbl_803DCD10 = mmAlloc(0x20, 0xff, 0);
}
