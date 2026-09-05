#include "main/pi_dolphin_path_api.h"
#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/rom_curve_def.h"
#include "main/gamebits.h"
#include "main/pi_dolphin.h"
#include "main/pi_dolphin_path_api.h"
#include "main/mm.h"
#include "main/texture.h"
#include "dolphin/os/OSInterrupt.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/track_dolphin_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/os/OSArena.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXCpu2Efb.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "main/camera.h"
#include "main/gameloop_api.h"
#include "main/map_load.h"
#include "main/map_texscroll.h"
#include "main/table_file.h"
#include "main/rcp_dolphin.h"
#include "main/sky_api.h"
#include "main/textrender_api.h"
#include "main/vecmath_distance_api.h"
#include "track/intersect_api.h"
#include "track/intersect_depth_read_api.h"
#include "main/objprint_load_api.h"
#include "dolphin/os/OSAlloc.h"
#include "main/objmodel.h"
#include "main/rcp_dolphin_render_api.h"
#include "dolphin/gx/GXBump.h"

static int pathSearchNodeMatchesTarget(PathSearch* search, PathSearchNode* node) {
    RomCurveDef* point;
    int target;
    target = search->pathId;
    point = (RomCurveDef*)node->point;
    switch (point->type) {
    case ROMCURVE_TYPE_TRICKY: {
        u8 idx = node->parentIndex;
        if ((idx & 0x80) == 0) {
            if (point->walkGroup != 0) {
                return target == point->walkGroup;
            } else {
                RomCurveDef* parent;
                int i;
                parent = (RomCurveDef*)search->nodes[idx].point;
                for (i = 0; i < 4; i++) {
                    if (point->id == (u32)parent->linkIds[i]) {
                        return target == ((u8*)parent)[i + 4];
                    }
                }
            }
        }
        return 0;
    }
    default:
        return target == (int)point;
    }
}

static void pathSearchHeapSiftDown(PathHeapEntry* heap, int size, int idx) {
    int half;
    PathHeapEntry* childptr;
    u32 key = heap[idx].priority;
    u16 val = heap[idx].nodeIndex;
    int child;
    PathHeapEntry* cp;
    half = size >> 1;
    while (idx <= half) {
        child = idx + idx;
        if (child < size) {
            cp = &heap[child];
            if (cp[0].priority < cp[1].priority) {
                child++;
            }
        }
        childptr = &heap[child];
        if (key >= childptr->priority) {
            break;
        }
        heap[idx].priority = childptr->priority;
        heap[idx].nodeIndex = childptr->nodeIndex;
        idx = child;
    }
    heap[idx].priority = key;
    heap[idx].nodeIndex = val;
}

static inline void pathSearchHeapInsert(PathSearch* search, u16 index, u32 distance) {
    int i;
    u32 key;
    u16 idx16;
    int parent;
    u32* heap;
    u16* hh;
    heap = (u32*)search->heap;
    hh = (u16*)heap;
    hh[++search->heapSize * 4 + 2] = index;
    *(u32*)((int)heap + search->heapSize * 8) = -1 - distance;
    i = search->heapSize;
    key = *(u32*)((int)heap + i * 8);
    idx16 = hh[i * 4 + 2];
    *heap = -1;
    while (parent = i >> 1, *(u32*)(hh + parent * 4) < key) {
        *(u16*)((int)heap + i * 8 + 4) = *(u16*)((int)heap + (int)((long)parent * 8) + 4);
        *(u32*)((int)heap + i * 8) = *(u32*)((int)heap + (int)((long)parent * 8));
        i = parent;
    }
    *(u32*)((int)heap + i * 8) = key;
    hh[i * 4 + 2] = idx16;
}

static inline void pathSearchClear(PathSearch* search) {
    int i;

    search->heapSize = 0;
    search->nodeCount = 0;
    for (i = 0; i < 0xfe; i++) {
        search->heap[i].priority = 0;
        search->nodes[i].visited = 0;
    }
}

static inline int pathSearchFindPointNode(PathSearch* search, RomCurveDef* point, int* countOut, int* visitedOut) {
    int index = 0;
    int offset = 0;
    int n;

    *countOut = search->nodeCount;
    for (n = *countOut; n > 0; n--) {
        PathSearchNode* scanNode = (PathSearchNode*)((u8*)search->nodes + offset);
        if (scanNode->point == point) {
            *visitedOut = scanNode->visited;
            return index;
        }
        offset += sizeof(PathSearchNode);
        index++;
    }
    return -1;
}

static inline void pathSearchHeapSiftUp(PathHeapEntry* heap, int heapIndex) {
    PathHeapEntry* entry = &heap[heapIndex];
    u32 priority = entry->priority;
    u16 nodeIndex = entry->nodeIndex;
    int parent;
    heap[0].priority = -1;
    while (parent = heapIndex >> 1, heap[(s32)parent].priority < priority) {
        heap[heapIndex].nodeIndex = heap[parent].nodeIndex;
        heap[heapIndex].priority = heap[parent].priority;
        heapIndex = parent;
    }
    heap[heapIndex].priority = priority;
    heap[heapIndex].nodeIndex = nodeIndex;
}

static inline void pathSearchHeapChangePriority(PathHeapEntry* heap, int heapSize, u16 targetNodeIndex,
                                                u32 newPriority) {
    int heapIndex;
    int searchIndex;
    PathHeapEntry* entry;
    u32 oldPriority;
    searchIndex = 0;
    for (; searchIndex <= heapSize; searchIndex++) {
        if (targetNodeIndex == heap[searchIndex].nodeIndex) {
            heapIndex = searchIndex;
            searchIndex = heapSize + 1;
        }
    }
    entry = &heap[heapIndex];
    oldPriority = entry->priority;
    entry->priority = newPriority;
    if (newPriority < oldPriority) {
        pathSearchHeapSiftDown(heap, heapSize, heapIndex);
    } else if (newPriority > oldPriority) {
        pathSearchHeapSiftUp(heap, heapIndex);
    }
}

void pathSearchAddNeighbor(PathSearch* search, PathSearchNode* previousNode, int previousNodeIndex, u32 routeDistance,
                           RomCurveDef* candidatePoint) {
    int pointCount;
    PathSearchNode* newNode;
    int foundNodeIndex;
    PathSearchNode* addedNode;
    int visited;
    int pointIndex;
    if (pathSearchNodeMatchesTarget(search, previousNode) != 0) {
        pointIndex = search->nodeCount;
        if (pointIndex != 0xfe) {
            newNode = &search->nodes[search->nodeCount++];
            newNode->point = candidatePoint;
            newNode->routeDistance = routeDistance;
            newNode->parentIndex = (u16)previousNodeIndex;
            newNode->distanceToTarget = (u32)vec3f_distanceSquared(&newNode->point->x, search->targetPosition);
        }
        pathSearchHeapInsert(search, pointIndex, 1);
    }
    foundNodeIndex = pathSearchFindPointNode(search, candidatePoint, &pointCount, &visited);
    if (foundNodeIndex >= 0 && visited == 0) {
        PathSearchNode* existingNode = &search->nodes[foundNodeIndex];
        if (routeDistance < existingNode->routeDistance) {
            u32 newPriority;
            existingNode->parentIndex = previousNodeIndex;
            existingNode->routeDistance = routeDistance;
            newPriority = existingNode->distanceToTarget + existingNode->routeDistance;
            pathSearchHeapChangePriority(search->heap, search->heapSize, foundNodeIndex, newPriority);
        }
    } else if (foundNodeIndex < 0) {
        if (pointCount == 0xfe) {
            addedNode = NULL;
        } else {
            addedNode = &search->nodes[search->nodeCount++];
            addedNode->point = candidatePoint;
            addedNode->routeDistance = routeDistance;
            addedNode->parentIndex = (u16)previousNodeIndex;
            addedNode->distanceToTarget = (u32)vec3f_distanceSquared(&addedNode->point->x, search->targetPosition);
        }
        if (addedNode != NULL) {
            if (addedNode->distanceToTarget > search->closestDistance) {
                u32 newPriority = addedNode->distanceToTarget + addedNode->routeDistance;
                pathSearchHeapInsert(search, pointCount, newPriority);
            } else {
                u32 newPriority;
                if (addedNode->distanceToTarget < search->closestDistance) {
                    search->closestDistance = addedNode->distanceToTarget;
                }
                newPriority = addedNode->distanceToTarget + addedNode->routeDistance;
                pathSearchHeapInsert(search, pointCount, newPriority);
            }
        }
    }
}

void pathSearchExpandNode(PathSearch* search, PathSearchNode* node, int idx) {
    u8 mask;
    char* link;
    RomCurveDef* point;
    RomCurveDef* linked;
    int bit;
    int t;
    point = (RomCurveDef*)node->point;
    if (search->routeFlags != 0) {
        t = point->blockedLinkMask;
    } else {
        t = ~point->blockedLinkMask;
    }
    bit = 0;
    link = (char*)point;
    mask = t;
    for (; bit < 4; bit++) {
        int linkId = ((RomCurveDef*)link)->linkIds[0];
        if (linkId > -1 && (mask & (1 << bit)) != 0) {
            linked = (RomCurveDef*)(*gRomCurveInterface)->getById(linkId);
            if (linked != NULL) {
                switch (linked->type) {
                case ROMCURVE_TYPE_TRICKY: {
                    s16 requiredBit;
                    s16 forbiddenBit;
                    mainGetBit(0x4e2);
                    requiredBit = linked->requiredBit;
                    if (requiredBit == -1 || mainGetBit(requiredBit) != 0) {
                        forbiddenBit = linked->forbiddenBit;
                        if (forbiddenBit == -1 || mainGetBit(forbiddenBit) == 0) {
                            if (!(linked->subtype == ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_A &&
                                  point->subtype == ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B)) {
                                f32 d = vec3f_distanceSquared(&point->x, &linked->x);
                                pathSearchAddNeighbor(search, node, idx, (u32)((f32)node->routeDistance + d), linked);
                            }
                        }
                    }
                    break;
                }
                default:
                    lbl_803DCD08 = (char*)linked;
                    break;
                }
            }
        }
        link += 4;
    }
}
RomCurveDef* pathSearchGetNextPoint(PathSearch* search) {
    RomCurveDef** path;
    int index = search->pathIndex;
    if (index < search->pathCount) {
        path = search->path;
        search->pathIndex++;
        return path[index];
    }
    return NULL;
}

int pathSearchBuildPath(PathSearch* search) {
    PathSearchNode* node;
    u32 cur;
    u32 prev;
    int i;
    int count;
    PathSearchNode* entry;

    prev = search->currentNode;
    node = &search->nodes[prev];
    node->childIndex = 0xff;
    while ((cur = node->parentIndex) != 0xff) {
        node = &search->nodes[cur];
        node->childIndex = prev;
        prev = cur;
    }
    if (node->childIndex == 0xff) {
        entry = NULL;
    } else {
        entry = &search->nodes[node->childIndex];
    }
    count = 0;
    i = 0;
    while (entry != NULL) {
        *(RomCurveDef**)((char*)search->path + i) = entry->point;
        i += sizeof(RomCurveDef*);
        count++;
        if (count >= 100) {
            entry = NULL;
        } else if (entry->childIndex == 0xff) {
            entry = NULL;
        } else {
            entry = &search->nodes[entry->childIndex];
        }
    }
    search->pathCount = count;
    search->pathIndex = 0;
    return count;
}

int pathSearchStep(PathSearch* search, u32 maxSteps) {
    int stepsRemaining;
    PathSearch* q = (PathSearch*)(int)search;
    int idx;
    int done;
    int result;
    PathSearchNode* elem;
    PathHeapEntry* heap;
    stepsRemaining = maxSteps;
    done = 0;
    result = PATH_SEARCH_PENDING;
    while (done == 0 && stepsRemaining != 0) {
        heap = q->heap;
        if (q->heapSize == 0) {
            idx = -1;
        } else {
            idx = heap[1].nodeIndex;
            heap[1].priority = heap[q->heapSize].priority;
            heap[1].nodeIndex = heap[q->heapSize--].nodeIndex;
            pathSearchHeapSiftDown(heap, q->heapSize, 1);
        }
        if (idx >= 0) {
            elem = &q->nodes[idx];
            q->currentNode = idx;
            if (pathSearchNodeMatchesTarget(q, elem) != 0) {
                done = 1;
                result = PATH_SEARCH_REACHED_TARGET;
            } else {
                elem->visited = 1;
                pathSearchExpandNode(q, elem, idx);
            }
        } else {
            done = 1;
            result = PATH_SEARCH_EXHAUSTED;
        }
        stepsRemaining--;
    }
    return result;
}

int pathSearchBegin(PathSearch* queue, RomCurveDef* startPoint, f32* targetPosition, int pathId, u32 routeFlags) {
    PathSearchNode* node;
    int nodeCount;

    pathSearchClear(queue);
    queue->startPoint = startPoint;
    queue->targetPosition = targetPosition;
    queue->pathId = pathId;
    queue->routeFlags = routeFlags & 1;
    queue->closestDistance = 10000;
    nodeCount = queue->nodeCount;
    if (nodeCount == 0xfe) {
        node = NULL;
    } else {
        node = &queue->nodes[queue->nodeCount++];
        node->point = startPoint;
        node->routeDistance = 0;
        node->parentIndex = 0xff;
        node->distanceToTarget = (u32)vec3f_distanceSquared(&node->point->x, queue->targetPosition);
    }
    pathSearchHeapInsert(queue, queue->nodeCount - 1, node->distanceToTarget + node->routeDistance);
    return 0;
}

void freeAndNull(void** p) {
    if (*p != NULL) {
        mm_free(*p);
        *p = NULL;
    }
}

void pathSearchInit(PathSearch* search) {
    search->nodes = (PathSearchNode*)mmAlloc(
        0xfe * sizeof(PathSearchNode) + 0xfe * sizeof(PathHeapEntry) + 100 * sizeof(RomCurveDef*), 0x10, 0);
    search->heap = (PathHeapEntry*)&search->nodes[0xfe];
    search->path = (RomCurveDef**)&search->heap[0xfe];
}

void allocSomething32bytes(void) {
    lbl_803DCD10 = mmAlloc(0x20, 0xff, 0);
}
