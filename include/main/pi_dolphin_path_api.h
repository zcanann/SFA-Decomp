#ifndef MAIN_PI_DOLPHIN_PATH_API_H_
#define MAIN_PI_DOLPHIN_PATH_API_H_

#include "global.h"

typedef struct RomCurveDef RomCurveDef;

typedef enum PathSearchStatus {
    PATH_SEARCH_EXHAUSTED = -1,
    PATH_SEARCH_PENDING = 0,
    PATH_SEARCH_REACHED_TARGET = 1,
} PathSearchStatus;

typedef struct PathSearchNode {
    RomCurveDef* point;
    u32 distanceToTarget;
    u32 routeDistance;
    u8 parentIndex;
    u8 childIndex;
    u8 visited;
    u8 padding;
} PathSearchNode;

typedef struct PathHeapEntry {
    u32 priority;
    u16 nodeIndex;
    u16 padding;
} PathHeapEntry;

typedef struct PathSearch {
    PathSearchNode* nodes;
    PathHeapEntry* heap;
    RomCurveDef** path;
    f32* targetPosition;
    s32 pathId;
    u32 reserved14;
    RomCurveDef* startPoint;
    s32 currentNode;
    s16 nodeCount;
    s16 heapSize;
    u32 closestDistance;
    u8 routeFlags;
    u8 padding29;
    s16 pathCount;
    s16 pathIndex;
    u16 padding2E;
} PathSearch;

STATIC_ASSERT(sizeof(PathSearchNode) == 0x10);
STATIC_ASSERT(sizeof(PathHeapEntry) == 0x8);
STATIC_ASSERT(sizeof(PathSearch) == 0x30);

void pathSearchInit(PathSearch* search);
void pathSearchAddNeighbor(PathSearch* search, PathSearchNode* previousNode, int previousNodeIndex, u32 routeDistance,
                           RomCurveDef* candidatePoint);
RomCurveDef* pathSearchGetNextPoint(PathSearch* search);
int pathSearchBuildPath(PathSearch* search);
void pathSearchExpandNode(PathSearch* search, PathSearchNode* node, int idx);
int pathSearchStep(PathSearch* search, u32 maxSteps);
int pathSearchBegin(PathSearch* search, RomCurveDef* startPoint, f32* targetPosition, int pathId, u32 routeFlags);

#endif /* MAIN_PI_DOLPHIN_PATH_API_H_ */
