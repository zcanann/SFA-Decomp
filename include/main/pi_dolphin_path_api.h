#ifndef MAIN_PI_DOLPHIN_PATH_API_H_
#define MAIN_PI_DOLPHIN_PATH_API_H_

#include "global.h"

typedef struct RomCurveDef RomCurveDef;

enum PathSearchLimits {
    PATH_SEARCH_NODE_CAPACITY = 254,
    PATH_SEARCH_PATH_CAPACITY = 100,
    PATH_SEARCH_NO_NODE = 0xFF,
};

typedef enum PathSearchStatus {
    PATH_SEARCH_EXHAUSTED = -1,
    PATH_SEARCH_PENDING = 0,
    PATH_SEARCH_REACHED_TARGET = 1,
} PathSearchStatus;

typedef struct PathSearchNode {
    RomCurveDef* point;
    u32 distanceToTargetSq;
    u32 routeCost; /* accumulated squared segment lengths, quantized on each extension */
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
    PathSearchNode* nodes; /* owns one allocation containing nodes, heap, then path */
    PathHeapEntry* heap;
    RomCurveDef** path;
    f32* targetPosition;
    s32 pathId;
    u32 reserved14;
    RomCurveDef* startPoint;
    s32 currentNode;
    s16 nodeCount;
    s16 heapSize;
    u32 closestDistanceSq;
    u8 reverse; /* requested direction's low bit: 0 forward, 1 backward */
    u8 padding29;
    s16 pathCount;
    s16 pathIndex;
    u16 padding2E;
} PathSearch;

STATIC_ASSERT(sizeof(PathSearchNode) == 0x10);
STATIC_ASSERT(offsetof(PathSearchNode, point) == 0);
STATIC_ASSERT(offsetof(PathSearchNode, distanceToTargetSq) == 4);
STATIC_ASSERT(offsetof(PathSearchNode, routeCost) == 8);
STATIC_ASSERT(offsetof(PathSearchNode, parentIndex) == 0xC);
STATIC_ASSERT(offsetof(PathSearchNode, childIndex) == 0xD);
STATIC_ASSERT(offsetof(PathSearchNode, visited) == 0xE);
STATIC_ASSERT(sizeof(PathHeapEntry) == 0x8);
STATIC_ASSERT(offsetof(PathHeapEntry, priority) == 0);
STATIC_ASSERT(offsetof(PathHeapEntry, nodeIndex) == 4);
STATIC_ASSERT(sizeof(PathSearch) == 0x30);
STATIC_ASSERT(offsetof(PathSearch, nodes) == 0);
STATIC_ASSERT(offsetof(PathSearch, heap) == 4);
STATIC_ASSERT(offsetof(PathSearch, path) == 8);
STATIC_ASSERT(offsetof(PathSearch, nodeCount) == 0x20);
STATIC_ASSERT(offsetof(PathSearch, heapSize) == 0x22);
STATIC_ASSERT(offsetof(PathSearch, reverse) == 0x28);
STATIC_ASSERT(offsetof(PathSearch, pathCount) == 0x2A);
STATIC_ASSERT(offsetof(PathSearch, pathIndex) == 0x2C);
STATIC_ASSERT(PATH_SEARCH_NODE_CAPACITY * sizeof(PathSearchNode) + PATH_SEARCH_NODE_CAPACITY * sizeof(PathHeapEntry) +
                  PATH_SEARCH_PATH_CAPACITY * sizeof(RomCurveDef*) ==
              0x1960);

void pathSearchInit(PathSearch* search);
void pathSearchAddNeighbor(PathSearch* search, PathSearchNode* previousNode, int previousNodeIndex, u32 routeCost,
                           RomCurveDef* candidatePoint);
RomCurveDef* pathSearchGetNextPoint(PathSearch* search);
int pathSearchBuildPath(PathSearch* search);
void pathSearchExpandNode(PathSearch* search, PathSearchNode* node, int idx);
int pathSearchStep(PathSearch* search, u32 maxSteps);
int pathSearchBegin(PathSearch* search, RomCurveDef* startPoint, f32* targetPosition, int pathId, u32 reverse);

#endif /* MAIN_PI_DOLPHIN_PATH_API_H_ */
