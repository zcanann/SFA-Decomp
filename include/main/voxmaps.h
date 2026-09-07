#ifndef MAIN_VOXMAPS_H_
#define MAIN_VOXMAPS_H_

#include "global.h"

#define VOXMAP_SLOT_COUNT 6

struct CurveHeapNode;
struct GameObject;
typedef struct Texture Texture;

typedef struct VoxMapSlotOrigin {
    s16 gridX;
    s16 gridZ;
} VoxMapSlotOrigin;

/* Each occupied tile stores four rows of four packed two-bit cells. */
typedef struct VoxMapNode {
    u8 rows[4];
} VoxMapNode;

STATIC_ASSERT(sizeof(VoxMapNode) == 4);

typedef struct VoxMapFile {
    u8 pad00[4];
    int minY;
    u8 pad08[4];
    int maxY;
    u8 pad10[4];
    VoxMapNode* nodeBase;
    int f18;
    u8* rowCounts;
    int f20;
    u8* bitmap;
    int f28;
} VoxMapFile;

STATIC_ASSERT(offsetof(VoxMapFile, nodeBase) == 0x14);
STATIC_ASSERT(offsetof(VoxMapFile, rowCounts) == 0x1c);
STATIC_ASSERT(offsetof(VoxMapFile, bitmap) == 0x24);
STATIC_ASSERT(sizeof(VoxMapFile) == 0x2c);

typedef struct VoxState {
    int blockOriginWorld[2];
    int blockOriginGrid[2];
    VoxMapFile* activeMap;
} VoxState;

STATIC_ASSERT(sizeof(VoxState) == 0x14);
STATIC_ASSERT(offsetof(VoxState, blockOriginGrid) == 0x08);
STATIC_ASSERT(offsetof(VoxState, activeMap) == 0x10);

typedef struct VoxPos {
    s16 x;
    s16 y;
    s16 z;
} VoxPos;

typedef struct RouteNode {
    s16 x;
    s16 y;
    s16 z;
    u16 hCost;
    u16 gCost;
    u8 parentNodeIndex;
    u8 nextNodeIndex;
    u8 expanded;
    u8 unkD;
} RouteNode;

STATIC_ASSERT(offsetof(RouteNode, gCost) == 0x8);
STATIC_ASSERT(offsetof(RouteNode, parentNodeIndex) == 0xa);
STATIC_ASSERT(offsetof(RouteNode, nextNodeIndex) == 0xb);
STATIC_ASSERT(offsetof(RouteNode, expanded) == 0xc);
STATIC_ASSERT(sizeof(RouteNode) == 0xe);

typedef struct RouteState {
    RouteNode* nodes;
    struct CurveHeapNode* queue;
    f32* pathPoints;
    s16 tgtX;
    s16 tgtY;
    s16 tgtZ;
    s16 startX;
    s16 startY;
    s16 startZ;
    int currentNodeIndex;
    s16 nodeCount;
    s16 queueCount;
    s16 pathCount;
    s16 pad22;
    s16 minHCost;
    u8 mode26;
    u8 pad27;
} RouteState;

STATIC_ASSERT(offsetof(RouteState, currentNodeIndex) == 0x18);
STATIC_ASSERT(offsetof(RouteState, nodeCount) == 0x1c);
STATIC_ASSERT(offsetof(RouteState, queueCount) == 0x1e);
STATIC_ASSERT(sizeof(RouteState) == 0x28);

typedef struct RouteNav {
    f32 startPos[3];
    f32 goalPos[3];
    f32 waypointPos[3];
    u8 searchIteration;
    u8 useDirectSteering;
    u8 maxSearchIterations;
    u8 nodesPerUpdate;
} RouteNav;

STATIC_ASSERT(offsetof(RouteNav, startPos) == 0);
STATIC_ASSERT(offsetof(RouteNav, goalPos) == 0xc);
STATIC_ASSERT(offsetof(RouteNav, waypointPos) == 0x18);
STATIC_ASSERT(offsetof(RouteNav, searchIteration) == 0x24);
STATIC_ASSERT(offsetof(RouteNav, useDirectSteering) == 0x25);
STATIC_ASSERT(offsetof(RouteNav, maxSearchIterations) == 0x26);
STATIC_ASSERT(offsetof(RouteNav, nodesPerUpdate) == 0x27);
STATIC_ASSERT(sizeof(RouteNav) == 0x28);

extern struct GameObject* gVoxMapsTransformObj;
extern VoxMapFile* gVoxMapsBuffers[VOXMAP_SLOT_COUNT];
extern VoxState gVoxMapsActiveState;
extern int gVoxMapsBlockIds[VOXMAP_SLOT_COUNT];
extern int gVoxMapsSlotAges[VOXMAP_SLOT_COUNT];
extern VoxMapSlotOrigin gVoxMapsSlotOrigins[VOXMAP_SLOT_COUNT];
extern u8 gVoxMapsSlotInUse[8];
extern int* gVoxMapsMapList;
extern int gVoxMapsMaxMapIndex;
extern u8* gVoxMapsScratchBuffer;
extern u8* gVoxMapsScratchBufferPtr;
extern Texture* gVoxMapsLargeTextures[2];
extern Texture* gVoxMapsSmallTextures[2];
extern int gMapBlockOriginWorldX;
extern int gMapBlockOriginWorldZ;
extern char sVoxmapsRouteNodesListOverflow[];
extern char sVoxMapsDebugStrings[];

u8* voxmaps_getRouteNode(u8* rowCounts, VoxMapNode* nodeBase, u8* bitmap, int tileX, int ySlot, int tileZ);
void voxmaps_freeRouteWork(RouteState* state);
void voxmaps_allocRouteWork(RouteState* state);
void voxmaps_updateTimers(void);
void voxmaps_gridToWorld(f32* out, s16* grid);
void voxmaps_worldToGrid(f32* in, s16* out);
void voxmaps_resetLoadedMaps(void);
void voxmaps_initialise(void);
int* voxmaps_updateActiveMap(VoxPos* obj);
int voxmaps_traceLine(VoxPos* start, VoxPos* end, VoxPos* coordOut, u8* occOut, u8 skipFirst);
int voxmaps_traceWorldLine(void* startPos, void* endPos);
void voxmaps_traceScaledVectorEnd(f32* out, void* origin, f32* dir, f32 scale);
void voxmaps_expandRouteNeighbors(RouteState* state, RouteNode* parentNode, int parentNodeIndex);
void voxmaps_visitRouteNeighbor(RouteState* state, RouteNode* parentNode, int parentNodeIndex, u16 count, s16* box);
int voxmaps_processRouteQueue(RouteState* state, int count);
int voxmaps_updateRoutePath(RouteNav* nav, RouteState* state);
int voxmaps_buildRouteWaypoints(RouteState* state, int maxPathPoints);
void loadVoxMaps(int handle, int* outCount, int* outSize);
VoxMapFile* voxLoadVoxMapActual(int mapArg, int slot, int b9, int b8);
int voxmaps_traceTraversableRoute(s16* dest, s16* start, s16* lastReachableOut);

#endif /* MAIN_VOXMAPS_H_ */
