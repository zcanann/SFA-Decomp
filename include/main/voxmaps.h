#ifndef MAIN_VOXMAPS_H_
#define MAIN_VOXMAPS_H_

#include "ghidra_import.h"
#include "main/curve.h"

typedef struct VoxMapSlotOrigin {
    u16 gridX;
    u16 gridZ;
} VoxMapSlotOrigin;

typedef struct VoxMaps {
    VoxMapSlotOrigin slotOrigin[6];
    int timer[6];
    int blockId[6];
    int blockOriginWorldX;
    int blockOriginWorldZ;
    int blockOriginGridX;
    int blockOriginGridZ;
    int f58;
    void* mapBuffer[6];
} VoxMaps;

typedef struct VoxPos {
    s16 x;
    s16 y;
    s16 z;
} VoxPos;

typedef struct VoxBlock {
    u8 pad0[6];
    s16 f6;
    s8 f8;
    s8 f9;
} VoxBlock;

typedef struct VoxActiveMap {
    u8 pad00[4];
    int minY;
    u8 pad08[4];
    int maxY;
    u8 pad10[4];
    int* nodeBase;
    u8 pad18[4];
    u8* header;
    u8 pad20[4];
    u8* bitmap;
} VoxActiveMap;

typedef struct VoxState {
    int unk00;
    int unk04;
    int originX;
    int originZ;
    VoxActiveMap* activeMap;
} VoxState;

typedef struct VoxMapFile {
    u8 pad00[0x14];
    int f14;
    int f18;
    int f1c;
    int f20;
    int f24;
    int f28;
} VoxMapFile;

typedef struct VoxBoxArg {
    s16 x;
    s16 z;
    s16 y;
    s16 pad6;
    u16 cost;
} VoxBoxArg;

typedef struct RouteNode {
    s16 x;
    s16 z;
    s16 y;
    u16 hCost;
    u16 gCost;
    u8 parentDir;
    u8 parentIdx;
    u8 flag;
    u8 unkD;
} RouteNode;

typedef struct RouteState {
    RouteNode* nodes;
    CurveHeapNode* queue;
    f32* pathPoints;
    s16 tgtX;
    s16 tgtZ;
    s16 tgtY;
    s16 startX;
    s16 startZ;
    s16 startY;
    int cur;
    s16 nodeCount;
    s16 queueCount;
    s16 pathCount;
    s16 pad22;
    s16 minHCost;
    u8 mode26;
    u8 pad27;
} RouteState;

typedef struct RouteNav {
    f32 destPos[3];
    f32 curPos[3];
    f32 tgtPos[3];
    u8 navState;
    u8 flag25;
    u8 maxIters;
    u8 budget;
} RouteNav;

extern int gVoxMapsSlotTimers[];
extern u32 gVoxMapsTransformObj;
extern VoxMaps gVoxMaps;
extern u8 gVoxMapsSlotInUse[8];
extern int* gVoxMapsMapList;
extern int gVoxMapsMaxMapIndex;
extern void* gVoxMapsScratchBuffer;
extern void* gVoxMapsScratchBufferPtr;
extern void* gVoxMapsLargeTextures[2];
extern void* gVoxMapsSmallTextures[2];
extern int gMapBlockOriginWorldX;
extern int gMapBlockOriginWorldZ;
extern f32 gVoxMapsBlockWorldSize;
extern VoxState gVoxMapsRouteState;
extern char sVoxmapsRouteNodesListOverflow[];
extern f32 gVoxMapsHCostScale;
extern char sVoxMapsDebugStrings[];

int* voxmaps_getRouteNode(u8* header, int* nodeBase, u8* bitmap, int tileX, int ySlot, int tileZ);
void voxmaps_freeRouteWork(void** work);
void voxmaps_allocRouteWork(void** work);
void voxmaps_updateTimers(void);
void voxmaps_gridToWorld(f32* out, s16* grid);
void voxmaps_worldToGrid(f32* in, s16* out);
void voxmaps_resetLoadedMaps(void);
void voxmaps_initialise(void);
int* voxmaps_updateActiveMap(VoxPos* obj);
int voxmaps_traceLine(VoxPos* start, VoxPos* end, VoxPos* coordOut, u8* occOut, u8 skipFirst);
void fn_800118EC(int state, VoxBoxArg* box, int parentDir);
void voxmapsFn_80010ff4(RouteState* state, VoxBoxArg* srcBox, int parentDir, u16 count, s16* box);
int voxmaps_processRouteQueue(RouteState* state, int count);
int voxmaps_updateRoutePath(RouteNav* nav, RouteState* state);
int fn_80011EB0(RouteState* state, int count);
void loadVoxMaps(int handle, int* outCount, int* outSize);


#endif /* MAIN_VOXMAPS_H_ */
