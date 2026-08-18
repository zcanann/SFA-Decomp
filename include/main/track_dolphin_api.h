#ifndef MAIN_TRACK_DOLPHIN_API_H_
#define MAIN_TRACK_DOLPHIN_API_H_

#include "types.h"
#include "game/objects/object.h"
#include "main/track_hit_results.h"
#include "main/model_render_instrs_api.h"
#include "main/track_dolphin_map_api.h"

STATIC_ASSERT(offsetof(TrackHitResults, triangleFlags) == 0x58);
STATIC_ASSERT(offsetof(TrackHitResults, objects) == 0x5C);
STATIC_ASSERT(offsetof(TrackHitResults, hitCount) == 0x6C);
STATIC_ASSERT(offsetof(TrackHitResults, hitMask) == 0x6E);

struct Shader;
struct MapBlockData;
enum HitQueryMask
{
    HITQUERY_TEST_OBJECT_HITBOXES = 0x01,  /* also test reset-object hitboxes, not just map triangles */
    /* keep only near-horizontal triangles: trackBuildBlockTriangles drops any
     * triangle whose plane normal Y is within +-0.707 (cos 45deg) of zero */
    HITQUERY_HORIZONTAL_SURFACES_ONLY = 0x04,
    HITQUERY_REUSE_TRIANGLE_BUFFER = 0x10, /* reuse the loaded map-triangle buffer (skip block reload) */
    HITQUERY_SKIP_CULLED_OBJECTS = 0x80,   /* skip objects whose modelInstance flag 0x01000000 is set */
    /* Composite the player's ladder/climb probe issues: floor-like surfaces
     * only, and 0x200 to drop the triangle-group class carrying group flag 8.
     * No 0x01, so map triangles only. The probe narrows the result to normal
     * Y > 0.707 and reads the rung heights, so it selects horizontal surfaces
     * by geometry - there is no climb surface type. */
    HITQUERY_CLIMB_SURFACE = 0x200 | HITQUERY_HORIZONTAL_SURFACES_ONLY,
};

typedef struct ObjModel ObjModel;

int objShadowRender(GameObject* obj, int renderMode, int unused, int frameCount);
int trackIntersectRebuildPending(void);
int trackGetNearestGroundOffsetAndNormal(GameObject* obj, f32 x, f32 y, f32 z, f32* outGroundOffset,
                                         f32* outNormal, int queryMask);
int trackGetNearestGroundOffset(GameObject* obj, f32 x, f32 y, f32 z, f32* outGroundOffset, int queryMask);
int trackGetHeight(GameObject* obj, f32 x, f32 y, f32 z, TrackGroundHit*** hitsOut, int mode, int queryMask);
int trackGetIntersect(GameObject* contactSource, f32* startPoints, f32* endPoints, int pointCount, void* results,
                        int flags);
void hitDetect_calcSweptSphereBounds(TrackQueryBounds* boundsOut, f32* startPoints, f32* endPoints, f32* radii,
                                     int pointCount);
void trackIntersectBroadphase(GameObject* obj, TrackQueryBounds* bounds, u32 mask, int flags);
void trackSetLinesEnabledByParam(int matchValue, GameObject* obj, int flag);
void playerShadowSetPositionOverride(GameObject* obj, f32 x, f32 y, f32 z);
void Obj_SetParent(GameObject* obj, GameObject* newParent, int updateLocalTransform);
void playerShadowClearPositionOverride(GameObject* obj);
int shadowInit(GameObject* obj, u32 arena, int flags);
void objShadowInvalidate(GameObject* obj);
void shadowVolumesSetDirty(s32 dirty);
void getSunFlareScissorRect(int* outX, int* outY, int* outWidth, int* outHeight);
void trackGetGridOrigin(int** outOrigin);
void trackGetTriangleBuffer(int* outCount, int* outTable);
void trackInitCollisionBuffers(void);
void trackIntersect(void);
void mapBlockRender_setVtxDcrs(u8 doSetup, struct MapBlockData* block, struct Shader* shader,
                               ModelRenderInstrsState* state);
void initTextures(void);
void mapClearBlockEdgeFlags(void);
void* mapBlockGetPolygon(MapBlockData* obj, int idx);
void mapBlockGpuRecoveryHook(void);
void* mapBlockGetUnused00Value(struct MapBlockData* block);
struct MapBlockData* MapBlock_loadFromFile(int blockId);
void setMapBlockFlag(void);
void trackTickDynamicSlotCooldowns(void);
void setupToRenderMapBlock(struct MapBlockData* block, void* posMtx);
void renderMapBlock(struct MapBlockData* block, u8 type);
void shadowBeginFrame(void);
void shadowVolumeBeginFrame(void);
void trackInvalidateDynamicSlotsForObject(GameObject* target);
void objDrawGroundShadow(GameObject* obj, ObjModel* model);
int findSurfaceInYRange(GameObject* obj, f32 x, f32 lo, f32 z, f32 hi, f32* outSurfaceY,
                        GameObject** outSurfaceObj);
void renderGlows(void);
void MapBlock_init(struct MapBlockData* block);
void MapBlock_initHits(struct MapBlockData* block, int index);
int mapBlockCountTrianglesByType(struct MapBlockData* block, int type);
void buildShadowVolumeBox(f32* direction, f32* out, f32 lowerScale);
int trackGetHeightAboveGround(GameObject* obj, f32 x, f32 y, f32 z, f32* outDepth, int queryMask);
extern int gIntersectLinePool;
extern f32* gIntersectPoints;

#endif /* MAIN_TRACK_DOLPHIN_API_H_ */
