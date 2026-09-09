#ifndef MAIN_TRACK_DOLPHIN_H_
#define MAIN_TRACK_DOLPHIN_H_

#include "types.h"
#include "game/objects/object.h"
#include "main/vec_types.h"

typedef struct TrackBlockDescriptor {
    void* object;
    s16 firstTriangle;
    u8 pad06[2];
    void* currentMatrix;
    void* currentCollisionMatrix;
    void* alternateMatrix;
    void* alternateCollisionMatrix;
} TrackBlockDescriptor;

/* One edge sweep packet: endpoints, unit direction, and sphere dimensions. */
typedef struct TrackSphereSweepEdge {
    f32 start[3];
    f32 end[3];
    f32 direction[3];
    f32 radius;
    f32 radiusSquared;
    f32 length;
} TrackSphereSweepEdge;

STATIC_ASSERT(sizeof(TrackSphereSweepEdge) == 0x30);
STATIC_ASSERT(offsetof(TrackSphereSweepEdge, start) == 0x00);
STATIC_ASSERT(offsetof(TrackSphereSweepEdge, end) == 0x0C);
STATIC_ASSERT(offsetof(TrackSphereSweepEdge, direction) == 0x18);
STATIC_ASSERT(offsetof(TrackSphereSweepEdge, radius) == 0x24);
STATIC_ASSERT(offsetof(TrackSphereSweepEdge, radiusSquared) == 0x28);
STATIC_ASSERT(offsetof(TrackSphereSweepEdge, length) == 0x2C);

typedef struct TrackShadowTriangle {
    Vec3f normal;
    f32 planeDistance;
    s8 flags;
    u8 pad11[3];
} TrackShadowTriangle;

/* TrackTriangle -- the 0x4c-byte collision triangle record packed into
 * gTrackTriangleBuffer.  Plane and edge-plane normals are prebaked f32;
 * vertex coordinates are stored as s16 triplets grouped by axis
 * (x0 x1 x2 / y0 y1 y2 / z0 z1 z2), which the hit-detect code reads both
 * by field and as an s16 index off the record base. */
typedef struct TrackTriangle {
    f32 planeD;           /* 0x00 plane equation constant */
    f32 planeN[3];        /* 0x04 plane normal xyz */
    s16 vx[3];            /* 0x10 vertex x coords */
    s16 vy[3];            /* 0x16 vertex y coords */
    s16 vz[3];            /* 0x1c vertex z coords */
    u8 pad22[2];          /* 0x22 */
    Vec3f edgeNormals[3]; /* 0x24 outward normals, one per triangle edge */
    u8 surfaceType;       /* 0x48 copied into intersect-line records */
    s8 flags;             /* 0x49 0x10 = disabled, 0x4 = force */
    u8 minMaxY;           /* 0x4a lo/hi nibble: s16 index (base 0xb) of min/max height */
    u8 edgeOutBits;       /* 0x4b per-edge outside bits from last query */
} TrackTriangle;

STATIC_ASSERT(sizeof(TrackTriangle) == 0x4C);
STATIC_ASSERT(offsetof(TrackTriangle, planeN) == 0x04);
STATIC_ASSERT(offsetof(TrackTriangle, vx) == 0x10);
STATIC_ASSERT(offsetof(TrackTriangle, vy) == 0x16);
STATIC_ASSERT(offsetof(TrackTriangle, vz) == 0x1C);
STATIC_ASSERT(offsetof(TrackTriangle, edgeNormals[0]) == 0x24);
STATIC_ASSERT(offsetof(TrackTriangle, edgeNormals[1]) == 0x30);
STATIC_ASSERT(offsetof(TrackTriangle, edgeNormals[2]) == 0x3C);
STATIC_ASSERT(offsetof(TrackTriangle, flags) == 0x49);
STATIC_ASSERT(sizeof(TrackBlockDescriptor) == 0x18);
STATIC_ASSERT(offsetof(TrackBlockDescriptor, firstTriangle) == 4);
STATIC_ASSERT(offsetof(TrackBlockDescriptor, currentCollisionMatrix) == 0x0C);
STATIC_ASSERT(sizeof(TrackShadowTriangle) == 0x14);

int trackSweepSphereAgainstEdge(TrackSphereSweepEdge* edge, f32* rayOrigin, f32* rayDirection, f32 maxDistance,
                                f32* hitPointOut, f32* planeOut, f32 unusedClearance, f32* hitDistanceOut,
                                f32 unusedEpsilon);

TrackBlockDescriptor* trackGetBlockDescriptors(u32* outCount);

void trackDolphin_buildSweptBounds(u32* boundsOut, float* startPoints, float* endPoints, float* radii, int pointCount);

/* extern-cleanup: defining-file public prototypes */
int collectShadowTrackTriangles(GameObject* obj, TrackTriangle* triangles, TrackShadowTriangle* planesOut,
                                Vec3f* verticesOut, int unusedTriangleCount, f32 offX, f32 offZ, int unusedRenderMode,
                                int kindSelector);
void objDrawShadowCasterMesh(Vec3f* vertices, ObjModelState* modelState, GameObject* obj, int triangleCount,
                             void* unusedDrawScratch, void* unusedBounds, f32 unusedYOffset);
void trackCollectGroundHits(struct TrackTriangle* triStart, struct TrackTriangle* triEnd,
                            struct TrackBlockDescriptor* desc, f32 qx, f32 qz, int allowDown);
#endif /* MAIN_TRACK_DOLPHIN_H_ */
