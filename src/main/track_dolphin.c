#define OBJHITS_STATE_INDEX_S8
#define TEX_SETSHADER_U8
#include "main/map_block.h"
#include "main/texture.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/hud_visibility_api.h"
#include "main/lightmap_api.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frustum.h"
#include "main/asset_load.h"
#include "game/objects/object.h"
#include "main/gameloop_api.h"
#include "sys/objects.h"
#include "main/mm.h"
#include "main/model_light.h"
#include "main/model.h"
#include "main/model_render_instrs_api.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#undef OBJHITS_STATE_INDEX_S8
#include "main/objtype.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/os/OSFastCast.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "main/camera.h"
#include "main/sky_state.h"
#include "main/track_dolphin.h"
#include "main/track_dolphin_api.h"
#include "main/track_dolphin_shadow_api.h"
#include "main/newshadows_shadow_api.h"
#define TRACK_BBOX_FLAGS_S8
#define TRACK_BBOX_MASK_TYPE  s8
#define TRACK_BBOX_ARG10_TYPE s8
#include "main/track_bbox_api.h"
#undef TRACK_BBOX_ARG10_TYPE
#undef TRACK_BBOX_MASK_TYPE
#undef TRACK_BBOX_FLAGS_S8
#include "main/dll/player_api.h"
#include "main/pause_menu_api.h"
#include "main/pi_dolphin.h"
#include "dolphin/os/OSCache.h"
#include "main/voxmaps.h"
#include "track/intersect_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/objmodel.h"
#include "main/newshadows.h"
#include "main/sky.h"
#include "main/newshadows_texture_api.h"
#include "main/acosf_api.h"
#include "main/tex_dolphin.h"
#include "string.h"

typedef struct MapDynamicSlot MapDynamicSlot;
typedef struct TrackTriangle TrackTriangle;

u32 gTrackTriangleBufferEnd;
s16 gTrackTriangleCount;
u8 gActiveTrackBlockCount;
TrackGroundHit* gTrackGroundHitWriteCursor;
TrackGroundHit** gTrackGroundHitPtrs;
s8 gTrackGroundHitCount;
s16 gIntersectLineCount;
s16 gIntersectPointCount;
f32 gIntersectSweepHitTime;
f32 gTrackResolvePushX;
f32 gTrackResolvePushZ;
u8 gIntersectRebuildRequested;
u8 mapBlockFlag;
u8 gIntersectRebuildCooldown;
u8 gTrackSweepHitCount;
MapDynamicSlot* gMapDynamicSlots;
u8 gIntersectLineTableReady;
u32 gIntersectLineSortOrderBuffer;
int gIntersectLineIndexTable;
f32* gIntersectPoints;
int gIntersectLinePool;
TrackTriangle* gTrackTriangleBuffer;

f32 gTrackCollisionEpsilon = 0.01f;

/* TrackTriangle -- the 0x4c-byte collision triangle record packed into
 * gTrackTriangleBuffer.  Plane and edge-plane normals are prebaked f32;
 * vertex coordinates are stored as s16 triplets grouped by axis
 * (x0 x1 x2 / y0 y1 y2 / z0 z1 z2), which the hit-detect code reads both
 * by field and as an s16 index off the record base. */
struct TrackTriangle {
    f32 planeD;     /* 0x00 plane equation constant */
    f32 planeN[3];  /* 0x04 plane normal xyz */
    s16 vx[3];      /* 0x10 vertex x coords */
    s16 vy[3];      /* 0x16 vertex y coords */
    s16 vz[3];      /* 0x1c vertex z coords */
    u8 pad22[2];    /* 0x22 */
    f32 edgeN0[3];  /* 0x24 edge 0 outward normal */
    f32 edgeN1[3];  /* 0x30 edge 1 outward normal */
    f32 edgeN2[3];  /* 0x3c edge 2 outward normal */
    u8 surfaceType; /* 0x48 copied into intersect-line records */
    s8 flags;       /* 0x49 0x10 = disabled, 0x4 = force */
    u8 minMaxY;     /* 0x4a lo/hi nibble: s16 index (base 0xb) of min/max height */
    u8 edgeOutBits; /* 0x4b per-edge outside bits from last query */
};

struct MapDynamicSlot {
    GameObject* owner;
    GameObject* target;
    Vec3f cachedLocalEnd;
    u8 cooldown;
    u8 querySlot;
    u8 pad16[2];
};

STATIC_ASSERT(sizeof(MapDynamicSlot) == 0x18);
STATIC_ASSERT(offsetof(MapDynamicSlot, cachedLocalEnd) == 0x08);
STATIC_ASSERT(offsetof(MapDynamicSlot, cooldown) == 0x14);
STATIC_ASSERT(offsetof(MapDynamicSlot, querySlot) == 0x15);

/* IntersectLine -- 0x10-byte water/track intersection line record built into
 * the scratch pool at gIntersectLinePool (cap 0x5dc) and later compacted into the
 * owning object's sorted table.  kind's low 6 bits are the sort/group key;
 * a kind of 0x14 marks a consumed scratch entry. */
typedef struct IntersectLine {
    u8 end0;     /* 0x0 per-endpoint byte from the source segment */
    u8 end1;     /* 0x1 */
    u8 flags;    /* 0x2 bit 0x10 is toggled on import */
    s8 kind;     /* 0x3 low 6 bits group key; 0x14 = consumed */
    s16 pt[2];   /* 0x4 indices into the shared point pool */
    s16 adj[2];  /* 0x8 neighbour line ids sharing pt[0]/pt[1] */
    s16 param;   /* 0xc s16 payload from the source segment */
    u8 pad0E[2]; /* 0xe */
} IntersectLine;

struct IntersectModLineObject {
    u8 pad00[0x30];
    MapHitLine* sourceLines; /* 0x30 */
    IntersectLine* lines;    /* 0x34 */
    u8 (*groupRanges)[2];    /* 0x38 */
    f32* points;             /* 0x3c */
    u8 pad40[0x1c];
    u8 sourceLineCount; /* 0x5c */
};

#define MAP_DYNAMIC_SLOT_COUNT 64

int trackBuildBlockTriangles(int base, int x0, int y0, int z0, int x1, int y1, int z1, int a, int b);
int trackBuildModelTriangles(int cur, TrackBlockDescriptor* desc, int* model, f32 scale, f32 x0, f32 y0, f32 z0, f32 x1,
                             f32 y1, f32 z1, u8 flags);
int trackGetIntersect2(int mode, void* tri1, void* tri2, f32* startPos, f32* endPos, int count, void* slots,
                       int flagsArg);
int trackSweepCircleAgainstLines(f32* startPos, f32* endPos, f32 radius, int flags, TrackLineIntersectResult* hit,
                                 GameObject* target, s8 lineMask, s8 segment, s8 yTolerance, GameObject* sourceObj);

extern u8 gTrackGridOrigin[0x104];

TrackBlockDescriptor gTrackBlockDescriptors[20];

u32 trackGetPackedSurfaceType(int* obj);

int insertPoint(int val, s16* arr, f32 x, f32 y, f32 z);

char sTrackNoFreeLastLineError[] = "NO FREE LAST LINE\n";

u16 gIntersectSegmentTypeTable[0x212];

char sTrackIntersectFuncOverflowFormat[] = "trackIntersect: FUNC OVERFLOW %d\n";

int findSurfaceInYRange(GameObject* obj, f32 x, f32 lo, f32 z, f32 hi, f32* outSurfaceY, GameObject** outSurfaceObj) {
    TrackGroundHit** arr;
    int n;
    int i;

    if (lo > hi) {
        f32 t = hi;
        hi = lo;
        lo = t;
    }
    n = trackGetHeight(obj, x, lo, z, &arr, 0, HITQUERY_TEST_OBJECT_HITBOXES);
    *outSurfaceY = lo;
    *outSurfaceObj = NULL;
    for (i = 0; i < n; i++) {
        TrackGroundHit* elem = arr[i];
        if ((s8)elem->surfaceType == 14) {
            continue;
        }
        if (lo < elem->height && hi > elem->height) {
            *outSurfaceObj = arr[i]->object;
            *outSurfaceY = arr[i]->height;
            return (arr[i]->normalY < 0.707f) + 1;
        }
    }
    return 0;
}

void Obj_SetParent(GameObject* obj, GameObject* newParent, int updateLocalTransform) {
    GameObject* oldParent;
    ObjHitsPriorityState* hitState;
    int yawSum;
    f32 dirX;
    f32 dirZ;
    u8 dirBuf[16];

    oldParent = (GameObject*)obj->anim.parent;
    if (oldParent == newParent) {
        return;
    }

    if (oldParent != NULL) {
        Obj_BuildTransformMatrices(oldParent);
    }
    if (newParent != NULL) {
        Obj_BuildTransformMatrices(newParent);
    }

    if (obj->anim.classId == 1) {
        playerReparentPreservingWorldTransform(obj, newParent);
        return;
    }

    obj->anim.parent = newParent;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (oldParent != NULL) {
        Obj_TransformLocalPointToWorld(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                       &obj->anim.worldPosX, &obj->anim.worldPosY, &obj->anim.worldPosZ, oldParent);
        Obj_TransformLocalPointToWorld(obj->anim.previousLocalPosX, obj->anim.previousLocalPosY,
                                       obj->anim.previousLocalPosZ, &obj->anim.previousWorldPosX,
                                       &obj->anim.previousWorldPosY, &obj->anim.previousWorldPosZ, oldParent);
        Obj_TransformLocalVectorToWorld(obj->anim.velocityX, 0.0f, obj->anim.velocityZ, &dirX, (f32*)dirBuf, &dirZ,
                                        oldParent);
        yawSum = oldParent->anim.rotX + obj->anim.rotX;
    } else {
        dirX = obj->anim.velocityX;
        dirZ = obj->anim.velocityZ;
        yawSum = obj->anim.rotX;
    }

    if (updateLocalTransform != 0) {
        if (obj->anim.parent != NULL) {
            Obj_TransformWorldPointToLocal(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ,
                                           &obj->anim.localPosX, &obj->anim.localPosY, &obj->anim.localPosZ,
                                           obj->anim.parent);
            Obj_TransformWorldPointToLocal(obj->anim.previousWorldPosX, obj->anim.previousWorldPosY,
                                           obj->anim.previousWorldPosZ, &obj->anim.previousLocalPosX,
                                           &obj->anim.previousLocalPosY, &obj->anim.previousLocalPosZ,
                                           obj->anim.parent);
            Obj_TransformWorldVectorToLocal(dirX, 0.0f, dirZ, &obj->anim.velocityX, (f32*)dirBuf, &obj->anim.velocityZ,
                                            obj->anim.parent);
            yawSum = yawSum - ((GameObject*)obj->anim.parent)->anim.rotX;
            if (yawSum > 0x8000) {
                yawSum -= 0xffff;
            }
            if (yawSum < -0x8000) {
                yawSum += 0xffff;
            }
            obj->anim.rotX = yawSum;
        } else {
            obj->anim.localPosX = obj->anim.worldPosX;
            obj->anim.localPosY = obj->anim.worldPosY;
            obj->anim.localPosZ = obj->anim.worldPosZ;
            obj->anim.previousLocalPosX = obj->anim.previousWorldPosX;
            obj->anim.previousLocalPosY = obj->anim.previousWorldPosY;
            obj->anim.previousLocalPosZ = obj->anim.previousWorldPosZ;
            obj->anim.velocityX = dirX;
            obj->anim.velocityZ = dirZ;
            obj->anim.rotX = yawSum;
        }
    }

    if (hitState != NULL) {
        hitState->localPosX = obj->anim.localPosX;
        hitState->localPosY = obj->anim.localPosY;
        hitState->localPosZ = obj->anim.localPosZ;
        hitState->worldPosX = obj->anim.worldPosX;
        hitState->worldPosY = obj->anim.worldPosY;
        hitState->worldPosZ = obj->anim.worldPosZ;
    }
}

int trackSweepCircleAgainstPoint(f32* x, f32* z, f32 centerX, f32 centerZ, f32 radius, s8 resolveCollision);
int trackResolveSurfacePenetration(f32* a, f32* b, f32* c, f32* p, f32 f1p, f32 y, u8 type);
int trackSweepSphereAgainstEdge(void* tri, f32* rayOrig, f32* rayDir, f32 maxd, f32* out29, f32* outNrm, f32 maxStep,
                                f32* outDist, f32 epsArg);
void* trackGetBlockDescriptors(u32* outVal);

int trackSweepCircleAgainstPoint(f32* x, f32* z, f32 centerX, f32 centerZ, f32 radius, s8 resolveCollision) {
    f32 startDeltaZ, startDeltaX, timeA, startDistanceSq, startX, startZ, moveX, moveZ, quadraticB, negB;
    f32 separation, sqrtDiscriminant, denominator, separationX, timeB, hitTime, hitX, hitZ;
    f32 separationZ, planeOffset, normalX, penetration, discriminant, quadraticC, normalZ;
    f32 motionLengthSq, fourMotionLengthSq;

    if (0.0f == radius) {
        return 0;
    }

    startX = x[0];
    startDeltaX = startX - centerX;
    startDistanceSq = startDeltaX * startDeltaX;
    startZ = z[0];
    startDeltaZ = startZ - centerZ;
    {
        f32 deltaZSq = startDeltaZ * startDeltaZ;
        startDistanceSq += deltaZSq;
    }
    quadraticC = startDistanceSq - radius * radius;
    if (quadraticC < 0.0f) {
        if (resolveCollision != 0) {
            x[1] = startX + gTrackResolvePushX;
            z[1] = z[0] + gTrackResolvePushZ;
        }
        return 0;
    }

    moveX = x[1] - startX;
    moveZ = z[1] - startZ;
    motionLengthSq = moveX * moveX + moveZ * moveZ;
    if (motionLengthSq > 0.0f) {
        quadraticB = 2.0f * (moveX * startDeltaX + moveZ * startDeltaZ);
        fourMotionLengthSq = 4.0f * motionLengthSq;
        discriminant = quadraticB * quadraticB - fourMotionLengthSq * quadraticC;
        if (discriminant >= 0.0f) {
            sqrtDiscriminant = sqrtf(discriminant);
            negB = -quadraticB;
            timeA = negB + sqrtDiscriminant;
            denominator = 2.0f * motionLengthSq;
            timeA /= denominator;
            timeB = (negB - sqrtDiscriminant) / denominator;
            if (timeA < 0.0f) {
                timeA = 10.0f;
            }
            if (timeB < 0.0f) {
                timeB = 10.0f;
            }
            if (timeB < timeA) {
                timeA = timeB;
            }
            hitTime = timeA;
            if (hitTime >= 0.0f && hitTime <= 1.0f) {
                gIntersectSweepHitTime = hitTime;
                if (resolveCollision != 0) {
                    hitX = hitTime * moveX + x[0];
                    hitZ = hitTime * moveZ + z[0];
                    normalX = (hitX - centerX) / radius;
                    normalZ = (hitZ - centerZ) / radius;
                    planeOffset = -(hitX * normalX + hitZ * normalZ);
                    penetration = planeOffset + (normalX * x[1] + normalZ * z[1]);
                    x[1] = x[1] - penetration * normalX;
                    z[1] = z[1] - penetration * normalZ;
                    separation = 0.1f;
                    separationX = separation * normalX;
                    separationZ = separation * normalZ;
                    while (planeOffset + (x[1] * normalX + z[1] * normalZ) < separation) {
                        x[1] += separationX;
                        z[1] += separationZ;
                    }
                }
                return 1;
            }
        }
    }
    return 0;
}

void trackInvalidateDynamicSlotsForObject(GameObject* target) {
    s16 i;
    for (i = 0; i < MAP_DYNAMIC_SLOT_COUNT; i++) {
        MapDynamicSlot* p = &gMapDynamicSlots[i];
        if (p->owner == target) {
            p->cooldown = 0;
        }
    }
}

/* trackIntersect -- rebuild the intersection line table from map blocks when
 * a refresh has been requested. */
/* trackSweepCircleAgainstLines -- sweep a 2D segment (with radius) against the intersection
 * line table, sliding/clipping the end point; fills *hit with the last hit. */
int trackSweepCircleAgainstLines(f32* startPos, f32* endPos, f32 radius, int flags, TrackLineIntersectResult* hit,
                                 GameObject* target, s8 lineMask, s8 segment, s8 yTolerance, GameObject* sourceObj) {
    f32 margin = 200.0f;
    f32 fracs[5];
    f32 dists[5];
    f32 lb[4], la[4], ld[4];
    s16 hits[6];
    f32 posX[2];
    f32 posZ[2];
    s16 m[2];
    int start;
    u8 flag4;
    int i;
    int found;
    int count;
    int end;
    u32 lineIdx;
    int vt, vp;
    s8 lineType;
    s8 flag1;
    s8 flag2;
    f32 dist;
    f32 len, ax2, ay2, az2, bx2, by2, bz2, dx, dz;
    f32 minX, maxX, minZ, maxZ;

    if (target != NULL) {
        if (segment != -1) {
            u8* tbl = target->anim.modelInstance->intersectionSegmentRanges;
            start = tbl[segment * 2];
            end = tbl[segment * 2 + 1];
        } else {
            start = 0;
            end = target->anim.modelInstance->modLineCount;
        }
        lineIdx = 0;
        vt = (int)target->anim.modelInstance->intersectionLines;
        vp = (int)target->anim.modelInstance->intersectionPoints;
        if (target->objectFlags & 0x100) {
            end = 0;
        }
    } else {
        if (segment != -1) {
            int idx = segment * 2;
            start = gIntersectSegmentTypeTable[idx];
            end = gIntersectSegmentTypeTable[idx + 1];
        } else {
            start = 0;
            end = gIntersectLineCount;
        }
        lineIdx = gIntersectLineIndexTable;
        vt = gIntersectLinePool;
        vp = (int)gIntersectPoints;
    }

    flag1 = !(flags & 1);
    flag2 = flags & 2;
    flag4 = flags & 4;

    {
        f32 x1, x0;
        x0 = startPos[0];
        posX[0] = x0;
        posZ[0] = startPos[2];
        x1 = endPos[0];
        posX[1] = x1;
        posZ[1] = endPos[2];
        if (x0 < x1) {
            minX = x0;
            maxX = x1;
        } else {
            minX = x1;
            maxX = x0;
        }
    }
    if (posZ[0] < posZ[1]) {
        minZ = posZ[0];
        maxZ = posZ[1];
    } else {
        minZ = posZ[1];
        maxZ = posZ[0];
    }
    minX -= radius;
    maxX += radius;
    minZ -= radius;
    maxZ += radius;
    minX -= margin;
    maxX += margin;
    minZ -= margin;
    maxZ += margin;

    count = 0;
    found = 1;

    while (found) {
        found = 0;
        for (i = start; i < end; i++) {
            u8* rec;
            int i0, i1;
            s8 lineFlags, kind;
            f32 *va, *vb;
            f32 ha, ylo, hb, yhi;

            dist = -1.0f;
            if (lineIdx != 0) {
                rec = (u8*)(vt + ((s16*)lineIdx)[i] * 0x10);
            } else {
                rec = (u8*)(vt + i * 0x10);
            }
            lineFlags = *(s8*)&((IntersectLine*)rec)->flags;
            if ((lineMask & ~lineFlags) == 0) {
                continue;
            }
            kind = ((IntersectLine*)rec)->kind;
            if (kind & 0x40) {
                continue;
            }
            i0 = ((IntersectLine*)rec)->pt[0];
            i1 = ((IntersectLine*)rec)->pt[1];
            if (kind & 0x80) {
                if (flag4 != 0) {
                    continue;
                }
                lineType = 0;
            } else {
                lineType = 1;
            }
            if (flag2 != 0) {
                lineType = 1;
            }
            va = (f32*)(vp + i0 * 0xc);
            ax2 = va[0];
            ay2 = va[1];
            az2 = va[2];
            vb = (f32*)(vp + i1 * 0xc);
            bx2 = vb[0];
            by2 = vb[1];
            bz2 = vb[2];
            if (ax2 < minX && bx2 < minX) {
                continue;
            }
            if (ax2 > maxX && bx2 > maxX) {
                continue;
            }
            if (az2 < minZ && bz2 < minZ) {
                continue;
            }
            if (az2 > maxZ && bz2 > maxZ) {
                continue;
            }

            ylo = ay2;
            if (by2 < ay2) {
                ylo = by2;
            }
            ylo = ylo - (f32)yTolerance;
            if (lineFlags & 0x80) {
                ha = (f32) * (s16*)rec;
                hb = ha;
            } else {
                ha = (f32)(s8)rec[0];
                hb = (f32)(s8)rec[1];
            }
            {
                f32 ta = ay2 + ha;
                yhi = ta;
                if (by2 + hb > ta) {
                    yhi = by2 + hb;
                }
            }
            yhi = yhi + (f32)yTolerance;
            if (startPos[1] < ylo) {
                continue;
            }
            if (startPos[1] > yhi) {
                continue;
            }

            dx = bx2 - ax2;
            dz = bz2 - az2;
            {
                f32 dd = dx * dx + dz * dz;
                if (0.0f == dd) {
                    continue;
                }
                len = sqrtf(dd);
            }
            dx /= len;
            dz /= len;
            lb[0] = dx;
            la[0] = dz;
            ld[0] = -(dx * ax2 + dz * az2);
            lb[1] = -dx;
            la[1] = -dz;
            ld[1] = -(lb[1] * bx2 + la[1] * bz2);
            lb[2] = -dz;
            la[2] = dx;
            {
                f32 q0 = lb[2] * (2.0f * lb[2] + ax2);
                f32 q1 = la[2] * (2.0f * la[2] + az2);
                ld[2] = -(q0 + q1);
            }
            lb[3] = dz;
            la[3] = -dx;
            {
                f32 q0 = lb[3] * (radius * lb[3] + ax2);
                f32 q1 = la[3] * (radius * la[3] + az2);
                ld[3] = -(q0 + q1);
            }
            gTrackResolvePushX = 0.5f * (lb[3] * radius);
            gTrackResolvePushZ = 0.5f * (la[3] * radius);

            {
                f32 *ap, *bp, *dp;
                s16* mp;
                f32* zp;
                f32* xp;
                int mi;
                int n;
                mi = 0;
                mp = m;
                zp = posZ;
                xp = posX;
                dist = 0.0f;
                do {
                    s16 mb = 1;
                    f32 pz, px;
                    *mp = 0;
                    n = 0;
                    pz = zp[0];
                    px = xp[0];
                    ap = la;
                    bp = lb;
                    dp = ld;
                    for (; n < 4; n++) {
                        if (dp[0] + (px * bp[0] + pz * ap[0]) < dist) {
                            *mp |= mb;
                        }
                        mb = (s16)(mb << 1);
                        ap++;
                        bp++;
                        dp++;
                    }
                    xp[0] = px;
                    zp[0] = pz;
                    mp++;
                    zp++;
                    xp++;
                    mi++;
                } while (mi < 2);
            }
            {
                s16 mx = m[0] ^ m[1];
                s16 ma = m[0] & m[1];
                dist = 1.0f;
                if ((m[0] & 0xc) == 0xc) {
                    if (m[0] & 1) {
                        found = trackSweepCircleAgainstPoint(posX, posZ, ax2, az2, radius, lineType);
                        dist = 0.0f;
                    } else if (m[0] & 2) {
                        found = trackSweepCircleAgainstPoint(posX, posZ, bx2, bz2, radius, lineType);
                        dist = 1.0f;
                    } else if (lineType != 0) {
                        posX[1] += gTrackResolvePushX;
                        posZ[1] += gTrackResolvePushZ;
                    }
                } else if (mx & 0xc) {
                    if (ma & 1) {
                        found = trackSweepCircleAgainstPoint(posX, posZ, ax2, az2, radius, lineType);
                        dist = 0.0f;
                    } else if (ma & 2) {
                        found = trackSweepCircleAgainstPoint(posX, posZ, bx2, bz2, radius, lineType);
                        dist = 1.0f;
                    } else if (m[0] & 4) {
                        f32 sx = posX[1] - posX[0];
                        f32 sz = posZ[1] - posZ[0];
                        f32 t0 = ld[3] + (posX[0] * lb[3] + posZ[0] * la[3]);
                        f32 t1 = ld[3] + (posX[1] * lb[3] + posZ[1] * la[3]);
                        f32 fr, cx, cz;
                        s16 ok;
                        if (t0 != t1) {
                            fr = t0 / (t0 - t1);
                        } else {
                            fr = 0.0f;
                        }
                        cx = sx * fr + posX[0];
                        cz = sz * fr + posZ[0];
                        gIntersectSweepHitTime = fr;
                        ok = 1;
                        if (ld[0] + (cx * lb[0] + cz * la[0]) < 0.0f) {
                            found = trackSweepCircleAgainstPoint(posX, posZ, ax2, az2, radius, lineType);
                            ok = 0;
                            dist = 0.0f;
                        }
                        if (ld[1] + (cx * lb[1] + cz * la[1]) < 0.0f) {
                            found = trackSweepCircleAgainstPoint(posX, posZ, bx2, bz2, radius, lineType);
                            ok = 0;
                            dist = 1.0f;
                        }
                        if (ok != 0) {
                            found = 1;
                            if (lineType != 0) {
                                int j;
                                if (flag1 != 0) {
                                    t1 = ld[3] + (posX[1] * lb[3] + posZ[1] * la[3]);
                                    posX[1] -= t1 * lb[3];
                                    posZ[1] -= t1 * la[3];
                                    j = 0;
                                    while (ld[3] + (posX[1] * lb[3] + posZ[1] * la[3]) < gTrackCollisionEpsilon) {
                                        posX[1] += gTrackCollisionEpsilon * lb[3];
                                        posZ[1] += gTrackCollisionEpsilon * la[3];
                                        j++;
                                        if (j > 0xa) {
                                            posX[1] = posX[0];
                                            posZ[1] = posZ[0];
                                            break;
                                        }
                                    }
                                } else {
                                    posX[1] = cx;
                                    posZ[1] = cz;
                                    j = 0;
                                    while (ld[3] + (posX[1] * lb[3] + posZ[1] * la[3]) < gTrackCollisionEpsilon) {
                                        posX[1] += gTrackCollisionEpsilon * lb[3];
                                        posZ[1] += gTrackCollisionEpsilon * la[3];
                                        j++;
                                        if (j > 0xa) {
                                            posX[1] = posX[0];
                                            posZ[1] = posZ[0];
                                            break;
                                        }
                                    }
                                }
                                {
                                    f32 ddx = posX[1] - ax2;
                                    f32 ddz = posZ[1] - az2;
                                    dist = sqrtf(ddx * ddx + ddz * ddz) / len;
                                }
                            }
                        }
                    }
                }
            }
            if (found) {
                break;
            }
        }
        if (found) {
            hits[count] = i;
            fracs[count] = gIntersectSweepHitTime;
            dists[count] = dist;
            count++;
            if (count > 4) {
                found = 0;
                if (lineType != 0) {
                    posX[1] = posX[0];
                    posZ[1] = posZ[0];
                }
            }
        }
    }

    if (count != 0 && hit != NULL) {
        int pick = count - 1;
        int hi;
        s16* rec2;
        f32 fa, fb;
        f32 *lineStart, *lineEnd;
        f32 dx, dz;
        if (flag1 == 0) {
            pick = 0;
        }
        dx = endPos[0];
        dx -= posX[0];
        dz = endPos[2];
        dz -= posZ[0];
        hit->distance = fracs[0] * sqrtf(dx * dx + dz * dz);
        hit->interpolation = dists[pick];
        hi = hits[pick];
        if (lineIdx != 0) {
            rec2 = (s16*)(vt + *(s16*)(lineIdx + hi * 2) * 0x10);
        } else {
            rec2 = (s16*)(vt + hi * 0x10);
        }
        {
            int j0 = rec2[2];
            int j1 = rec2[3];
            if ((s8) * (u8*)((u8*)rec2 + 2) & 0x80) {
                fa = rec2[0];
                fb = fa;
            } else {
                fa = (f32)(s8) * (u8*)rec2;
                fb = (f32)(s8) * ((u8*)rec2 + 1);
            }
            hit->lineStartX = ((f32*)vp)[j0 * 3];
            lineStart = (f32*)(vp + j0 * 0xc);
            hit->lineStartY = lineStart[1];
            hit->upperY0 = hit->lineStartY + fa;
            hit->lineStartZ = lineStart[2];
            hit->lineEndX = ((f32*)vp)[j1 * 3];
            lineEnd = (f32*)(vp + j1 * 0xc);
            hit->lineEndY = lineEnd[1];
            hit->upperY1 = hit->lineEndY + fb;
            hit->lineEndZ = lineEnd[2];
            hit->surfaceType = (s8)(*((u8*)rec2 + 3) & 0x3f);
            hit->flags = *((u8*)rec2 + 2);
            hit->kind = rec2[6];
            hit->object = target;
            hit->adjacentLine0 = rec2[4];
            hit->adjacentLine1 = rec2[5];
        }
    }
    if (count != 0) {
        gTrackSweepHitCount++;
        count = 1;
        endPos[0] = posX[1];
        endPos[2] = posZ[1];
    }
    return count;
}

int insertPoint(int val, s16* arr, f32 x, f32 y, f32 z) {
    f32* p;
    f32* base;
    int i;
    int n;

    i = 0;
    p = base = gIntersectPoints;
    n = gIntersectPointCount;
    for (; i < n; i++) {
        if (x == p[0] && y == p[1] && z == p[2]) {
            s16* q = arr + 1;
            q[i << 1] = val;
            return i;
        }
        p += 3;
    }
    base[n * 3] = x;
    gIntersectPoints[gIntersectPointCount * 3 + 1] = y;
    gIntersectPoints[gIntersectPointCount * 3 + 2] = z;
    arr[gIntersectPointCount << 1] = val;
    arr[(gIntersectPointCount << 1) + 1] = -1;
    gIntersectPointCount++;
    return gIntersectPointCount - 1;
}

static inline MapDynamicSlot* trackFindDynamicSlot(GameObject* self, GameObject* target, int querySlot) {
    s16 k;
    MapDynamicSlot* entry;

    k = 0;
    do {
        entry = &gMapDynamicSlots[k];
        if (entry->cooldown != 0 && entry->owner == self && entry->target == target &&
            entry->querySlot == (u8)querySlot) {
            entry->cooldown = 0;
            return entry;
        }
        k++;
    } while (k < 0x40);
    return NULL;
}

static inline int trackDynamicSlotEnabled(int querySlot) {
    return (u8)querySlot != 0xff;
}

static inline MapDynamicSlot* trackAllocDynamicSlot(self, target, querySlot)
GameObject* self;
GameObject* target;
u8 querySlot;
{
    s16 k;
    MapDynamicSlot* entry;

    k = 0;
    do {
        entry = &gMapDynamicSlots[k];
        if (entry->cooldown == 0) {
            entry->owner = self;
            entry->target = target;
            entry->querySlot = querySlot;
            entry->cooldown = 2;
            return entry;
        }
        k++;
    } while (k < 0x40);
    debugPrintf(sTrackNoFreeLastLineError);
    return NULL;
}

int trackGetLineIntersect(f32* startPos, f32* endPos, f32 radius, int flags, TrackLineIntersectResult* out,
                          GameObject* self, s8 lineMask, s8 segment, int slot, s8 yTolerance) {
    f32 worldStart[3];
    f32 worldEnd[3];
    f32 localStart[3];
    f32 localEnd[3];
    GameObject** objects;
    int count;
    int i;
    u32 parentAddress;

    gTrackSweepHitCount = 0;
    if (out != NULL) {
        out->surfaceType = -1;
        out->kind = -1;
    }
    parentAddress = (self != NULL) ? (u32)self->anim.parent : 0;
    if (parentAddress != 0) {
        Obj_TransformLocalPointToWorld(startPos[0], startPos[1], startPos[2], &worldStart[0], &worldStart[1],
                                       &worldStart[2], (GameObject*)parentAddress);
        Obj_TransformLocalPointToWorld(endPos[0], endPos[1], endPos[2], &worldEnd[0], &worldEnd[1], &worldEnd[2],
                                       (GameObject*)parentAddress);
    } else {
        memcpy(worldStart, startPos, 0xc);
        memcpy(worldEnd, endPos, 0xc);
    }
    objects = objGetAllOfType(6, &count);
    for (i = 0; i < count; i++) {
        GameObject* target = (GameObject*)objects[i];
        ObjHitsPriorityState* priorityState;
        ModelFileHeader* modelHeader;
        f32 cullRadiusSq;
        f32 dx, dy, dz;
        s8 hit;
        MapDynamicSlot* entry;

        if (target == self) {
            continue;
        }
        if (target->anim.transformMatrixIndex <= -1) {
            continue;
        }
        if (target->anim.modelInstance->intersectionLines == NULL) {
            continue;
        }
        priorityState = (ObjHitsPriorityState*)target->anim.hitReactState;
        if (priorityState != NULL && (priorityState->flags & 1) == 0) {
            continue;
        }
        dx = target->anim.localPosX - worldStart[0];
        dy = target->anim.localPosY - worldStart[1];
        dz = target->anim.localPosZ - worldStart[2];
        modelHeader = target->anim.modelBanks[priorityState->stateIndex]->file;
        cullRadiusSq = (f32)(modelFileHeaderGetCullDistance(modelHeader) + 0x32);
        cullRadiusSq *= cullRadiusSq;
        hit = 0;
        {
            f32 ddy = dy * dy;
            if (ddy + dx * dx + dz * dz < cullRadiusSq) {
                hit = 1;
            }
        }
        if (hit == 0) {
            dx = target->anim.localPosX - worldEnd[0];
            dy = target->anim.localPosY - worldEnd[1];
            dz = target->anim.localPosZ - worldEnd[2];
            {
                f32 ddy = dy * dy;
                if (ddy + dx * dx + dz * dz < cullRadiusSq) {
                    hit = 1;
                }
            }
        }
        if (hit == 0) {
            continue;
        }
        if (trackDynamicSlotEnabled(slot) && (entry = trackFindDynamicSlot(self, target, slot)) != NULL) {
            localStart[0] = entry->cachedLocalEnd.x;
            localStart[1] = entry->cachedLocalEnd.y;
            localStart[2] = entry->cachedLocalEnd.z;
        } else {
            Obj_TransformWorldPointToLocal(worldStart[0], worldStart[1], worldStart[2], &localStart[0], &localStart[1],
                                           &localStart[2], target);
        }
        Obj_TransformWorldPointToLocal(worldEnd[0], worldEnd[1], worldEnd[2], &localEnd[0], &localEnd[1], &localEnd[2],
                                       (GameObject*)(int)target);
        if (trackSweepCircleAgainstLines(localStart, localEnd, radius, flags, out, target, lineMask, segment,
                                         yTolerance, self) != 0) {
            Obj_TransformLocalPointToWorld(localEnd[0], localEnd[1], localEnd[2], &worldEnd[0], &worldEnd[1],
                                           &worldEnd[2], (GameObject*)(int)target);
        }
        if (trackDynamicSlotEnabled(slot)) {
            entry = trackAllocDynamicSlot(self, target, slot);
            if (entry != NULL) {
                entry->cachedLocalEnd.x = localEnd[0];
                entry->cachedLocalEnd.y = localEnd[1];
                entry->cachedLocalEnd.z = localEnd[2];
            }
        }
    }
    trackSweepCircleAgainstLines(worldStart, worldEnd, radius, flags, out, NULL, lineMask, segment, yTolerance, self);
    if (gTrackSweepHitCount != 0 && out != NULL) {
        f32 upperDeltaStart = out->upperY0 - out->lineStartY;
        f32 upperDeltaEnd = out->upperY1 - out->lineEndY;
        f32 len;
        out->sourceNormalX = out->lineEndZ - out->lineStartZ;
        out->sourceNormalY = 0.0f;
        out->sourceNormalZ = out->lineStartX - out->lineEndX;
        {
            f32 sqA = out->sourceNormalX * out->sourceNormalX;
            f32 sqB = out->sourceNormalZ * out->sourceNormalZ;
            len = 1.0f / sqrtf(sqA + sqB);
        }
        out->sourceNormalX *= len;
        out->sourceNormalZ *= len;
        out->sourceNormalW = -(out->sourceNormalX * out->lineStartX + out->sourceNormalZ * out->lineStartZ);
        if (out->object != NULL) {
            Obj_TransformLocalPointToWorld(out->lineStartX, out->lineStartY, out->lineStartZ, &out->lineStartX,
                                           &out->lineStartY, &out->lineStartZ, out->object);
            Obj_TransformLocalPointToWorld(out->lineEndX, out->lineEndY, out->lineEndZ, &out->lineEndX, &out->lineEndY,
                                           &out->lineEndZ, out->object);
        }
        if (parentAddress != 0) {
            Obj_TransformWorldPointToLocal(out->lineStartX, out->lineStartY, out->lineStartZ, &out->lineStartX,
                                           &out->lineStartY, &out->lineStartZ, (GameObject*)parentAddress);
            Obj_TransformWorldPointToLocal(out->lineEndX, out->lineEndY, out->lineEndZ, &out->lineEndX, &out->lineEndY,
                                           &out->lineEndZ, (GameObject*)parentAddress);
        }
        out->normalX = out->lineEndZ - out->lineStartZ;
        out->normalY = 0.0f;
        out->normalZ = out->lineStartX - out->lineEndX;
        {
            f32 sqA = out->normalX * out->normalX;
            f32 sqB = out->normalZ * out->normalZ;
            len = 1.0f / sqrtf(sqA + sqB);
        }
        out->normalX *= len;
        out->normalZ *= len;
        out->upperY0 = out->lineStartY + upperDeltaStart;
        out->upperY1 = out->lineEndY + upperDeltaEnd;
        out->normalW = -(out->normalX * out->lineStartX + out->normalZ * out->lineStartZ);
    }
    if (gTrackSweepHitCount != 0) {
        if (parentAddress != 0) {
            Obj_TransformWorldPointToLocal(worldEnd[0], worldEnd[1], worldEnd[2], &endPos[0], &endPos[1], &endPos[2],
                                           (GameObject*)parentAddress);
        } else {
            memcpy(endPos, worldEnd, 0xc);
        }
    }
    return gTrackSweepHitCount;
}

void intersectModLineBuild(IntersectModLineObject* obj) {
    s16 pointLinks[0xd48];
    IntersectLine* line;
    int lineIndex;
    int sourceLineCount;
    MapHitLine* sourceLine;
    int lineByteOffset;
    int outputLineIndex;
    s16 previousGroup;

    mapBlockFlag = 1;
    gIntersectLineCount = 0;
    gIntersectPointCount = 0;
    sourceLineCount = obj->sourceLineCount;
    for (lineIndex = 0, sourceLine = obj->sourceLines; lineIndex < sourceLineCount; sourceLine++, lineIndex++) {
        int i;
        if (gIntersectLineCount < 0x5dc) {
            line = (IntersectLine*)((u8*)gIntersectLinePool + gIntersectLineCount * 0x10);
            line->end0 = sourceLine->endpointData[0];
            line->end1 = sourceLine->endpointData[1];
            line->kind = sourceLine->kind;
            if ((line->kind & 0x3f) == 0x11) {
                line->kind &= ~0x3f;
                line->kind |= 2;
            }
            line->flags = sourceLine->flags;
            *(s8*)&line->flags ^= 0x10;
            line->param = sourceLine->param;
            for (i = 0; i < 2; i++) {
                f32 x = sourceLine->x[i];
                f32 y = sourceLine->y[i];
                f32 z = sourceLine->z[i];
                if (gIntersectPointCount < 0x6a4) {
                    line->pt[i] = insertPoint(gIntersectLineCount, pointLinks, x, y, z);
                }
            }
            gIntersectLineCount++;
        }
    }
    {
        outputLineIndex = 0;
        lineByteOffset = outputLineIndex;
        for (; outputLineIndex < gIntersectLineCount; lineByteOffset += sizeof(IntersectLine), outputLineIndex++) {
            int pointLinkIndex;
            s16* firstPointLinks;
            s16* secondPointLinks;
            line = (IntersectLine*)((u8*)gIntersectLinePool + lineByteOffset);
            pointLinkIndex = line->pt[0] * 2;
            firstPointLinks = &pointLinks[pointLinkIndex];
            if (firstPointLinks[0] > -1 && firstPointLinks[0] != outputLineIndex) {
                line->adj[0] = firstPointLinks[0];
            } else if (firstPointLinks[1] > -1 && firstPointLinks[1] != outputLineIndex) {
                line->adj[0] = firstPointLinks[1];
            } else {
                line->adj[0] = -1;
            }
            {
                pointLinkIndex = line->pt[1] * 2;
                secondPointLinks = &pointLinks[pointLinkIndex];
            }
            if (secondPointLinks[0] > -1 && secondPointLinks[0] != outputLineIndex) {
                line->adj[1] = secondPointLinks[0];
            } else if (secondPointLinks[1] > -1 && secondPointLinks[1] != outputLineIndex) {
                line->adj[1] = secondPointLinks[1];
            } else {
                line->adj[1] = -1;
            }
        }
    }
    if (gIntersectLineCount * 0x10 + gIntersectPointCount * 0xc + 0x28 == 0) {
        return;
    }
    obj->lines = mmAlloc(gIntersectLineCount * 0x10 + gIntersectPointCount * 0xc + 0x28, 0xffff00ff, 0);
    obj->points = (f32*)((u8*)obj->lines + gIntersectLineCount * 0x10);
    obj->groupRanges = (u8(*)[2])((u8*)obj->points + gIntersectPointCount * 0xc);
    {
        int k;
        for (k = 0; k < 40; k++) {
            (*(u8**)&obj->groupRanges)[k] = 0xff;
        }
    }
    previousGroup = -1;
    for (outputLineIndex = 0; outputLineIndex < gIntersectLineCount; outputLineIndex++) {
        s16 best = 0;
        u8* base;
        int j = 0;
        s16 grp;
        base = (u8*)gIntersectLinePool;
        for (; j < gIntersectLineCount; j++) {
            if (((s8)base[j * 0x10 + 3] & 0x3f) < ((s8)base[best * 0x10 + 3] & 0x3f)) {
                best = j;
            }
        }
        grp = (s16)((s8)base[best * 0x10 + 3] & 0x3f);
        if (grp >= 0x14) {
            grp = 1;
            debugPrintf(sTrackIntersectFuncOverflowFormat, 1);
        }
        if (grp != previousGroup) {
            obj->groupRanges[grp][0] = outputLineIndex;
            if (previousGroup != -1) {
                obj->groupRanges[previousGroup][1] = outputLineIndex;
            }
            previousGroup = grp;
        }
        {
            int m;
            s16 bestLine;
            bestLine = best;
            for (m = 0; m < outputLineIndex; m++) {
                if (obj->lines[m].adj[0] == bestLine) {
                    obj->lines[m].adj[0] = outputLineIndex;
                }
                if (obj->lines[m].adj[1] == bestLine) {
                    obj->lines[m].adj[1] = outputLineIndex;
                }
            }
        }
        {
            s16 bestLine;
            bestLine = best;
            for (lineIndex = 0; lineIndex < gIntersectLineCount; lineIndex++) {
                line = &((IntersectLine*)gIntersectLinePool)[lineIndex];
                if (line->kind != 0x14) {
                    if (bestLine == line->adj[0]) {
                        line->adj[0] = outputLineIndex;
                    }
                    if (bestLine == ((IntersectLine*)gIntersectLinePool)[lineIndex].adj[1]) {
                        ((IntersectLine*)gIntersectLinePool)[lineIndex].adj[1] = outputLineIndex;
                    }
                }
            }
        }
        memcpy(&obj->lines[outputLineIndex], (char*)gIntersectLinePool + best * 0x10, 0x10);
        *(u8*)(gIntersectLinePool + best * 0x10 + 3) = 0x14;
    }
    if (previousGroup != -1) {
        obj->groupRanges[previousGroup][1] = gIntersectLineCount;
    }
    memcpy(obj->points, gIntersectPoints, gIntersectPointCount * 0xc);
    gIntersectLineCount = 0;
    gIntersectPointCount = 0;
}

void trackIntersect(void) {
    s16 counts[0x47];
    s16 edges[0x6a4 * 2];
    s16* sourceCoord;
    u8* linePoint;
    int sourceOffset;
    int blockIndex;
    int rowOffset;
    int sourceIndex;
    int endpoint;
    int gridX, gridZ;
    int layer;
    IntersectLine* line;
    int i;
    int lineOffset;
    u8* lineBytes;
    s16* sortOrder;
    s16 firstLine;
    s16 secondLine;
    int sortIndex;
    int sortComplete;
    s16 previousType, segmentType;
    f32 pointX, pointY, pointZ;
    f32 blockX;
    f32 blockZ;

    gIntersectLineTableReady = 0;
    if (gIntersectRebuildCooldown != 0 && getHudHiddenFrameCount() == 0) {
        gIntersectRebuildCooldown--;
    }
    if ((s8)mapBlockFlag == 1) {
        gIntersectRebuildRequested = 1;
        mapBlockFlag = 0;
        return;
    }
    if ((s8)gIntersectRebuildRequested == 0) {
        return;
    }
    gIntersectRebuildRequested = 0;
    if (getHudHiddenFrameCount() != 0) {
        gIntersectRebuildCooldown = 2;
    }

    for (i = 0; i < 0x47; i++) {
        counts[i] = 0;
    }
    gIntersectLineCount = 0;
    gIntersectPointCount = 0;

    for (layer = 0; layer < 5; layer++) {
        s8* idx = mapGetBlockIdx(layer);
        for (gridZ = 0, rowOffset = 0; gridZ < 0x10; rowOffset += 0x10, gridZ++) {
            gridX = 0;
            blockIndex = rowOffset;
            blockZ = 640.0f * gridZ;
            for (; gridX < 0x10; blockIndex++, gridX++) {
                if (idx[blockIndex] >= 0) {
                    MapBlockData* blk = mapGetBlock(idx[blockIndex]);
                    sourceIndex = 0;
                    sourceOffset = 0;
                    blockX = 640.0f * gridX;
                    for (; sourceIndex < blk->hitCount; sourceOffset += sizeof(MapHitLine), sourceIndex++) {
                        if (gIntersectLineCount < 0x5dc) {
                            MapHitLine* sourceLine = (MapHitLine*)((u8*)blk->hits + sourceOffset);
                            s16* sourcePoints = sourceLine->x;
                            IntersectLine* rec = (IntersectLine*)(gIntersectLinePool + gIntersectLineCount * 0x10);
                            f32 mapOriginX, mapOriginZ;
                            rec->end0 = sourceLine->endpointData[0];
                            rec->end1 = sourceLine->endpointData[1];
                            rec->kind = sourceLine->kind;
                            if ((rec->kind & 0x3f) == 0x11) {
                                rec->kind &= ~0x3f;
                                rec->kind |= 2;
                            }
                            rec->flags = sourceLine->flags;
                            *(s8*)&rec->flags = rec->flags ^ 0x10;
                            rec->param = sourceLine->param;
                            mapOriginX = blockX + playerMapOffsetX;
                            mapOriginZ = blockZ + playerMapOffsetZ;
                            endpoint = 0;
                            sourceCoord = sourcePoints;
                            linePoint = (u8*)rec;
                            for (; endpoint < 2; sourceCoord++, linePoint += 2, endpoint++) {
                                pointX = mapOriginX + sourceCoord[0];
                                pointY = sourceCoord[2];
                                pointZ = sourceCoord[4] + mapOriginZ;
                                if (gIntersectPointCount < 0x6a4) {
                                    *(s16*)(linePoint + 4) =
                                        insertPoint(gIntersectLineCount, edges, pointX, pointY, pointZ);
                                }
                            }
                            counts[rec->kind & 0x3f]++;
                            gIntersectLineCount++;
                        }
                    }
                }
            }
        }
    }

    for (i = 0; i < gIntersectLineCount; i++) {
        int pointIndex;
        s16* pointEdges;
        s16* pointEdges2;
        s16 adjacentLine;

        line = (IntersectLine*)(gIntersectLinePool + i * 16);
        pointIndex = line->pt[0] * 2;
        pointEdges = &edges[pointIndex];
        adjacentLine = pointEdges[0];
        if (adjacentLine > -1 && adjacentLine != i) {
            line->adj[0] = adjacentLine;
        } else {
            adjacentLine = pointEdges[1];
            if (adjacentLine > -1 && adjacentLine != i) {
                line->adj[0] = adjacentLine;
            } else {
                line->adj[0] = -1;
            }
        }
        pointIndex = line->pt[1] * 2;
        pointEdges2 = &edges[pointIndex];
        adjacentLine = pointEdges2[0];
        if (adjacentLine > -1 && adjacentLine != i) {
            line->adj[1] = adjacentLine;
        } else {
            adjacentLine = pointEdges2[1];
            if (adjacentLine > -1 && adjacentLine != i) {
                line->adj[1] = adjacentLine;
            } else {
                line->adj[1] = -1;
            }
        }
    }

    if (gIntersectLineSortOrderBuffer != 0) {
        for (i = 0; i < gIntersectLineCount; i++) {
            *(s16*)(gIntersectLineSortOrderBuffer + i * 2) = i;
        }
        sortComplete = 0;
        while (sortComplete == 0) {
            sortComplete = 1;
            for (sortIndex = 0, lineOffset = sortIndex; sortIndex < gIntersectLineCount - 1;
                 lineOffset += sizeof(s16), sortIndex++) {
                int firstType;

                lineBytes = (u8*)gIntersectLinePool;
                sortOrder = (s16*)(gIntersectLineSortOrderBuffer + lineOffset);
                firstLine = sortOrder[0];
                firstType = (s8)lineBytes[firstLine * sizeof(IntersectLine) + 3] & 0x3f;
                if (firstType < ((s8)lineBytes[(secondLine = sortOrder[1]) * sizeof(IntersectLine) + 3] & 0x3f)) {
                    sortOrder[0] = secondLine;
                    *(s16*)(gIntersectLineSortOrderBuffer + lineOffset + sizeof(s16)) = firstLine;
                    sortComplete = 0;
                }
            }
        }
    }

    for (i = 0x46; i != 0; i--) {
        counts[i - 1] += counts[i];
    }

    for (i = 0; i < gIntersectLineCount; i++) {
        IntersectLine* line = (IntersectLine*)(gIntersectLinePool + i * 16);
        int typeIndex = (line->kind & 0x3f) + 1;
        s16 typeOffset = counts[typeIndex]++;
        *(s16*)(gIntersectLineIndexTable + typeOffset * 2) = i;
    }

    for (i = 0; i < gIntersectLineCount - 1; i++) {
    }

    for (i = 0; i < 40; i++) {
        gIntersectSegmentTypeTable[i] = 0xffff;
    }

    previousType = -1;
    for (i = 0, lineOffset = i; i < gIntersectLineCount; lineOffset += 2, i++) {
        segmentType =
            (s16)((s8) * (u8*)(gIntersectLinePool + *(s16*)(gIntersectLineIndexTable + lineOffset) * 0x10 + 3) & 0x3f);
        if (segmentType >= 0x14) {
            segmentType = 1;
            debugPrintf(sTrackIntersectFuncOverflowFormat, 1);
        }
        if (previousType != segmentType) {
            u16 v = i;
            int ti = segmentType * 2;
            gIntersectSegmentTypeTable[ti] = v;
            if (previousType != -1) {
                int pi = previousType * 2;
                gIntersectSegmentTypeTable[pi + 1] = v;
            }
            previousType = segmentType;
        }
    }
    if (previousType != -1) {
        int pi = previousType * 2;
        gIntersectSegmentTypeTable[pi + 1] = gIntersectLineCount;
    }
    gIntersectLineTableReady = 1;
}

void trackSetLinesEnabledByParam(int matchVal, GameObject* obj, int flag) {
    int count;
    int i;
    struct IntersectModLineObject* mod;
    IntersectLine* e;
    if (obj != NULL) {
        mod = (struct IntersectModLineObject*)obj->anim.modelInstance;
        e = mod->lines;
        count = mod->sourceLineCount;
    } else {
        e = (IntersectLine*)gIntersectLinePool;
        count = gIntersectLineCount;
    }
    if (flag != 0) {
        for (i = 0; i < count; i++) {
            if (e->param == matchVal) {
                e->kind = (s8)(e->kind & ~0x40);
            }
            e++;
        }
    } else {
        for (i = 0; i < count; i++) {
            if (e->param == matchVal) {
                e->kind = (s8)(e->kind | 0x40);
            }
            e++;
        }
    }
}

void trackTickDynamicSlotCooldowns(void) {
    u32 cur;
    int idx;
    s16 i;
    i = 0;
    idx = 0;
    do {
        MapDynamicSlot* entry = (MapDynamicSlot*)((u8*)gMapDynamicSlots + idx);
        cur = entry->cooldown;
        if (cur != 0) {
            entry->cooldown--;
        }
        idx += sizeof(MapDynamicSlot);
        i++;
    } while (i < MAP_DYNAMIC_SLOT_COUNT);
}

int trackIntersectRebuildPending(void) {
    int r = 0;
    if ((s8)mapBlockFlag != 0 || (s8)gIntersectRebuildRequested != 0 || gIntersectRebuildCooldown != 0) {
        r = 1;
    }
    return r;
}

void setMapBlockFlag(void) {
    mapBlockFlag = 0x1;
}

int trackGetHeightAboveGround(GameObject* obj, f32 x, f32 y, f32 z, f32* outDepth, int queryMask) {
    TrackGroundHit** arr;
    int n;
    int i;
    f32 best;
    f32 cur;

    n = trackGetHeight(obj, x, y, z, &arr, 0, queryMask);
    if (n != 0) {
        TrackGroundHit** arrp;
        best = y - arr[0]->height;
        arrp = arr + 1;
        for (i = 1; i < n; i++, arrp++) {
            cur = (*arrp)->height;
            cur = y - cur;
            if (cur >= 0.0f) {
                if (best < 0.0f || cur < best) {
                    best = cur;
                }
            }
        }
        if (best >= 0.0f) {
            *outDepth = best;
            return 1;
        }
        *outDepth = 0.0f;
        return 0;
    }
    *outDepth = 0.0f;
    return 0;
}

static inline f32 trackAbsF32(f32 value) {
    if (value >= 0.0f) {
        return value;
    }
    return -value;
}

int trackGetNearestGroundOffsetAndNormal(GameObject* obj, f32 x, f32 y, f32 z, f32* outGroundOffset, f32* outNormal,
                                         int queryMask) {
    TrackGroundHit** hits;
    int hitCount;
    int hitIndex;
    int nearestIndex;
    f32 firstDistance;
    f32 bestDistance;

    hitCount = trackGetHeight(obj, x, y, z, &hits, 0, queryMask);
    if (hitCount != 0) {
        firstDistance = hits[0]->height;
        firstDistance = trackAbsF32(y - firstDistance);
        bestDistance = firstDistance;
        nearestIndex = 0;
        for (hitIndex = 1; hitIndex < hitCount; hitIndex++) {
            f32 distance = hits[hitIndex]->height;
            distance = y - distance;
            distance = trackAbsF32(distance);
            if (distance < bestDistance) {
                bestDistance = distance;
                nearestIndex = hitIndex;
            }
        }
        *outGroundOffset = y - hits[nearestIndex]->height;
        outNormal[0] = hits[nearestIndex]->normalX;
        outNormal[1] = hits[nearestIndex]->normalY;
        outNormal[2] = hits[nearestIndex]->normalZ;
        return 0;
    }
    *outGroundOffset = 0.0f;
    return 1;
}

int trackGetNearestGroundOffset(GameObject* obj, f32 x, f32 y, f32 z, f32* outGroundOffset, int queryMask) {
    TrackGroundHit** hits;
    int hitCount;
    int hitIndex;
    int nearestIndex;
    f32 firstDistance;
    f32 bestDistance;

    hitCount = trackGetHeight(obj, x, y, z, &hits, 0, queryMask);
    if (hitCount != 0) {
        firstDistance = hits[0]->height;
        firstDistance = trackAbsF32(y - firstDistance);
        bestDistance = firstDistance;
        nearestIndex = 0;
        for (hitIndex = 1; hitIndex < hitCount; hitIndex++) {
            f32 distance = hits[hitIndex]->height;
            distance = y - distance;
            distance = trackAbsF32(distance);
            if (distance < bestDistance) {
                bestDistance = distance;
                nearestIndex = hitIndex;
            }
        }
        *outGroundOffset = y - hits[nearestIndex]->height;
        return 0;
    }
    *outGroundOffset = 0.0f;
    return 1;
}

void trackCollectGroundHits(TrackTriangle* triStart, TrackTriangle* triEnd, TrackBlockDescriptor* desc, f32 qx, f32 qz,
                            int allowDown) {
    f32* vxp;
    f32* vyp;
    f32* vzp;
    TrackTriangle* tri;
    f32 ox;
    f32 planeY;
    f32 oz;
    f32 vxs[7];
    f32 vys[7];
    f32 vzs[7];
    f32 vec[4];

    if (desc->object == NULL) {
        qx -= (f32)((int*)gTrackGridOrigin)[0];
        qz -= (f32)((int*)gTrackGridOrigin)[2];
    }
    for (tri = triStart; tri < triEnd; tri++) {
        s8 fl = tri->flags;
        int inside;
        int i;

        if (fl & 0x10) {
            if (!(fl & 0x4)) {
                continue;
            }
        }
        vec[0] = tri->planeN[0];
        vec[1] = tri->planeN[1];
        vec[2] = tri->planeN[2];
        if (!(vec[1] > 0.0f)) {
            if (allowDown == 0) {
                continue;
            }
            if (0.0f == vec[1]) {
                continue;
            }
        }
        planeY = -(vec[0] * qx + vec[2] * qz + tri->planeD) / vec[1];
        (vxp = vxs)[0] = (f32)tri->vx[0];
        (vyp = vys)[0] = (f32)tri->vy[0];
        (vzp = vzs)[0] = (f32)tri->vz[0];
        vxp[1] = (f32)tri->vx[1];
        vyp[1] = (f32)tri->vy[1];
        vzp[1] = (f32)tri->vz[1];
        vxp[2] = (f32)tri->vx[2];
        vyp[2] = (f32)tri->vy[2];
        vzp[2] = (f32)tri->vz[2];
        inside = 1;
        {
            for (i = 0; i < 3; i++) {
                int nxt;
                f32 zero;
                f32 extrudeDistance;
                f32 nz, ny, nx, mag;
                extrudeDistance = 10.0f;
                zero = 0.0f;

                nxt = i + 1;
                if (nxt > 2) {
                    nxt = 0;
                }
                vxp[3] = extrudeDistance * vec[0] + vxp[i];
                vyp[3] = extrudeDistance * vec[1] + vyp[i];
                vzp[3] = extrudeDistance * vec[2] + vzp[i];
                nx = vyp[3] * (vzp[i] - vzp[nxt]) + (vyp[i] * (vzp[nxt] - vzp[3]) + vyp[nxt] * (vzp[3] - vzp[i]));
                ny = vzp[3] * (vxp[i] - vxp[nxt]) + (vzp[i] * (vxp[nxt] - vxp[3]) + vzp[nxt] * (vxp[3] - vxp[i]));
                nz = vxp[3] * (vyp[i] - vyp[nxt]) + (vxp[i] * (vyp[nxt] - vyp[3]) + vxp[nxt] * (vyp[3] - vyp[i]));
                mag = sqrtf(nx * nx + ny * ny + nz * nz);
                if (mag > zero) {
                    f32 s = 1.0f / mag;
                    nx *= s;
                    ny *= s;
                    nz *= s;
                }
                if (-(nx * vxp[i] + ny * vyp[i] + nz * vzp[i]) + (nx * qx + ny * planeY + nz * qz) > 0.2f) {
                    inside = 0;
                    break;
                }
            }
        }
        if (inside == 0) {
            continue;
        }
        if (gTrackGroundHitCount >= 0x23) {
            break;
        }
        if (desc->object != NULL) {
            Matrix_TransformPoint(desc->currentCollisionMatrix, qx, planeY, qz, &ox, &planeY, &oz);
            Matrix_TransformVector(desc->currentCollisionMatrix, vec, vec);
        }
        gTrackGroundHitWriteCursor->height = planeY;
        gTrackGroundHitWriteCursor->surfaceType = tri->surfaceType;
        gTrackGroundHitWriteCursor->normalX = vec[0];
        gTrackGroundHitWriteCursor->normalY = vec[1];
        gTrackGroundHitWriteCursor->normalZ = vec[2];
        gTrackGroundHitWriteCursor->object = desc->object;
        gTrackGroundHitWriteCursor++;
        gTrackGroundHitCount++;
    }
}

int trackGetHeight(GameObject* obj, f32 x, f32 y, f32 z, TrackGroundHit*** hitsOut, int mode, int queryMask) {
    u8* base = (u8*)gIntersectSegmentTypeTable;
    TrackBlockDescriptor* desc = (TrackBlockDescriptor*)(base + 0x424);
    TrackBlockDescriptor* end;
    u8* ptr;
    TrackGroundHit* hit;
    int i, j;
    int sorted;
    int conv[6];
    f32 tx, ty, tz;

    if (mode >= 0) {
        conv[0] = x;
        conv[3] = x;
        conv[1] = (int)(y - 10000.0f);
        conv[4] = (int)(10000.0f + y);
        conv[2] = z;
        conv[5] = z;
        trackIntersectBroadphase(obj, (TrackQueryBounds*)conv, queryMask, 1);
    } else {
        if (mode == -1) {
            mode = 0;
        } else {
            mode = 1;
        }
    }

    gTrackGroundHitWriteCursor = (TrackGroundHit*)(base + 0xdc);
    gTrackGroundHitPtrs = (TrackGroundHit**)(base + 0x50);
    gTrackGroundHitCount = 0;
    end = (TrackBlockDescriptor*)(base + 0x424) + gActiveTrackBlockCount;
    for (; desc < end; desc++) {
        if (gTrackGroundHitCount >= 0x23) {
            break;
        }
        if (desc->object != NULL) {
            Matrix_TransformPoint(desc->currentMatrix, x, 0.0f, z, &tx, &ty, &tz);
            trackCollectGroundHits(gTrackTriangleBuffer + desc->firstTriangle,
                                   gTrackTriangleBuffer + desc[1].firstTriangle, desc, tx, tz, mode);
        } else {
            trackCollectGroundHits(gTrackTriangleBuffer + desc->firstTriangle,
                                   gTrackTriangleBuffer + desc[1].firstTriangle, desc, x, z, mode);
        }
    }

    for (j = 0, ptr = base + 0xdc, i = 0; j < gTrackGroundHitCount; j++) {
        *(u8**)((u8*)gTrackGroundHitPtrs + i) = ptr;
        ptr += 0x18;
        i += 4;
    }

    sorted = 0;
    while (!sorted) {
        sorted = 1;
        for (j = 0; j < gTrackGroundHitCount - 1; j++) {
            if (gTrackGroundHitPtrs[j]->height < gTrackGroundHitPtrs[j + 1]->height) {
                hit = gTrackGroundHitPtrs[j];
                sorted = 0;
                gTrackGroundHitPtrs[j] = gTrackGroundHitPtrs[j + 1];
                gTrackGroundHitPtrs[j + 1] = hit;
            }
        }
    }

    *hitsOut = (TrackGroundHit**)(base + 0x50);
    return gTrackGroundHitCount;
}

int trackResolveSurfacePenetration(f32* a, f32* b, f32* c, f32* p, f32 f1p, f32 y, u8 type) {
    f32 displacement[3];
    f32 horizontalNormal[3];

    if (type == 3) {
        f32 fa, scale;
        f32 fb;
        b[0] = c[0];
        b[1] = c[1];
        b[2] = c[2];
        displacement[0] = b[0] - a[0];
        displacement[1] = b[1] - a[1];
        displacement[2] = b[2] - a[2];
        Vec3_Normalize(displacement);
        fb = (p[3] + (b[2] * p[2] + (b[0] * p[0] + b[1] * p[1]))) - y;
        fa = (p[3] + (a[2] * p[2] + (a[0] * p[0] + a[1] * p[1]))) - y;
        if (fa != fb) {
            scale = fa / (fa - fb);
        } else {
            scale = 0.0f;
        }
        displacement[0] = b[0] - a[0];
        displacement[1] = b[1] - a[1];
        displacement[2] = b[2] - a[2];
        b[0] = displacement[0] * scale;
        b[1] = displacement[1] * scale;
        b[2] = displacement[2] * scale;
        b[0] += a[0];
        b[1] += a[1];
        b[2] += a[2];
        return 1;
    }
    {
        f32 p1 = *(f32*)(p + 1);
        if (p1 < 0.707f && p1 > -0.707f) {
            switch (type) {
            case 1:
            case 8:
            case 0xa: {
                f32 normalZ;
                f32 normalX;

                normalX = p[0];
                normalZ = p[2];
                y = y - (p[3] + (b[2] * normalZ + (normalX * b[0] + b[1] * p[1])));
                if (y > 0.0f) {
                    f32 px = normalX * normalX;
                    f32 pz = normalZ * normalZ;
                    f32 d = mathCosfHighPrecision(atan2fHighPrecision(p[1], sqrtf(px + pz)));
                    if (0.0f != d) {
                        y /= d;
                    }
                    horizontalNormal[0] = p[0];
                    horizontalNormal[1] = 0.0f;
                    horizontalNormal[2] = p[2];
                    Vec3_Normalize(horizontalNormal);
                    b[0] = y * horizontalNormal[0] + b[0];
                    b[2] = y * horizontalNormal[2] + b[2];
                }
                break;
            }
            default: {
                f32 t;
                b[0] -= f1p * p[0];
                b[1] -= f1p * p[1];
                b[2] -= f1p * p[2];
                t = y - (p[3] + (b[2] * p[2] + (b[1] * p[1] + b[0] * p[0])));
                b[0] += t * p[0];
                b[1] += t * p[1];
                b[2] += t * p[2];
                break;
            }
            }
        } else {
            int switchType = type;
            switch (switchType) {
            case 5:
            case 8: {
                f32 t;
                b[0] -= f1p * p[0];
                b[1] -= f1p * p[1];
                b[2] -= f1p * p[2];
                t = y - (p[3] + (b[2] * p[2] + (b[1] * p[1] + b[0] * p[0])));
                b[0] += t * p[0];
                b[1] += t * p[1];
                b[2] += t * p[2];
                break;
            }
            case 9:
            case 0xa:
            default: {
                f32 normalZ;
                f32 normalX;

                normalX = p[0];
                normalZ = p[2];
                y = y - (p[3] + (b[2] * normalZ + (normalX * b[0] + b[1] * p[1])));
                if (y > 0.0f) {
                    f32 px = normalX * normalX;
                    f32 pz = normalZ * normalZ;
                    f32 d = mathSinfHighPrecision(atan2fHighPrecision(p[1], sqrtf(px + pz)));
                    d = y / d;
                    b[1] += d;
                }
                break;
            }
            }
        }
    }
    return 1;
}

int trackSweepSphereAgainstEdge(void* tri, f32* rayOrig, f32* rayDir, f32 maxd, f32* out29, f32* outNrm, f32 maxStep,
                                f32* outDist, f32 epsArg) {
    f32 nrm[3];
    f32 e[3];
    f32 tmp14[3];
    f32 hit[3];
    f32 len, f29, f12, zero;
    f32* T = tri;

    Vec3_Cross(rayDir, T + 6, nrm);
    len = Vec3_Normalize(nrm);
    if (0.0f == len) {
        return 0;
    }
    e[0] = rayOrig[0] - T[0];
    e[1] = rayOrig[1] - T[1];
    e[2] = rayOrig[2] - T[2];
    {
        f32 d0 = nrm[1] * e[1];
        f29 = d0 + nrm[0] * e[0] + nrm[2] * e[2];
    }
    f29 *= f29;
    if (f29 <= T[10]) {
        Vec3_Cross(e, T + 6, tmp14);
        {
            f32 dl = tmp14[1] * nrm[1];
            len = -(dl + tmp14[0] * nrm[0] + tmp14[2] * nrm[2]) / len;
        }
        Vec3_Cross(nrm, T + 6, tmp14);
        Vec3_Normalize(tmp14);
        {
            f32 s = sqrtf(T[10] - f29);
            f32 dd = rayDir[1] * tmp14[1];
            f32 dn = dd + rayDir[0] * tmp14[0] + rayDir[2] * tmp14[2];
            f32 r = s / dn;
            if (r < 0.0f) {
                r = -r;
            }
            len -= r;
        }
        zero = 0.0f;
        if (len >= zero) {
            if (len <= maxd) {
                hit[0] = rayDir[0] * len;
                hit[1] = rayDir[1] * len;
                hit[2] = rayDir[2] * len;
                hit[0] = rayOrig[0] + hit[0];
                hit[1] = rayOrig[1] + hit[1];
                hit[2] = rayOrig[2] + hit[2];
                {
                    f32 d2 = T[7] * T[1];
                    f12 = (hit[0] * T[6] + hit[1] * T[7] + hit[2] * T[8]) - (d2 + T[6] * T[0] + T[8] * T[2]);
                }
                if (f12 >= zero) {
                    if (f12 <= T[11]) {
                        tmp14[0] = T[6] * f12;
                        tmp14[1] = T[7] * f12;
                        tmp14[2] = T[8] * f12;
                        tmp14[0] = T[0] + tmp14[0];
                        tmp14[1] = T[1] + tmp14[1];
                        tmp14[2] = T[2] + tmp14[2];
                        outNrm[0] = hit[0] - tmp14[0];
                        outNrm[1] = hit[1] - tmp14[1];
                        outNrm[2] = hit[2] - tmp14[2];
                        Vec3_Normalize(outNrm);
                        {
                            f32 dh = hit[1] * outNrm[1];
                            outNrm[3] = T[9] - (dh + hit[0] * outNrm[0] + hit[2] * outNrm[2]);
                        }
                        out29[0] = *(f32*)((u8*)hit + 0);
                        out29[1] = *(f32*)((u8*)hit + 4);
                        out29[2] = *(f32*)((u8*)hit + 8);
                        *outDist = len;
                        return 3;
                    }
                }
            }
        }
    }
    return 0;
}

/* trackGetIntersect2 -- sweep each input sphere against the gathered triangle
 * lists, bouncing/sliding up to 10 times per slot; returns hit mask. */
char sTrackHitOverflowError[] = "HIT OVERFLOW\n";

int trackGetIntersect2(int mode, void* tri1, void* tri2, f32* startPos, f32* endPos, int count, void* slots,
                       int flagsArg) {
    f32 *ep1, *ep2;
    f32 *sp1, *sp2;
    u8* slotp;
    u8* typeSlotp;
    f32* outp;
    f32 *edge1p, *edge2p, *vbp, *evecp;
    u8* slotBase;
    s16 i;
    u8 retLo;
    u8 curBit;
    u8 retHi;
    u8 typeb;
    u8 typeb2;
    TrackBlockDescriptor* descSave;
    u8 type;
    f32 edge2[4];
    f32 edge1[4];
    f32 edge0[4];
    f32 rdata[3];
    f32* rdatap = rdata;
    f32 evec[3];
    f32 vb[3];
    f32 va[3];
    f32 ws[3];
    f32 we[3];
    f32 delta[3];
    f32 hitpt[3];
    f32 cur[3];
    f32 plane[4];
    f32 norm4[4];
    f32 svFrom[3];
    f32* svFromp = svFrom;
    f32 svHit[3];
    f32 svWorld[3];
    f32 dir[3];
    f32 tmp1[3];
    f32 tmp2[3];
    f32 frac;
    f32 ndot;
    f32 dS;
    f32 dotv;
    f32 sq;
    f32 disc;
    f32 root;
    f32 tt;
    f32 rr;
    f32 dE;
    u8 vertexBit;
    u8 nextBit;
    u8 found;
    u8 bounces;
    s16 hit;
    TrackTriangle* tri;
    u32 objmtx;
    TrackBlockDescriptor* desc;
    f32 eps;
    f32 negStep, radius, maxStep;
    f32 offX, offZ;
    f32 mag;
    s32* gridOrigin;
    TrackBlockDescriptor* descEnd;
    TrackHitResults* results = slots;

    slotBase = (u8*)slots;
    descEnd = gTrackBlockDescriptors + gActiveTrackBlockCount;
    gridOrigin = (s32*)gTrackGridOrigin;
    offX = (f32)gridOrigin[0];
    offZ = (f32)gridOrigin[2];
    i = 0;
    retLo = 0;
    retHi = 0;
    curBit = 1;
    ep1 = endPos;
    ep2 = endPos;
    sp1 = startPos;
    sp2 = startPos;
    slotp = slots;
    outp = slots;
    edge1p = edge1;
    edge2p = edge2;
    vbp = vb;
    evecp = evec;
    eps = 0.0f;
    do {
        cur[0] = ep1[0];
        cur[1] = ep2[1];
        cur[2] = ep2[2];
        svFromp[0] = sp1[0];
        svFromp[1] = sp2[1];
        svFromp[2] = sp2[2];
        radius = *(f32*)(slotp + 0x40);
        typeSlotp = slotBase + i;
        type = typeSlotp[0x54];
        maxStep = radius + gTrackCollisionEpsilon;
        rdatap[0] = radius;
        rdatap[1] = radius * radius;
        bounces = 0;
        negStep = -maxStep;
        do {
            we[0] = cur[0];
            we[1] = cur[1];
            we[2] = cur[2];
            found = 0;
            hit = 0;
            for (desc = gTrackBlockDescriptors; desc < descEnd; desc++) {
                if (desc->object != NULL) {
                    Matrix_TransformPoint(desc->alternateMatrix, svFromp[0], svFromp[1], svFromp[2], &ws[0], &ws[1],
                                          &ws[2]);
                    Matrix_TransformPoint(desc->currentMatrix, cur[0], cur[1], cur[2], &we[0], &we[1], &we[2]);
                } else {
                    ws[0] = svFromp[0] - offX;
                    ws[1] = svFromp[1];
                    ws[2] = svFromp[2] - offZ;
                    we[0] = cur[0] - offX;
                    we[1] = cur[1];
                    we[2] = cur[2] - offZ;
                }
                PSVECSubtract((Vec*)we, (Vec*)ws, (Vec*)delta);
                mag = PSVECMag((Vec*)delta);
                if (mag > eps) {
                    PSVECNormalize((Vec*)delta, (Vec*)dir);
                }
                for (tri = gTrackTriangleBuffer + desc->firstTriangle;
                     tri < gTrackTriangleBuffer + desc[1].firstTriangle; tri++) {
                    u8 b;
                    tri->edgeOutBits = 0;
                    if (tri->flags & 0x10) {
                        continue;
                    }
                    plane[0] = tri->planeN[0];
                    plane[1] = tri->planeN[1];
                    plane[2] = tri->planeN[2];
                    plane[3] = tri->planeD;
                    dE = (plane[3] + PSVECDotProduct((Vec*)plane, (Vec*)we)) - radius;
                    if (!(dE <= 0.0f)) {
                        continue;
                    }
                    dS = (plane[3] + PSVECDotProduct((Vec*)plane, (Vec*)ws)) - radius;
                    if ((dS <= 0.0f && dE >= 0.0f) || (dS >= 0.0f && dE <= 0.0f)) {
                        if (dS != dE) {
                            frac = dS / (dS - dE);
                        } else {
                            frac = 0.0f;
                        }
                        PSVECScale((Vec*)delta, (Vec*)hitpt, frac);
                        PSVECAdd((Vec*)hitpt, (Vec*)ws, (Vec*)hitpt);
                        if (hitpt[1] < tri->vy[tri->minMaxY & 0xf] - maxStep) {
                            continue;
                        }
                        if (hitpt[1] > tri->vy[tri->minMaxY >> 4] + maxStep) {
                            continue;
                        }
                        edge0[0] = tri->edgeN0[0];
                        edge0[1] = tri->edgeN0[1];
                        edge0[2] = tri->edgeN0[2];
                        edge0[3] = -(tri->vz[0] * edge0[2] + (tri->vx[0] * edge0[0] + tri->vy[0] * edge0[1])) +
                                   PSVECDotProduct((Vec*)edge0, (Vec*)hitpt);
                        edge1[0] = tri->edgeN1[0];
                        edge1[1] = tri->edgeN1[1];
                        edge1[2] = tri->edgeN1[2];
                        edge1[3] = -(tri->vz[1] * edge1[2] + (tri->vx[1] * edge1[0] + tri->vy[1] * edge1[1])) +
                                   PSVECDotProduct((Vec*)edge1p, (Vec*)hitpt);
                        edge2[0] = tri->edgeN2[0];
                        edge2[1] = tri->edgeN2[1];
                        edge2[2] = tri->edgeN2[2];
                        edge2[3] = -(tri->vz[2] * edge2[2] + (tri->vx[2] * edge2[0] + tri->vy[2] * edge2[1])) +
                                   PSVECDotProduct((Vec*)edge2p, (Vec*)hitpt);
                        b = 0;
                        if (radius > 0.0f) {
                            if (edge0[3] > 0.0f) {
                                b |= 1;
                            }
                            if (edge1[3] > 0.0f) {
                                b |= 2;
                            }
                            if (edge2[3] > 0.0f) {
                                b |= 4;
                            }
                        }
                        if (b == 0) {
                            hit = 1;
                            goto hitCheck;
                        }
                        tri->edgeOutBits = b;
                    } else if (dS >= negStep && radius > 0.0f) {
                        edge0[0] = tri->edgeN0[0];
                        edge0[1] = tri->edgeN0[1];
                        edge0[2] = tri->edgeN0[2];
                        edge0[3] = -(tri->vz[0] * edge0[2] + (tri->vx[0] * edge0[0] + tri->vy[0] * edge0[1])) +
                                   PSVECDotProduct((Vec*)edge0, (Vec*)ws);
                        edge1[0] = tri->edgeN1[0];
                        edge1[1] = tri->edgeN1[1];
                        edge1[2] = tri->edgeN1[2];
                        edge1[3] = -(tri->vz[1] * edge1[2] + (tri->vx[1] * edge1[0] + tri->vy[1] * edge1[1])) +
                                   PSVECDotProduct((Vec*)edge1p, (Vec*)ws);
                        edge2[0] = tri->edgeN2[0];
                        edge2[1] = tri->edgeN2[1];
                        edge2[2] = tri->edgeN2[2];
                        edge2[3] = -(tri->vz[2] * edge2[2] + (tri->vx[2] * edge2[0] + tri->vy[2] * edge2[1])) +
                                   PSVECDotProduct((Vec*)edge2p, (Vec*)ws);
                        b = 0;
                        if (edge0[3] > 0.0f) {
                            b |= 1;
                        }
                        if (edge1[3] > 0.0f) {
                            b |= 2;
                        }
                        if (edge2[3] > 0.0f) {
                            b |= 4;
                        }
                        tri->edgeOutBits = b;
                    }
                }
                if (mag != 0.0f) {
                    for (tri = gTrackTriangleBuffer + desc->firstTriangle;
                         tri < gTrackTriangleBuffer + desc[1].firstTriangle; tri++) {
                        u8 edgeBit;
                        if (tri->edgeOutBits == 0) {
                            continue;
                        }
                        for (edgeBit = 0; edgeBit < 3; edgeBit++) {
                            u8 k;
                            if ((tri->edgeOutBits & (1 << edgeBit)) == 0) {
                                continue;
                            }
                            k = edgeBit + 1;
                            if (k > 2) {
                                k = 0;
                            }
                            va[0] = tri->vx[edgeBit];
                            va[1] = tri->vy[edgeBit];
                            va[2] = tri->vz[edgeBit];
                            vb[0] = tri->vx[k];
                            vb[1] = tri->vy[k];
                            vb[2] = tri->vz[k];
                            PSVECSubtract((Vec*)vbp, (Vec*)va, (Vec*)evecp);
                            rdatap[2] = Vec3_Normalize(evecp);
                            if (trackSweepSphereAgainstEdge(va, ws, dir, mag, hitpt, plane, maxStep, &frac, 0.0f)) {
                                hit = 1;
                                goto hitCheck;
                            }
                        }
                    }
                    for (tri = gTrackTriangleBuffer + desc->firstTriangle;
                         tri < gTrackTriangleBuffer + desc[1].firstTriangle; tri++) {
                        if (tri->edgeOutBits == 0) {
                            continue;
                        }
                        for (vertexBit = 0; vertexBit < 3; vertexBit++) {
                            int ok;
                            if ((tri->edgeOutBits & (1 << vertexBit)) == 0) {
                                continue;
                            }
                            nextBit = vertexBit + 1;
                            if (nextBit > 2) {
                                nextBit = 0;
                            }
                            va[0] = tri->vx[vertexBit];
                            va[1] = tri->vy[vertexBit];
                            va[2] = tri->vz[vertexBit];
                            rr = rdatap[1];
                            PSVECSubtract((Vec*)va, (Vec*)ws, (Vec*)tmp1);
                            dotv = PSVECDotProduct((Vec*)tmp1, (Vec*)dir);
                            sq = PSVECSquareMag((Vec*)tmp1);
                            if (dotv < 0.0f && sq > rr) {
                                ok = 0;
                            } else {
                                disc = -(dotv * dotv - sq);
                                if (disc > rr) {
                                    ok = 0;
                                } else {
                                    root = sqrtf(rr - disc);
                                    if (sq > rr) {
                                        dotv -= root;
                                    } else {
                                        dotv += root;
                                    }
                                    if (dotv >= 0.0f && dotv <= mag) {
                                        PSVECScale((Vec*)dir, (Vec*)hitpt, dotv);
                                        PSVECAdd((Vec*)ws, (Vec*)hitpt, (Vec*)hitpt);
                                        PSVECSubtract((Vec*)hitpt, (Vec*)va, (Vec*)plane);
                                        PSVECNormalize((Vec*)plane, (Vec*)plane);
                                        root = sqrtf(rr);
                                        ndot = -PSVECDotProduct((Vec*)hitpt, (Vec*)plane);
                                        plane[3] = ndot + root;
                                        frac = dotv;
                                        ok = 1;
                                    } else {
                                        ok = 0;
                                    }
                                }
                            }
                            if (ok) {
                                hit = 1;
                                goto hitCheck;
                            }
                            vb[0] = tri->vx[nextBit];
                            vb[1] = tri->vy[nextBit];
                            vb[2] = tri->vz[nextBit];
                            dE = rdatap[1];
                            PSVECSubtract((Vec*)vbp, (Vec*)ws, (Vec*)tmp2);
                            sq = PSVECDotProduct((Vec*)tmp2, (Vec*)dir);
                            dotv = PSVECSquareMag((Vec*)tmp2);
                            if (sq < 0.0f && dotv > dE) {
                                ok = 0;
                            } else {
                                disc = -(sq * sq - dotv);
                                if (disc > dE) {
                                    ok = 0;
                                } else {
                                    root = sqrtf(dE - disc);
                                    if (dotv > dE) {
                                        tt = sq - root;
                                    } else {
                                        tt = sq + root;
                                    }
                                    if (tt >= 0.0f && tt <= mag) {
                                        PSVECScale((Vec*)dir, (Vec*)hitpt, tt);
                                        PSVECAdd((Vec*)ws, (Vec*)hitpt, (Vec*)hitpt);
                                        PSVECSubtract((Vec*)hitpt, (Vec*)vbp, (Vec*)plane);
                                        PSVECNormalize((Vec*)plane, (Vec*)plane);
                                        root = sqrtf(dE);
                                        ndot = -PSVECDotProduct((Vec*)hitpt, (Vec*)plane);
                                        plane[3] = ndot + root;
                                        frac = tt;
                                        ok = 1;
                                    } else {
                                        ok = 0;
                                    }
                                }
                            }
                            if (ok) {
                                hit = 1;
                                goto hitCheck;
                            }
                        }
                    }
                }
            hitCheck:
                if (hit != 0) {
                    u8 triFlags;
                    we[0] = hitpt[0];
                    we[1] = hitpt[1];
                    we[2] = hitpt[2];
                    norm4[0] = plane[0];
                    norm4[1] = plane[1];
                    norm4[2] = plane[2];
                    norm4[3] = plane[3];
                    typeb = tri->surfaceType;
                    triFlags = tri->flags;
                    typeb2 = triFlags;
                    objmtx = (u32)desc->object;
                    svWorld[0] = ws[0];
                    svWorld[1] = ws[1];
                    svWorld[2] = ws[2];
                    svHit[0] = hitpt[0];
                    svHit[1] = hitpt[1];
                    svHit[2] = hitpt[2];
                    descSave = desc;
                    found = 1;
                    if ((u8)type == 7) {
                        outp[0] = norm4[0];
                        outp[1] = norm4[1];
                        outp[2] = norm4[2];
                        outp[3] = norm4[3];
                        typeSlotp[0x50] = typeb;
                        typeSlotp[0x58] = triFlags;
                        *(int*)(slotp + 0x5c) = objmtx;
                        bounces++;
                        goto slotComplete;
                    }
                    break;
                }
            }
            if (found != 0) {
                bounces++;
                if (bounces > 10) {
                    logPrintf(sTrackHitOverflowError);
                    cur[0] = svFromp[0];
                    cur[1] = svFromp[1];
                    cur[2] = svFromp[2];
                    found = 0;
                } else {
                    f32 pen;
                    if (objmtx != 0) {
                        Matrix_TransformPoint(descSave->currentMatrix, cur[0], cur[1], cur[2], &cur[0], &cur[1],
                                              &cur[2]);
                    } else {
                        cur[0] -= offX;
                        cur[2] -= offZ;
                    }
                    pen = norm4[3] + (cur[2] * norm4[2] + (cur[0] * norm4[0] + cur[1] * norm4[1]));
                    pen -= radius;
                    trackResolveSurfacePenetration(svWorld, cur, svHit, norm4, pen, maxStep, type);
                    if (objmtx != 0) {
                        Matrix_TransformPoint(descSave->currentCollisionMatrix, cur[0], cur[1], cur[2], &cur[0],
                                              &cur[1], &cur[2]);
                    } else {
                        cur[0] += offX;
                        cur[2] += offZ;
                    }
                    outp[0] = norm4[0];
                    outp[1] = norm4[1];
                    outp[2] = norm4[2];
                    outp[3] = norm4[3];
                    typeSlotp[0x50] = typeb;
                    typeSlotp[0x58] = typeb2;
                    *(int*)(slotp + 0x5c) = objmtx;
                }
            }
        } while (found != 0);
    slotComplete:
        if (bounces != 0) {
            if (norm4[1] >= 0.707f || norm4[1] <= -0.707f) {
                retHi |= curBit;
            }
            ep1[0] = cur[0];
            ep2[1] = cur[1];
            ep2[2] = cur[2];
            results->hitCount++;
            retLo |= curBit;
        }
        curBit = (u8)(curBit << 1);
        slotp += 4;
        outp += 4;
        i++;
        ep1 += 3;
        ep2 += 3;
        sp1 += 3;
        sp2 += 3;
    } while (i < count);
    return retLo | (retHi << 4);
}

int trackGetIntersect(GameObject* contactSrc, f32* startPos, f32* endPos, int count, void* results, int flags) {
    int lim;
    f32* fp;
    void** pp;
    s16 i;
    u8 hitCount;
    TrackBlockDescriptor* tbl = gTrackBlockDescriptors;

    if (count > 4) {
        count = 4;
    }
    ((TrackHitResults*)results)->hitCount = 0;

    i = 0;
    if (count > 0) {
        lim = count - 8;
        if (count > 8) {
            f32 b, a;
            fp = results;
            pp = results;
            a = 0.0f;
            b = 1.0f;
            while (i < lim) {
                fp[0] = a;
                fp[1] = b;
                fp[2] = a;
                fp[3] = a;
                pp[0x17] = NULL;
                fp[4] = a;
                fp[5] = b;
                fp[6] = a;
                fp[7] = a;
                pp[0x18] = NULL;
                fp[8] = a;
                fp[9] = b;
                fp[10] = a;
                fp[11] = a;
                pp[0x19] = NULL;
                fp[12] = a;
                fp[13] = b;
                fp[14] = a;
                fp[15] = a;
                pp[0x1a] = NULL;
                fp[16] = a;
                fp[17] = b;
                fp[18] = a;
                fp[19] = a;
                pp[0x1b] = NULL;
                fp[20] = a;
                fp[21] = b;
                fp[22] = a;
                fp[23] = a;
                pp[0x1c] = NULL;
                fp[24] = a;
                fp[25] = b;
                fp[26] = a;
                fp[27] = a;
                pp[0x1d] = NULL;
                fp[28] = a;
                fp[29] = b;
                fp[30] = a;
                fp[31] = a;
                pp[0x1e] = NULL;
                fp += 32;
                pp += 8;
                i += 8;
            }
        }
        {
            f32 b, a;
            fp = (f32*)results + i * 4;
            pp = (void**)results + i;
            a = 0.0f;
            b = 1.0f;
            while (i < count) {
                fp[0] = a;
                fp[1] = b;
                fp[2] = a;
                fp[3] = a;
                pp[0x17] = NULL;
                fp += 4;
                pp += 1;
                i++;
            }
        }
    }

    hitCount = trackGetIntersect2(0, gTrackTriangleBuffer + tbl->firstTriangle,
                                  gTrackTriangleBuffer + tbl[1].firstTriangle, startPos, endPos, count, results, 0);

    fp = results;
    pp = results;
    for (i = 0; i < count; i++) {
        if (pp[i + 0x17] != NULL) {
            Obj_TransformLocalVectorByWorldMatrix(pp[i + 0x17], &fp[i * 4], &fp[i * 4]);
            if (contactSrc != NULL) {
                ObjHits_AddContactObject(pp[i + 0x17], contactSrc);
            }
        }
    }

    ((TrackHitResults*)results)->hitMask = hitCount;
    return hitCount;
}

int trackBuildModelTriangles(int cur, TrackBlockDescriptor* desc, int* model, f32 scale, f32 x0, f32 y0, f32 z0, f32 x1,
                             f32 y1, f32 z1, u8 flags) {
    f32 xd, xc, xb, xa;
    f32 zd, zc, zb, za;
    f32 ytmp;
    s16 *xw, *yw, *zw;
    f32 ex, ey, ez;
    int t;
    int tEnd;
    int minYi, maxYi;
    int j2;
    int k22;
    u8* blk;
    s16 *xs, *ys, *zs;
    ModelFileHeader* hdr;
    int deg;
    int flag20;
    int flag8;
    int i;
    int count;
    int flag4;

    hdr = (ModelFileHeader*)*model;

    Matrix_TransformPoint(desc->currentMatrix, x0, y0, z0, &xa, &ytmp, &za);
    Matrix_TransformPoint(desc->currentMatrix, x0, y0, z1, &xb, &y0, &zb);
    Matrix_TransformPoint(desc->currentMatrix, x1, y1, z0, &xc, &ytmp, &zc);
    Matrix_TransformPoint(desc->currentMatrix, x1, y1, z1, &xd, &y1, &zd);

    x0 = x1 = xa;
    z0 = z1 = za;
    if (xb < x1) {
        x0 = xb;
    }
    if (xb > x1) {
        x1 = xb;
    }
    if (zb < z0) {
        z0 = zb;
    }
    if (zb > z1) {
        z1 = zb;
    }
    if (xc < x0) {
        x0 = xc;
    }
    if (xc > x1) {
        x1 = xc;
    }
    if (zc < z0) {
        z0 = zc;
    }
    if (zc > z1) {
        z1 = zc;
    }
    if (xd < x0) {
        x0 = xd;
    }
    if (xd > x1) {
        x1 = xd;
    }
    if (zd < z0) {
        z0 = zd;
    }
    if (zd > z1) {
        z1 = zd;
    }

    count = hdr->collisionBlockCount;
    i = 0;
    flag20 = flags & 0x20;
    flag8 = flags & 8;
    flag4 = flags & 4;

    for (; i < count; i++) {
        s16* bs;
        u32 bf;
        blk = modelFileGetCollisionBlock((u8*)hdr, i);
        bs = (s16*)blk;
        bf = *(u32*)(blk + 0x10);

        if (bf & 0x100000) {
            continue;
        }
        if ((bf & 0x8000000) && flag20 == 0) {
            continue;
        }
        if (x0 > bs[2] * scale) {
            continue;
        }
        if (x1 < bs[1] * scale) {
            continue;
        }
        if (y0 > bs[4] * scale) {
            continue;
        }
        if (y1 < bs[3] * scale) {
            continue;
        }
        if (z0 > bs[6] * scale) {
            continue;
        }
        if (z1 < bs[5] * scale) {
            continue;
        }

        tEnd = *(u16*)(blk + 0x14);
        t = *(u16*)blk;
        for (; t < tEnd; t++) {
            u16* twn = modelFileGetCollisionTriangle((u8*)hdr, t);
            u16* tw;
            f32 tMinX, tMaxX, tMinY, tMaxY, tMinZ, tMaxZ;
            u8* vout;
            int j;
            int nxi, nyi, nzi;
            f32 fnx, fny, fnz;
            f32 len, inv;

            tMinX = 1e30f;
            tMaxX = -1e30f;
            tMinY = tMinX;
            tMaxY = tMaxX;
            tMinZ = tMinX;
            tMaxZ = tMaxX;
            for (j = 0, tw = twn, vout = (u8*)cur; j < 3; j++) {
                s16* v = ObjModel_GetBaseVertexCoords(hdr, *tw);
                f32 fx, fy, fz;
                if (hdr->flags & 0x800) {
                    fx = v[0] * scale;
                    fy = v[1] * scale;
                    fz = v[2] * scale;
                } else {
                    fx = v[0] * scale / 256.0f;
                    fy = v[1] * scale / 256.0f;
                    fz = v[2] * scale / 256.0f;
                }
                if (fx > tMaxX) {
                    tMaxX = fx;
                }
                if (fx < tMinX) {
                    tMinX = fx;
                }
                if (fy > tMaxY) {
                    tMaxY = fy;
                    maxYi = j;
                }
                if (fy < tMinY) {
                    tMinY = fy;
                    minYi = j;
                }
                if (fz > tMaxZ) {
                    tMaxZ = fz;
                }
                if (fz < tMinZ) {
                    tMinZ = fz;
                }
                ((TrackTriangle*)vout)->vx[0] = fx;
                ((TrackTriangle*)vout)->vy[0] = fy;
                ((TrackTriangle*)vout)->vz[0] = fz;
                tw++;
                vout += 2;
            }
            if (tMinY > y1) {
                continue;
            }
            if (tMaxY < y0) {
                continue;
            }
            if (tMinX > x1) {
                continue;
            }
            if (tMaxX < x0) {
                continue;
            }
            if (tMinZ > z1) {
                continue;
            }
            if (tMaxZ < z0) {
                continue;
            }

            xs = ((TrackTriangle*)cur)->vx;
            ys = ((TrackTriangle*)cur)->vy;
            zs = ((TrackTriangle*)cur)->vz;

            nxi = ys[2] * (zs[0] - zs[1]) + (ys[0] * (zs[1] - zs[2]) + ys[1] * (zs[2] - zs[0]));
            fnx = nxi;
            nyi = zs[2] * (xs[0] - xs[1]) + (zs[0] * (xs[1] - xs[2]) + zs[1] * (xs[2] - xs[0]));
            fny = nyi;
            nzi = xs[2] * (ys[0] - ys[1]) + (xs[0] * (ys[1] - ys[2]) + xs[1] * (ys[2] - ys[0]));
            fnz = nzi;
            len = sqrtf(fnz * fnz + (fnx * fnx + fny * fny));
            if (!(len > 0.0f)) {
                continue;
            }
            inv = 1.0f / len;
            ((TrackTriangle*)cur)->planeN[0] = fnx * inv;
            ((TrackTriangle*)cur)->planeN[1] = fny * inv;
            ((TrackTriangle*)cur)->planeN[2] = fnz * inv;

            if (flag8) {
                if (((TrackTriangle*)cur)->planeN[1] >= 0.707f) {
                    continue;
                }
                if (((TrackTriangle*)cur)->planeN[1] <= -0.707f) {
                    continue;
                }
            }
            if (flag4) {
                if (((TrackTriangle*)cur)->planeN[1] < 0.707f && ((TrackTriangle*)cur)->planeN[1] > -0.707f) {
                    continue;
                }
            }

            ((TrackTriangle*)cur)->planeD =
                -(*(f32*)(cur + 0xc) * *(s16*)(cur + 0x1c) +
                  (*(f32*)(cur + 4) * *(s16*)(cur + 0x10) + *(f32*)(cur + 8) * *(s16*)(cur + 0x16)));

            {
                f32 eps;
                k22 = 0;
                deg = 0;
                j2 = 0;
                xw = xs;
                yw = ys;
                zw = zs;
                eps = 0.0f;
                for (; j2 < 3; j2++) {
                    int k = j2 + 1;
                    f32 px, py, pz;
                    if (k > 2) {
                        k = 0;
                    }
                    px = ((TrackTriangle*)cur)->planeN[0] + xw[0];
                    py = ((TrackTriangle*)cur)->planeN[1] + yw[0];
                    pz = ((TrackTriangle*)cur)->planeN[2] + zw[0];
                    ex = py * (f32)(zw[0] - zs[k]) + ((f32)yw[0] * ((f32)zs[k] - pz) + ys[k] * (pz - zw[0]));
                    ey = pz * (f32)(xw[0] - xs[k]) + ((f32)zw[0] * ((f32)xs[k] - px) + zs[k] * (px - xw[0]));
                    ez = px * (f32)(yw[0] - ys[k]) + ((f32)xw[0] * ((f32)ys[k] - py) + xs[k] * (py - yw[0]));
                    len = sqrtf(ez * ez + (ex * ex + ey * ey));
                    if (len > eps) {
                        f32 inv2 = 1.0f / len;
                        ex *= inv2;
                        ey *= inv2;
                        ez *= inv2;
                    } else {
                        deg = 1;
                    }
                    *(f32*)(cur + k22++ * 4 + 0x24) = ex;
                    *(f32*)(cur + k22++ * 4 + 0x24) = ey;
                    *(f32*)(cur + k22++ * 4 + 0x24) = ez;
                    xw++;
                    yw++;
                    zw++;
                }
                if (deg) {
                    continue;
                }
            }

            *(s8*)&((TrackTriangle*)cur)->surfaceType = (u8)trackGetPackedSurfaceType((int*)blk);
            ((TrackTriangle*)cur)->minMaxY = (u8)((maxYi << 4) | minYi);
            ((TrackTriangle*)cur)->flags = 10;
            ((TrackTriangle*)cur)->flags |= 8;
            cur += 0x4c;
            if ((u32)cur >= gTrackTriangleBufferEnd) {
                return cur;
            }
        }
    }
    return cur;
}

/* trackBuildBlockTriangles -- gather map-block collision triangles overlapping
 * the query box into the buffer at cur; returns advanced cursor. */
int trackBuildBlockTriangles(cur, x0, y0, z0, x1, y1, z1, flags, doEdges)
int cur;
int x0;
int y0;
int z0;
int x1;
int y1;
int z1;
int flags;

u8 doEdges;
{
    MapBlockData* cells[16];
    f32 e2[3];
    f32 e1[3];
    f32 e0[3];
    f32 verts2[3];
    f32 verts[3];
    f32 v0[3];
    f32 en[3];
    u32 offA;
    int* firstp;
    int last;
    int mask16;
    int f40, f80, f200, f120, f20, f8, f100, f4;
    int gx0, gz0, gx1, gz1;
    u32 offB;
    MapBlockData **cellp, **cw;
    int gx, gz;
    int count, layer;
    int *descp, *dw;
    u32 offC;
    int relx0, relz0, relx1, relz1;
    int i;
    int vEnd;
    u32 triEnd;
    u8 typeb;
    u32 bb;
    u32 dmaflip;
    f32* vertp;
    MapBlockData** p1;
    int* q1;
    MapBlockData** p2;
    int* q2;

    x0 -= gMapBlockOriginWorldX;
    z0 -= gMapBlockOriginWorldZ;
    x1 -= gMapBlockOriginWorldX;
    z1 -= gMapBlockOriginWorldZ;
    if (x0 > x1) {
        x0 ^= x1;
        x1 ^= x0;
        x0 ^= x1;
    }
    if (z0 > z1) {
        z0 ^= z1;
        z1 ^= z0;
        z0 ^= z1;
    }
    gx0 = fastFloorf((f32)x0 / 640.0f);
    gz0 = fastFloorf((f32)z0 / 640.0f);
    gx1 = fastFloorf((f32)x1 / 640.0f);
    gz1 = fastFloorf((f32)z1 / 640.0f);

    count = 0;
    layer = 0;
    cellp = cells;
    cw = cellp;
    descp = (int*)gTrackGridOrigin;
    dw = descp;
    do {
        for (gx = gx0, p1 = cw, q1 = dw; gx <= gx1 && count < 16; gx++) {
            for (gz = gz0, p2 = p1, q2 = q1; gz <= gz1 && count < 16; gz++) {
                MapBlockData* blk = mapGetBlockAtPos(gx, gz, layer);
                if (blk != NULL) {
                    *p2 = blk;
                    q2[0] = gx * 0x280;
                    q2[2] = gz * 0x280;
                    p2++;
                    q2 += 3;
                    p1++;
                    q1 += 3;
                    cw++;
                    dw += 3;
                    count++;
                }
            }
        }
        layer++;
    } while (layer < 5);

    if (count == 0) {
        return cur;
    }

    {
        MapBlockData* c0 = cells[0];
        void* p = mapBlockGetPolygon(c0, 0);
        dmaflip = 0;
        offA = 0;
        cacheAllocAndCopy((u8*)p, c0->nPolygons << 3, &offA, &offB, 0x2000);
        cacheAllocAndCopy((u8*)c0->vertices, c0->vertexCount * 6, &offB, &offC, 0x2000);
    }
    i = 0;
    firstp = (int*)gTrackGridOrigin;
    f40 = (u16)flags & 0x40;
    f80 = (u16)flags & 0x80;
    f200 = (u16)flags & 0x200;
    f120 = (u16)flags & 0x120;
    f20 = (u16)flags & 0x20;
    f8 = (u16)flags & 8;
    f100 = (u16)flags & 0x100;
    f4 = (u16)flags & 4;
    last = count - 1;
    for (; i < count; i++) {
        MapBlockData* blk;
        int vb;
        u8* tri;
        s16 mask;
        s16 bit;
        int pos;
        int dxoff, dzoff;
        u8* tri0;

        bb = offA;
        vb = offB;
        if (i < last) {
            MapBlockData* next = cellp[1];
            u32 nextBase;
            void* p;
            int c13, c14;
            dmaflip ^= 0x2000u;
            nextBase = dmaflip + 0x2000;
            p = mapBlockGetPolygon(next, 0);
            offA = dmaflip;
            c13 = cacheAllocAndCopy((u8*)p, next->nPolygons << 3, &offA, &offB, nextBase);
            c14 = cacheAllocAndCopy((u8*)next->vertices, next->vertexCount * 6, &offB, &offC, nextBase);
            cacheQueueWait((u8)(c13 + c14));
        } else {
            cacheQueueWait(0);
        }

        blk = *cellp;
        relx0 = x0 - descp[0];
        relx1 = x1 - descp[0];
        relz0 = z0 - descp[2];
        relz1 = z1 - descp[2];
        descp[0] += gMapBlockOriginWorldX;
        descp[2] += gMapBlockOriginWorldZ;
        if (relx0 < 0) {
            relx0 = 0;
        }
        if (relx1 > 0x280) {
            relx1 = 0x280;
        }
        if (relz0 < 0) {
            relz0 = 0;
        }
        if (relz1 > 0x280) {
            relz1 = 0x280;
        }
        dxoff = descp[0] - firstp[0];
        dzoff = descp[2] - firstp[2];

        mask = 0;
        bit = 1;
        for (pos = 0; pos != 0x280; pos += 0x50) {
            if (relx0 <= pos + 0x50 && relx1 >= pos) {
                mask |= bit;
            }
            bit = bit << 1;
        }
        for (pos = 0; pos != 0x280; pos += 0x50) {
            if (relz0 <= pos + 0x50 && relz1 >= pos) {
                mask |= bit;
            }
            bit = bit << 1;
        }
        tri0 = blk->polygonGroups;
        tri = tri0;
        triEnd = (u32)tri0 + blk->polyGroupCount * 0x14;
        mask16 = mask;
        for (; (u32)tri < triEnd; tri += 0x14) {
            u32 tf = ((MapTriGroup*)tri)->flags;
            int t0;
            u8 type;
            u8* vq;

            if ((tf & 0x10) && f40) {
                continue;
            }
            if (!(tf & 4) && f80) {
                continue;
            }
            if (tf & 8) {
                if (tf & 1) {
                    continue;
                }
                if (f200) {
                    continue;
                }
                type = 4;
                if (f120 == 0) {
                    type |= 0x10;
                }
            } else {
                if ((tf & 2) && f20 == 0) {
                    continue;
                }
                type = 2;
            }
            if (((MapTriGroup*)tri)->minY + blk->collisionYOffset > y1) {
                continue;
            }
            if (((MapTriGroup*)tri)->maxY + blk->collisionYOffset < y0) {
                continue;
            }
            if (((MapTriGroup*)tri)->minX > relx1) {
                continue;
            }
            if (((MapTriGroup*)tri)->maxX < relx0) {
                continue;
            }
            if (((MapTriGroup*)tri)->minZ > relz1) {
                continue;
            }
            if (((MapTriGroup*)tri)->maxZ < relz0) {
                continue;
            }
            if (tf & 4) {
                type |= 8;
            }
            typeb = trackGetPackedSurfaceType((int*)tri);
            t0 = ((MapTriGroup*)tri)->firstTri;
            vq = (u8*)(bb + t0 * 8);
            vEnd = ((MapTriGroup*)tri)[1].firstTri;
            vertp = (f32*)(u32)verts;
            for (; t0 < vEnd; t0++, vq += 8) {
                u8* vo;
                s16* vp;
                f32* vf;
                u8 maxYi, minYi;
                u16* tw;
                int minX, maxX, minY, maxY, minZ, maxZ;
                int j;
                f32 mag;

                if ((mask16 & ((MapTriIndex*)vq)->cellMask & 0xff) == 0) {
                    continue;
                }
                if ((mask16 & ((MapTriIndex*)vq)->cellMask & 0xff00) == 0) {
                    continue;
                }
                vp = (s16*)(vb + ((MapTriIndex*)vq)->vert[0] * 6);
                minX = vp[0] >> 3;
                maxX = minX;
                minY = (vp[1] >> 3) + blk->collisionYOffset;
                maxY = minY;
                minZ = vp[2] >> 3;
                maxZ = minZ;
                ((TrackTriangle*)cur)->vx[0] = minX + dxoff;
                ((TrackTriangle*)cur)->vy[0] = minY;
                ((TrackTriangle*)cur)->vz[0] = minZ + dzoff;
                v0[0] = __OSs16tof32(&((TrackTriangle*)cur)->vx[0]);
                v0[1] = __OSs16tof32(&((TrackTriangle*)cur)->vy[0]);
                v0[2] = __OSs16tof32(&((TrackTriangle*)cur)->vz[0]);
                maxYi = 0;
                minYi = 0;
                j = 1;
                tw = &((MapTriIndex*)vq)->vert[1];
                vo = (u8*)(cur + 2);
                vf = verts;
                for (; j < 3; j++) {
                    int x, yy, z;
                    vp = (s16*)(vb + *tw * 6);
                    x = vp[0] >> 3;
                    yy = blk->collisionYOffset + (vp[1] >> 3);
                    z = vp[2] >> 3;
                    if (x > maxX) {
                        maxX = x;
                    } else if (x < minX) {
                        minX = x;
                    }
                    if (yy > maxY) {
                        maxY = yy;
                        maxYi = j;
                    } else if (yy < minY) {
                        minY = yy;
                        minYi = j;
                    }
                    if (z > maxZ) {
                        maxZ = z;
                    } else if (z < minZ) {
                        minZ = z;
                    }
                    ((TrackTriangle*)vo)->vx[0] = x + dxoff;
                    ((TrackTriangle*)vo)->vy[0] = yy;
                    ((TrackTriangle*)vo)->vz[0] = z + dzoff;
                    vf[0] = __OSs16tof32(((TrackTriangle*)vo)->vx);
                    vf[1] = __OSs16tof32(((TrackTriangle*)vo)->vy);
                    vf[2] = __OSs16tof32(((TrackTriangle*)vo)->vz);
                    tw++;
                    vo += 2;
                    vf += 3;
                }
                if (minY > y1) {
                    continue;
                }
                if (maxY < y0) {
                    continue;
                }
                if (minX > relx1) {
                    continue;
                }
                if (maxX < relx0) {
                    continue;
                }
                if (minZ > relz1) {
                    continue;
                }
                if (maxZ < relz0) {
                    continue;
                }

                PSVECSubtract((Vec*)v0, (Vec*)vertp, (Vec*)e0);
                PSVECSubtract((Vec*)vertp, (Vec*)verts2, (Vec*)e1);
                PSVECCrossProduct((Vec*)e0, (Vec*)e1, (Vec*)(cur + 4));
                mag = PSVECMag((Vec*)(cur + 4));
                if (!(mag > 0.0f)) {
                    continue;
                }
                mag = 1.0f / mag;
                PSVECScale((Vec*)(cur + 4), (Vec*)(cur + 4), mag);
                if (f8) {
                    if (((TrackTriangle*)cur)->planeN[1] >= 0.707f || ((TrackTriangle*)cur)->planeN[1] <= -0.707f) {
                        if (type != 4) {
                            continue;
                        }
                        if (f100 == 0) {
                            continue;
                        }
                    }
                }
                if (f4) {
                    if (((TrackTriangle*)cur)->planeN[1] < 0.707f && ((TrackTriangle*)cur)->planeN[1] > -0.707f) {
                        continue;
                    }
                }
                ((TrackTriangle*)cur)->planeD = -PSVECDotProduct((Vec*)(cur + 4), (Vec*)v0);
                if (doEdges) {
                    int k22, deg, j2;
                    f32* ep;
                    f32 one, eps;
                    PSVECSubtract((Vec*)verts2, (Vec*)v0, (Vec*)e2);
                    k22 = 0;
                    deg = 0;
                    j2 = 0;
                    ep = e0;
                    eps = 0.0f;
                    one = 1.0f;
                    do {
                        f32 m;
                        PSVECCrossProduct((Vec*)(cur + 4), (Vec*)ep, (Vec*)en);
                        m = PSVECMag((Vec*)en);
                        if (m > eps) {
                            m = one / m;
                            PSVECScale((Vec*)en, (Vec*)en, m);
                            *(f32*)(cur + (k22++) * 4 + 0x24) = en[0];
                            *(f32*)(cur + (k22++) * 4 + 0x24) = en[1];
                            *(f32*)(cur + (k22++) * 4 + 0x24) = en[2];
                        } else {
                            deg = 1;
                            break;
                        }
                        ep += 3;
                        j2++;
                    } while (j2 < 3);
                    if (deg) {
                        continue;
                    }
                }
                {
                    u32 tf2 = ((MapTriGroup*)tri)->flags;
                    u8 t2;
                    if (tf2 & 8) {
                        t2 = 0xe;
                    } else {
                        t2 = typeb;
                    }
                    if (tf2 & 0x20) {
                        type |= 0x40;
                    }
                    *(s8*)&((TrackTriangle*)cur)->surfaceType = t2;
                    ((TrackTriangle*)cur)->minMaxY = (u8)((maxYi << 4) | minYi);
                    ((TrackTriangle*)cur)->flags = type;
                    cur += 0x4c;
                    if ((u32)cur >= gTrackTriangleBufferEnd) {
                        return cur;
                    }
                }
            }
        }
        cellp++;
        descp += 3;
    }
    return cur;
}

void trackIntersectBroadphase(GameObject* obj, TrackQueryBounds* ranges, u32 queryMask, int b) {
    f32 x0 = (f32)(ranges->minX - 5);
    f32 x1 = (f32)(ranges->maxX + 5);
    f32 y0 = (f32)(ranges->minY - 5);
    f32 y1 = (f32)(ranges->maxY + 5);
    f32 z0 = (f32)(ranges->minZ - 5);
    f32 z1 = (f32)(ranges->maxZ + 5);
    ObjAnimComponent** resetObjects;
    int flag80;
    s16 i;
    ObjAnimComponent* resetObj;
    int* model;
    int masked;
    int count;

    {
        int cur;
        TrackBlockDescriptor* desc;
        TrackBlockDescriptor* descEnd;

        desc = gTrackBlockDescriptors;
        desc->object = NULL;
        desc->firstTriangle = 0;
        desc++;
        descEnd = &gTrackBlockDescriptors[20];
        gTrackTriangleBufferEnd = (u32)(gTrackTriangleBuffer + 1200);
        masked = queryMask & 0xffff;
        if ((masked & 0x10) != 0) {
            cur = (int)gTrackTriangleBuffer;
        } else {
            cur = trackBuildBlockTriangles((int)gTrackTriangleBuffer, x0, y0, z0, x1, y1, z1, queryMask, b);
        }
        if (cur < gTrackTriangleBufferEnd && (masked & 1) && obj != NULL) {
            ObjAnimComponent** t = ObjHitReact_GetResetObjects(&count);
            i = 0;
            resetObjects = t;
            flag80 = masked & 0x80;
            for (; i < count; resetObjects++, i++) {
                ObjHitsPriorityState* hitState;
                ObjHitboxTransformState* transformState;
                ModelFileHeader* hdr;
                f32 r, c;

                resetObj = *resetObjects;
                if (flag80 && (resetObj->modelInstance->flags & OBJDEF_FLAG_RELATED_TO_HIT_DETECT)) {
                    continue;
                }
                hitState = (ObjHitsPriorityState*)resetObj->hitReactState;
                if (hitState == NULL) {
                    continue;
                }
                transformState = resetObj->hitboxTransformState;
                if (transformState == NULL) {
                    continue;
                }
                if (transformState->resetFrames != 0) {
                    continue;
                }
                if (transformState->pad10E != 0) {
                    continue;
                }
                model = (int*)resetObj->banks[(s8)hitState->stateIndex];
                if (model == NULL) {
                    continue;
                }
                hdr = (ModelFileHeader*)*model;
                if (hdr->collisionBlockCount == 0) {
                    continue;
                }
                r = (f32)(u32)modelFileHeaderGetCullDistance(hdr);
                c = resetObj->worldPosX;
                if (x1 < c - r) {
                    continue;
                }
                if (x0 > c + r) {
                    continue;
                }
                c = resetObj->worldPosY;
                if (y1 < c - r) {
                    continue;
                }
                if (y0 > c + r) {
                    continue;
                }
                c = resetObj->worldPosZ;
                if (z1 < c - r) {
                    continue;
                }
                if (z0 > c + r) {
                    continue;
                }

                desc->currentCollisionMatrix = (f32*)resetObj->hitboxTransformState->matrices +
                                               ((resetObj->hitboxTransformState->activeMatrixIndex + 2) << 4);
                desc->currentMatrix = (f32*)resetObj->hitboxTransformState->matrices +
                                      (resetObj->hitboxTransformState->activeMatrixIndex << 4);
                desc->alternateCollisionMatrix = (f32*)resetObj->hitboxTransformState->matrices +
                                                 (((resetObj->hitboxTransformState->activeMatrixIndex ^ 1) + 2) << 4);
                desc->alternateMatrix = (f32*)resetObj->hitboxTransformState->matrices +
                                        ((resetObj->hitboxTransformState->activeMatrixIndex ^ 1) << 4);

                desc->firstTriangle = (s16)((cur - (int)gTrackTriangleBuffer) / 0x4c);
                desc->object = resetObj;
                cur = trackBuildModelTriangles(cur, desc, model, 1.0f, x0, y0, z0, x1, y1, z1, queryMask);
                desc++;
                if (cur >= gTrackTriangleBufferEnd) {
                    break;
                }
                if (desc >= descEnd) {
                    break;
                }
            }
        }
        gTrackTriangleCount = (s16)((cur - (int)gTrackTriangleBuffer) / 0x4c);
        gActiveTrackBlockCount = (u8)(desc - gTrackBlockDescriptors);
        desc->firstTriangle = gTrackTriangleCount;
    }
}

void hitDetect_calcSweptSphereBounds(TrackQueryBounds* boundsOut, f32* startPoints, f32* endPoints, f32* radii,
                                     int pointCount) {
    int i;

    boundsOut->minX = 1000000;
    boundsOut->maxX = -1000000;
    boundsOut->minY = 1000000;
    boundsOut->maxY = -1000000;
    boundsOut->minZ = 1000000;
    boundsOut->maxZ = -1000000;
    for (i = pointCount; i != 0; i--) {
        if (startPoints[0] - radii[0] < boundsOut->minX) {
            boundsOut->minX = (int)(startPoints[0] - radii[0]);
        }
        if (startPoints[0] + radii[0] > boundsOut->maxX) {
            boundsOut->maxX = (int)(startPoints[0] + radii[0]);
        }
        if (startPoints[1] - radii[0] < boundsOut->minY) {
            boundsOut->minY = (int)(startPoints[1] - radii[0]);
        }
        if (startPoints[1] + radii[0] > boundsOut->maxY) {
            boundsOut->maxY = (int)(startPoints[1] + radii[0]);
        }
        if (startPoints[2] - radii[0] < boundsOut->minZ) {
            boundsOut->minZ = (int)(startPoints[2] - radii[0]);
        }
        if (startPoints[2] + radii[0] > boundsOut->maxZ) {
            boundsOut->maxZ = (int)(startPoints[2] + radii[0]);
        }
        if (endPoints[0] - radii[0] < boundsOut->minX) {
            boundsOut->minX = (int)(endPoints[0] - radii[0]);
        }
        if (endPoints[0] + radii[0] > boundsOut->maxX) {
            boundsOut->maxX = (int)(endPoints[0] + radii[0]);
        }
        if (endPoints[1] - radii[0] < boundsOut->minY) {
            boundsOut->minY = (int)(endPoints[1] - radii[0]);
        }
        if (endPoints[1] + radii[0] > boundsOut->maxY) {
            boundsOut->maxY = (int)(endPoints[1] + radii[0]);
        }
        if (endPoints[2] - radii[0] < boundsOut->minZ) {
            boundsOut->minZ = (int)(endPoints[2] - radii[0]);
        }
        if (endPoints[2] + radii[0] > boundsOut->maxZ) {
            boundsOut->maxZ = (int)(endPoints[2] + radii[0]);
        }
        startPoints += 3;
        endPoints += 3;
        radii += 1;
    }
}

void* trackGetBlockDescriptors(u32* outVal) {
    *outVal = gActiveTrackBlockCount;
    return gTrackBlockDescriptors;
}

void trackGetGridOrigin(int** outOrigin) {
    *outOrigin = (int*)gTrackGridOrigin;
}

void trackGetTriangleBuffer(int* outCount, int* outTable) {
    TrackBlockDescriptor* descriptors = gTrackBlockDescriptors;
    *outCount = descriptors[gActiveTrackBlockCount].firstTriangle;
    *outTable = (int)gTrackTriangleBuffer;
}

void trackInitCollisionBuffers(void) {
    int i;
    int off;
    if (gTrackTriangleBuffer == NULL) {
        gTrackTriangleBuffer = mmAlloc(1200 * sizeof(TrackTriangle), 0xffff00ff, 0);
        gIntersectLinePool = (int)mmAlloc(0x5dc0, 0xffff00ff, 0);
        gIntersectPoints = mmAlloc(0x4fb0, 0xffff00ff, 0);
        gIntersectLineIndexTable = (int)mmAlloc(0xbb8, 0xffff00ff, 0);
        gMapDynamicSlots = mmAlloc(MAP_DYNAMIC_SLOT_COUNT * sizeof(MapDynamicSlot), 0xffff00ff, 0);
    }
    off = 0;
    for (i = 0; i < 4; i++) {
        int j;
        for (j = 0; j < 16; j++) {
            ((MapDynamicSlot*)((u8*)gMapDynamicSlots + off))[j].cooldown = 0;
        }
        off += sizeof(MapDynamicSlot) * 16;
    }
    gIntersectLineCount = 0;
    gIntersectPointCount = 0;
    mapBlockFlag = 0;
    gIntersectRebuildRequested = 0;
}

u8 gTrackGridOrigin[0x104];
