#define TRACK_BBOX_FLAGS_S8
#include "dlls/object_descriptor.h"
#include "dolphin/os/OSReport.h"
#include "main/dll/rom_curve_def.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/track_bbox_api.h"
#include "main/voxmaps.h"
#include "main/dll/dll_0015_curves.h"
#include "main/obj_list.h"
#include "main/vecmath_distance_api.h"
#include "main/vecmath.h"
#include "main/shader_api.h"
#include "string.h"
#include "main/dll/objfsa_internal.h"

int nRomCurves;
RomCurveDef* gRomCurveLastFindStart;
RomCurveDef* gRomCurveLastFindEnd;

int RomCurve_initFromCurveId(RomCurveWalker* state, GameObject* unusedObj, int startCurveId,
                             RomCurveInterface* unusedInterface);
int RomCurve_goNextPointIndexed(RomCurveWalker* state, int pickIdx);
void RomCurve_setNextNode(void* walker, void* curve);
int RomCurve_initCurve(RomCurveWalker* state, GameObject* obj, int* curveTypes, int curveType, f32 maxDistance);
int RomCurve_findShortestPathLink(RomCurveDef* startCurve, int unused1, int unused2, int* previousCurveId);
int Objfsa_GetNearestAdjacentLink(RomCurveDef* curve, int preferredNeighborId, f32 x, f32 y, f32 z);
int curves_findEnclosingLoopOfType17(f32 x, f32 y, f32 z);
int curves_isNotPoint(RomCurveDef* curve);
int curves_isPoint(RomCurveDef* curve);
void RomCurve_getLastFindSegment(RomCurveDef** startOut, RomCurveDef** endOut);
void* RomCurve_getCurves(int* outCount);
void RomCurve_initialise(void);

#define ROMCURVE_TANGENT_SCALE         2.0f
#define ROMCURVE_ANGLE_PI              3.1415927f
#define ROMCURVE_HALF_CIRCLE_ANGLE     32768.0f
#define ROMCURVE_NEG_ONE               -1.0f
#define ROMCURVE_ONE                   1.0f
#define ROMCURVE_ZERO                  0.0f
#define ROMCURVE_VERTICAL_OFFSET       10.0f
#define ROMCURVE_HALF                  0.5f
#define ROMCURVE_FIND_DISTANCE_INITIAL 3.4028235e38f

int RomCurve_getForwardControlPointId(RomCurveDef* curve, int exclude, int pickIdx);
int RomCurve_getControlPointId(RomCurveDef* curve, int exclude, int pickIdx);
int RomCurve_segmentIntersectsOriginRayXZ(f32 x, f32 unusedY, f32 z, RomCurveDef* a, RomCurveDef* b, f32 unusedW);

RomCurveDef* romCurves[ROMCURVE_MAX_CURVES];

#define OBJFSA_CORNER(BASE, OFF, POSOFF) (f32)((f32) * (s8*)(OFF) * scale + *(f32*)((BASE) + (POSOFF)))
#define OBJFSA_SET_PLANE(P, K, XA, ZA)                                                                                 \
    len = sqrtf(dxn * dxn + dzn * dzn);                                                                                \
    if (len) {                                                                                                         \
        dxn = dxn / len;                                                                                               \
        dzn = dzn / len;                                                                                               \
    }                                                                                                                  \
    (P).planes[K].normalX = (s16)(32767.0f * dxn);                                                                     \
    (P).planes[K].normalZ = (s16)(32767.0f * dzn);                                                                     \
    (P).planeOffsets[K] = -((f32)(P).planes[K].normalX * (XA) + (f32)(P).planes[K].normalZ * (ZA))
#define OBJFSA_NEWPATCH (patchBase[0][gObjfsaPatchCount])
#define OBJFSA_SET_NEWPATCH_PLANE(K, DXE, DZE, XA, ZA)                                                                 \
    pl = &OBJFSA_NEWPATCH.planes[K];                                                                                   \
    po = &OBJFSA_NEWPATCH.planeOffsets[K];                                                                             \
    dxn = (DXE);                                                                                                       \
    dzn = (DZE);                                                                                                       \
    len = sqrtf(dxn * dxn + dzn * dzn);                                                                                \
    if (len) {                                                                                                         \
        dxn = dxn / len;                                                                                               \
        dzn = dzn / len;                                                                                               \
    }                                                                                                                  \
    pl->normalX = (s16)(32767.0f * dxn);                                                                               \
    pl->normalZ = (s16)(32767.0f * dzn);                                                                               \
    *(po) = -(pl->normalX * (XA) + pl->normalZ * (ZA))

static f32 RomCurve_scaleTangent(f32 t) {
    return ROMCURVE_TANGENT_SCALE * t;
}

static inline f32 RomCurveNode_GetHermiteTangent(void** nodePtr, int angleOffset, int useCos);

static inline ObjfsaPatch* Objfsa_GetPatch(int patchIndex) {
    return &gObjfsaPatches[patchIndex];
}

static inline ObjfsaStorage* Objfsa_GetStorage(ObjfsaPatch* patches) {
    return (ObjfsaStorage*)patches;
}

static inline ObjfsaWalkGroup* Objfsa_GetWalkGroup(int groupIndex) {
    return &gObjfsaWalkGroups[groupIndex];
}

static inline u8* Objfsa_GetPatchGroupPatchList(int groupIndex) {
    return Objfsa_GetWalkGroup(groupIndex)->patchIndices;
}

static inline u8 Objfsa_IsWalkGroupActive(int groupIndex) {
    return gObjfsaWalkGroupActive[groupIndex];
}

static inline int Objfsa_IsPointInsidePatch(const float* point, const ObjfsaPatch* patch) {
    int edgeIndex;

    if (point[1] >= patch->maxY || patch->minY >= point[1]) {
        return 0;
    }

    for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++) {
        if (patch->planeOffsets[edgeIndex] + point[0] * patch->planes[edgeIndex].normalX +
                point[2] * patch->planes[edgeIndex].normalZ >
            0.0f) {
            return 0;
        }
    }
    return 1;
}

static inline int Objfsa_IsPointInsideWalkGroup(const float* point, const ObjfsaWalkGroup* walkGroup) {
    int edgeIndex;

    if (point[1] >= walkGroup->maxY || walkGroup->minY >= point[1]) {
        return 0;
    }

    for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++) {
        if (walkGroup->planeOffsets[edgeIndex] + point[0] * walkGroup->planes[edgeIndex].normalX +
                point[2] * walkGroup->planes[edgeIndex].normalZ >
            0.0f) {
            return 0;
        }
    }
    return 1;
}

static inline u16 Objfsa_GetLinkedWalkGroup(u16 patchGroupId, u32 currentWalkGroupIndex) {
    if (((__cntlzw(0xff - currentWalkGroupIndex) >> 5) & patchGroupId) != 0) {
        return (patchGroupId & 0xff00) >> 8;
    }
    return patchGroupId & 0xff;
}

static inline RomCurveDef* Objfsa_FindRomCurveById(int curveId) {
    int hi;
    int lo;
    int mid;
    u32 id;

    if (curveId < 0) {
        return NULL;
    }

    hi = nRomCurves - 1;
    lo = 0;
    id = curveId;
    while (hi >= lo) {
        mid = (hi + lo) >> 1;
        if (id > romCurves[mid]->id) {
            lo = mid + 1;
        } else if (id < romCurves[mid]->id) {
            hi = mid - 1;
        } else {
            return romCurves[mid];
        }
    }

    return NULL;
}

static inline u32 RomCurve_GetId(RomCurveDef* curve) {
    return curve->id;
}

static inline int RomCurve_IsLinkIdValid(int linkId) {
    return -1 < linkId;
}

static inline RomCurveDef* RomCurve_FindByIdInline(u32 curveId) {
    int high;
    int low;
    int mid;

    if ((s32)curveId < 0) {
        return NULL;
    }

    high = nRomCurves - 1;
    low = 0;
    while (high >= low) {
        mid = (high + low) >> 1;
        if (curveId > RomCurve_GetId(romCurves[mid])) {
            low = mid + 1;
        } else if (curveId < RomCurve_GetId(romCurves[mid])) {
            high = mid - 1;
        } else {
            return romCurves[mid];
        }
    }

    return NULL;
}

static inline RomCurveDef* RomCurve_FindByIdWithLimit(u32 curveId, int lim) {
    int high;
    int low;
    int mid;

    if ((s32)curveId < 0) {
        return NULL;
    }

    high = lim;
    low = 0;
    while (high >= low) {
        mid = (high + low) >> 1;
        if (curveId > RomCurve_GetId(romCurves[mid])) {
            low = mid + 1;
        } else if (curveId < RomCurve_GetId(romCurves[mid])) {
            high = mid - 1;
        } else {
            return romCurves[mid];
        }
    }

    return NULL;
}

static inline int Objfsa_RomCurveIsForwardEnd(RomCurveDef* curve) {
    int slot;
    RomCurveDef* c = curve;

    for (slot = 0; slot < 4; slot++) {
        if (c->linkIds[slot] != -1 && (c->backwardLinkMask & (1 << slot)) == 0) {
            return 0;
        }
    }
    return 1;
}

static inline int RomCurve_CollectForwardLinks(RomCurveDef* curve, int* ids) {
    int link;
    int count;
    u32 mask;
    s32* lp;
    int i;

    count = 0;
    mask = 1;
    lp = curve->linkIds;
    for (i = 0; i < ROMCURVE_LINK_COUNT; i++) {
        link = *lp++;
        if ((link > -1) && ((curve->backwardLinkMask & mask) == 0) && (link != 0)) {
            ids[count++] = link;
        }
        mask = mask << 1;
    }
    return count;
}

static inline int RomCurve_CollectBackwardLinks(RomCurveDef* curve, int* ids) {
    int link;
    int count;
    u32 mask;
    s32* lp;
    int i;

    count = 0;
    mask = 1;
    lp = curve->linkIds;
    for (i = 0; i < ROMCURVE_LINK_COUNT; i++) {
        link = *lp++;
        if ((link > -1) && ((curve->backwardLinkMask & mask) != 0) && (link != 0)) {
            ids[count++] = link;
        }
        mask = mask << 1;
    }
    return count;
}

static inline f32 RomCurveNode_GetHermiteTangent(void** nodePtr, int angleOffset, int useCos) {
    f32 angle;
    f32 trig;

    angle = 3.1415927f * (f32)((s32) * (s8*)((char*)*nodePtr + angleOffset) << 8) / 32768.0f;
    if (useCos) {
        trig = mathCosf(angle);
    } else {
        trig = mathSinf(angle);
    }
    trig = (f32)(u32)((RomCurveDef*)*nodePtr)->tangentMag * trig;
    return 2.0f * trig;
}

static inline int RomCurve_pickRandomControlPointId_2A(RomCurveDef* curve) {
    int count;
    u32 mask;
    int i;
    int result;
    int candidates[4];

    count = 0;
    mask = 1;
    for (i = 0; i < 4; i = i + 1) {
        if ((curve->linkIds[i] > -1) && ((curve->backwardLinkMask & mask) == 0) && (curve->linkIds[i] != -1)) {
            candidates[count++] = curve->linkIds[i];
        }
        mask = mask << 1;
    }
    if (count != 0) {
        result = candidates[randomGetRange(0, count - 1)];
    } else {
        result = -1;
    }
    return result;
}

static inline int RomCurve_pickRandomControlPointId_2B(RomCurveDef* curve) {
    int count;
    u32 mask;
    int i;
    int result;
    int candidates[4];

    count = 0;
    mask = 1;
    for (i = 0; i < 4; i = i + 1) {
        if ((curve->linkIds[i] > -1) && ((curve->backwardLinkMask & mask) != 0) && (curve->linkIds[i] != -1)) {
            candidates[count++] = curve->linkIds[i];
        }
        mask = mask << 1;
    }
    if (count != 0) {
        result = candidates[randomGetRange(0, count - 1)];
    } else {
        result = -1;
    }
    return result;
}

#define ROMCURVE_REFRESH_CONTROL(secondNode)                                                                           \
    state->hermX2[0] = ((RomCurveDef*)state->currentNode)->x;                                                          \
    state->hermX2[1] = ((RomCurveDef*)state->secondNode)->x;                                                           \
    t = (float)(u32)((RomCurveDef*)state->currentNode)->tangentMag *                                                   \
        mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->currentNode)->yaw << 8) /                      \
                 ROMCURVE_HALF_CIRCLE_ANGLE);                                                                          \
    state->hermX2[2] = ROMCURVE_TANGENT_SCALE * t;                                                                     \
    t = (float)(u32)((RomCurveDef*)state->secondNode)->tangentMag *                                                    \
        mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->secondNode)->yaw << 8) /                       \
                 ROMCURVE_HALF_CIRCLE_ANGLE);                                                                          \
    state->hermX2[3] = ROMCURVE_TANGENT_SCALE * t;                                                                     \
    state->hermY2[0] = ((RomCurveDef*)state->currentNode)->y;                                                          \
    state->hermY2[1] = ((RomCurveDef*)state->secondNode)->y;                                                           \
    t = (float)(u32)((RomCurveDef*)state->currentNode)->tangentMag *                                                   \
        mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->currentNode)->pitch << 8) /                    \
                 ROMCURVE_HALF_CIRCLE_ANGLE);                                                                          \
    state->hermY2[2] = ROMCURVE_TANGENT_SCALE * t;                                                                     \
    t = (float)(u32)((RomCurveDef*)state->secondNode)->tangentMag *                                                    \
        mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->secondNode)->pitch << 8) /                     \
                 ROMCURVE_HALF_CIRCLE_ANGLE);                                                                          \
    state->hermY2[3] = ROMCURVE_TANGENT_SCALE * t;                                                                     \
    state->hermZ2[0] = ((RomCurveDef*)state->currentNode)->z;                                                          \
    state->hermZ2[1] = ((RomCurveDef*)state->secondNode)->z;                                                           \
    t = (float)(u32)((RomCurveDef*)state->currentNode)->tangentMag *                                                   \
        mathCosf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->currentNode)->yaw << 8) /                      \
                 ROMCURVE_HALF_CIRCLE_ANGLE);                                                                          \
    state->hermZ2[2] = ROMCURVE_TANGENT_SCALE * t;                                                                     \
    t = (float)(u32)((RomCurveDef*)state->secondNode)->tangentMag *                                                    \
        mathCosf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->secondNode)->yaw << 8) /                       \
                 ROMCURVE_HALF_CIRCLE_ANGLE);                                                                          \
    state->hermZ2[3] = ROMCURVE_TANGENT_SCALE * t

int RomCurve_initFromCurveId(RomCurveWalker* state, GameObject* unusedObj, int startCurveId,
                             RomCurveInterface* unusedInterface) {
    char* stateBytes;
    RomCurveDef* currentCurve;
    int nextId;
    RomCurveDef* nextCurve;
    f32 t;

    if (state == NULL) {
        return 1;
    }
    if (startCurveId != -1) {
        stateBytes = (char*)state;
        if (state->reverse != 0) {
            state->currentNode = Objfsa_FindRomCurveById(startCurveId);
            nextId = RomCurve_pickRandomControlPointId_2A(state->currentNode);
            if (nextId == -1) {
                return 1;
            }
            startCurveId = nextId;
        }

        currentCurve = Objfsa_FindRomCurveById(startCurveId);
        state->currentNode = currentCurve;
        if (currentCurve == 0) {
            state->currentNode = NULL;
            return 1;
        }

        if (state->reverse != 0) {
            nextId = RomCurve_pickRandomControlPointId_2B(state->currentNode);
        } else {
            nextId = RomCurve_pickRandomControlPointId_2A(state->currentNode);
        }
        if (nextId == -1) {
            return 1;
        }

        nextCurve = Objfsa_FindRomCurveById(nextId);
        state->nextNode = nextCurve;
        if (nextCurve == 0) {
            state->nextNode = NULL;
            return 1;
        }

        ROMCURVE_REFRESH_CONTROL(nextNode);
        if (RomCurve_goNextPoint(state) != 0) {
            return 1;
        }

        state->eval = Curve_EvalHermite;
        state->coeffFn = Curve_BuildHermiteCoeffs;
        state->coeffX = state->hermX;
        state->coeffY = state->hermY;
        state->coeffZ = state->hermZ;
        state->moveNetwork = 8;
        curvesMove(&state->curve);
        return 0;
    }
    return 1;
}

int RomCurve_getControlPointId(RomCurveDef* curve, int exclude, int pickIdx) {
    int candidates[4];
    int neighbor;
    int count = 0;
    u32 mask = 1;
    int i;
    for (i = 0; i < 4; i++) {
        neighbor = curve->linkIds[i];
        if (neighbor > -1 && ((s32)curve->backwardLinkMask & mask) != 0 && neighbor != exclude) {
            candidates[count++] = neighbor;
        }
        mask <<= 1;
    }
    if (count != 0) {
        if (pickIdx > count - 1) {
            pickIdx = count - 1;
        }
        if (pickIdx == -1) {
            pickIdx = randomGetRange(0, count - 1);
        }
        return candidates[pickIdx];
    }
    return -1;
}

int RomCurve_getForwardControlPointId(RomCurveDef* curve, int exclude, int pickIdx) {
    int candidates[4];
    int neighbor;
    int count = 0;
    u32 mask = 1;
    int i;
    for (i = 0; i < 4; i++) {
        neighbor = curve->linkIds[i];
        if (neighbor > -1 && ((s32)curve->backwardLinkMask & mask) == 0 && neighbor != exclude) {
            candidates[count++] = neighbor;
        }
        mask <<= 1;
    }
    if (count != 0) {
        if (pickIdx > count - 1) {
            pickIdx = count - 1;
        }
        if (pickIdx == -1) {
            pickIdx = randomGetRange(0, count - 1);
        }
        return candidates[pickIdx];
    }
    return -1;
}

int RomCurve_goNextPointIndexed(RomCurveWalker* state, int pickIdx) {
    char* stateBytes;
    int nextId;
    RomCurveDef* nextCurve;
    f32 t;

    if (state == NULL) {
        return 1;
    }

    stateBytes = (char*)state;
    if (state->currentNode == NULL || state->nextNode == NULL) {
        return 1;
    }

    state->previousNode = state->currentNode;
    state->currentNode = state->nextNode;
    memcpy(state->hermX, state->hermX2, sizeof(state->hermX));
    memcpy(state->hermY, state->hermY2, sizeof(state->hermY));
    memcpy(state->hermZ, state->hermZ2, sizeof(state->hermZ));

    if (state->reverse != 0) {
        nextId = RomCurve_getControlPointId(state->currentNode, -1, pickIdx);
    } else {
        nextId = RomCurve_getForwardControlPointId(state->currentNode, -1, pickIdx);
    }

    if (nextId != -1) {
        nextCurve = Objfsa_FindRomCurveById(nextId);
        state->nextNode = nextCurve;
        if (state->nextNode != NULL) {
            if (state->reverse != 0) {
                ROMCURVE_REFRESH_CONTROL(previousNode);
            } else {
                ROMCURVE_REFRESH_CONTROL(nextNode);
            }

            if (state->moveNetwork != 0) {
                curvesSetupMoveNetworkCurve(&state->curve);
            }

            if (state->reverse != 0) {
                Curve_AdvanceAlongPath(&state->curve, ROMCURVE_NEG_ONE);
            } else {
                Curve_AdvanceAlongPath(&state->curve, ROMCURVE_ONE);
            }
            return 0;
        }
    } else {
        state->nextNode = NULL;
    }
    return 1;
}

void RomCurve_setNextNode(void* walker, void* curve) {
    RomCurveWalker* state = walker;
    f32 t;
    if (curve != 0 && curve != state->nextNode) {
        state->nextNode = curve;
        state->hermX2[1] = ((RomCurveDef*)state->nextNode)->x;
        t = (float)(u32)((RomCurveDef*)state->nextNode)->tangentMag *
            mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->nextNode)->yaw << 8) /
                     ROMCURVE_HALF_CIRCLE_ANGLE);
        state->hermX2[3] = ROMCURVE_TANGENT_SCALE * t;
        state->hermY2[1] = ((RomCurveDef*)state->nextNode)->y;
        t = (float)(u32)((RomCurveDef*)state->nextNode)->tangentMag *
            mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->nextNode)->pitch << 8) /
                     ROMCURVE_HALF_CIRCLE_ANGLE);
        state->hermY2[3] = ROMCURVE_TANGENT_SCALE * t;
        state->hermZ2[1] = ((RomCurveDef*)state->nextNode)->z;
        t = (float)(u32)((RomCurveDef*)state->nextNode)->tangentMag *
            mathCosf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->nextNode)->yaw << 8) /
                     ROMCURVE_HALF_CIRCLE_ANGLE);
        state->hermZ2[3] = ROMCURVE_TANGENT_SCALE * t;
    }
}

int RomCurve_setClosed(RomCurveWalker* state, int closed) {
    float savedPhase;
    float t;
    void* tmpCurve;

    if (closed == state->reverse) {
        return 0;
    }
    if (state->currentNode == 0 || state->previousNode == 0) {
        return 1;
    }

    savedPhase = state->phase;
    state->reverse = closed;
    tmpCurve = state->previousNode;
    state->previousNode = state->nextNode;
    state->nextNode = tmpCurve;

    state->hermX2[0] = ((RomCurveDef*)state->currentNode)->x;
    state->hermX2[1] = ((RomCurveDef*)state->nextNode)->x;
    t = (float)(u32)((RomCurveDef*)state->currentNode)->tangentMag *
        mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->currentNode)->yaw << 8) /
                 ROMCURVE_HALF_CIRCLE_ANGLE);
    state->hermX2[2] = ROMCURVE_TANGENT_SCALE * t;
    t = (float)(u32)((RomCurveDef*)state->nextNode)->tangentMag *
        mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->nextNode)->yaw << 8) /
                 ROMCURVE_HALF_CIRCLE_ANGLE);
    state->hermX2[3] = ROMCURVE_TANGENT_SCALE * t;

    state->hermY2[0] = ((RomCurveDef*)state->currentNode)->y;
    state->hermY2[1] = ((RomCurveDef*)state->nextNode)->y;
    t = (float)(u32)((RomCurveDef*)state->currentNode)->tangentMag *
        mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->currentNode)->pitch << 8) /
                 ROMCURVE_HALF_CIRCLE_ANGLE);
    state->hermY2[2] = ROMCURVE_TANGENT_SCALE * t;
    t = (float)(u32)((RomCurveDef*)state->nextNode)->tangentMag *
        mathSinf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->nextNode)->pitch << 8) /
                 ROMCURVE_HALF_CIRCLE_ANGLE);
    state->hermY2[3] = ROMCURVE_TANGENT_SCALE * t;

    state->hermZ2[0] = ((RomCurveDef*)state->currentNode)->z;
    state->hermZ2[1] = ((RomCurveDef*)state->nextNode)->z;
    t = (float)(u32)((RomCurveDef*)state->currentNode)->tangentMag *
        mathCosf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->currentNode)->yaw << 8) /
                 ROMCURVE_HALF_CIRCLE_ANGLE);
    state->hermZ2[2] = ROMCURVE_TANGENT_SCALE * t;
    t = (float)(u32)((RomCurveDef*)state->nextNode)->tangentMag *
        mathCosf(ROMCURVE_ANGLE_PI * (float)((s32)((RomCurveDef*)state->nextNode)->yaw << 8) /
                 ROMCURVE_HALF_CIRCLE_ANGLE);
    state->hermZ2[3] = ROMCURVE_TANGENT_SCALE * t;

    if (RomCurve_goNextPoint(state) != 0) {
        return 1;
    }

    state->eval = Curve_EvalHermite;
    state->coeffFn = Curve_BuildHermiteCoeffs;
    state->coeffX = state->hermX;
    state->coeffY = state->hermY;
    state->coeffZ = state->hermZ;
    state->moveNetwork = 8;
    curvesMove(&state->curve);
    state->phase = savedPhase;
    return 0;
}

u8 RomCurve_goNextPoint(RomCurveWalker* state) {
    char* stateBytes;
    int neighborId;
    RomCurveDef* nextCurve;
    float t;

    if (state == NULL) {
        return 1;
    }
    stateBytes = (char*)state;
    if (state->currentNode == NULL || state->nextNode == NULL) {
        return 1;
    }

    state->previousNode = state->currentNode;
    state->currentNode = state->nextNode;
    memcpy(state->hermX, state->hermX2, sizeof(state->hermX));
    memcpy(state->hermY, state->hermY2, sizeof(state->hermY));
    memcpy(state->hermZ, state->hermZ2, sizeof(state->hermZ));

    if (state->reverse != 0) {
        neighborId = RomCurve_pickRandomControlPointId_2B(state->currentNode);
    } else {
        neighborId = RomCurve_pickRandomControlPointId_2A(state->currentNode);
    }

    if (neighborId != -1) {
        nextCurve = Objfsa_FindRomCurveById(neighborId);

        state->nextNode = nextCurve;
        if (state->nextNode != NULL) {
            if (state->reverse != 0) {
                ROMCURVE_REFRESH_CONTROL(previousNode);
            } else {
                ROMCURVE_REFRESH_CONTROL(nextNode);
            }

            if (state->moveNetwork != 0) {
                curvesSetupMoveNetworkCurve(&state->curve);
            }
            if (state->reverse != 0) {
                Curve_AdvanceAlongPath(&state->curve, ROMCURVE_NEG_ONE);
            } else {
                Curve_AdvanceAlongPath(&state->curve, ROMCURVE_ONE);
            }
            return 0;
        }
    } else {
        state->nextNode = NULL;
    }
    return 1;
}

int RomCurve_initCurve(RomCurveWalker* state, GameObject* obj, int* curveTypes, int curveType, f32 maxDistance) {
    char* stateBytes;
    int curveId;
    RomCurveDef* currentCurve;
    int nextId;
    RomCurveDef* nextCurve;
    RomCurveDef* distanceCurve;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    f32 t;

    if (state == NULL) {
        return 1;
    }

    stateBytes = (char*)state;
    curveId = curves_findNearObj(obj, curveTypes, 1, curveType, 0xc);
    if (curveId != -1) {
        if (state->reverse != 0) {
            state->currentNode = Objfsa_FindRomCurveById(curveId);
            nextId = RomCurve_pickRandomControlPointId_2A(state->currentNode);
            if (nextId == -1) {
                return 1;
            }
            curveId = nextId;
        }

        currentCurve = Objfsa_FindRomCurveById(curveId);
        state->currentNode = currentCurve;
        if (currentCurve == 0) {
            state->currentNode = NULL;
            return 1;
        }

        if (state->reverse != 0) {
            nextId = RomCurve_pickRandomControlPointId_2B(state->currentNode);
        } else {
            nextId = RomCurve_pickRandomControlPointId_2A(state->currentNode);
        }
        if (nextId == -1) {
            return 1;
        }

        nextCurve = Objfsa_FindRomCurveById(nextId);
        state->nextNode = nextCurve;
        if (nextCurve == 0) {
            state->nextNode = NULL;
            return 1;
        }

        if (maxDistance) {
            if (state->reverse != 0) {
                distanceCurve = (RomCurveDef*)state->nextNode;
                dx = distanceCurve->x - obj->anim.localPosX;
                dy = distanceCurve->y - obj->anim.localPosY;
                dz = distanceCurve->z - obj->anim.localPosZ;
            } else {
                distanceCurve = (RomCurveDef*)state->currentNode;
                dx = distanceCurve->x - obj->anim.localPosX;
                dy = distanceCurve->y - obj->anim.localPosY;
                dz = distanceCurve->z - obj->anim.localPosZ;
            }
            distance = sqrtf(dx * dx + dy * dy + dz * dz);
            if (distance > maxDistance) {
                return 1;
            }
        }

        ROMCURVE_REFRESH_CONTROL(nextNode);
        if (RomCurve_goNextPoint(state) != 0) {
            return 1;
        }

        state->eval = Curve_EvalHermite;
        state->coeffFn = Curve_BuildHermiteCoeffs;
        state->coeffX = state->hermX;
        state->coeffY = state->hermY;
        state->coeffZ = state->hermZ;
        state->moveNetwork = 8;
        curvesMove(&state->curve);
        return 0;
    }
    return 1;
}
int curves_findNearObj(GameObject* obj, int* curveTypes, int typeCount, int action, int bboxMode) {
    f32 bestDistance;
    f32 bestActionDistance;
    int curveIndex;
    RomCurveDef* curve;
    RomCurveDef* bestCurve;
    RomCurveDef* bestActionCurve;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    f32 curvePos[3];
    s16 curveGrid[4];
    s16 objGrid[4];
    u8 traceHit;
    int bboxHit[20];
    int typeIndex;
    u8 traceResult;

    bestDistance = 1905.0f;
    bestCurve = NULL;
    bestActionDistance = bestDistance;
    bestActionCurve = NULL;

    curvePos[0] = obj->anim.localPosX;
    curvePos[1] = ROMCURVE_VERTICAL_OFFSET + obj->anim.localPosY;
    curvePos[2] = obj->anim.localPosZ;
    voxmaps_worldToGrid(curvePos, objGrid);

    for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++) {
        curve = (RomCurveDef*)romCurves[curveIndex];
        typeIndex = 0;
        do {
            if ((curve->type == curveTypes[typeIndex]) || (typeCount <= 0)) {
                dx = curve->x - obj->anim.localPosX;
                dy = curve->y - obj->anim.localPosY;
                dz = curve->z - obj->anim.localPosZ;
                distance = sqrtf(dz * dz + (dx * dx + dy * dy));
                if (distance < bestDistance) {
                    curvePos[0] = curve->x;
                    curvePos[1] = ROMCURVE_VERTICAL_OFFSET + curve->y;
                    curvePos[2] = curve->z;
                    voxmaps_worldToGrid(curvePos, curveGrid);
                    traceResult = voxmaps_traceLine((VoxPos*)curveGrid, (VoxPos*)objGrid, NULL, &traceHit, 0);
                    if (((traceHit == 1) || (traceResult != 0)) &&
                        (trackGetLineIntersect(&obj->anim.localPosX, curvePos, ROMCURVE_ONE, 0,
                                               (TrackLineIntersectResult*)bboxHit, obj, bboxMode, -1, 0, 0) == 0)) {
                        bestDistance = distance;
                        bestCurve = curve;
                    }
                }
                if ((curve->action == action) && (distance < bestActionDistance)) {
                    curvePos[0] = curve->x;
                    curvePos[1] = ROMCURVE_VERTICAL_OFFSET + curve->y;
                    curvePos[2] = curve->z;
                    voxmaps_worldToGrid(curvePos, curveGrid);
                    traceResult = voxmaps_traceLine((VoxPos*)curveGrid, (VoxPos*)objGrid, NULL, &traceHit, 0);
                    if (((traceHit == 1) || (traceResult != 0)) &&
                        (trackGetLineIntersect(&obj->anim.localPosX, curvePos, ROMCURVE_ONE, 0,
                                               (TrackLineIntersectResult*)bboxHit, obj, bboxMode, -1, 0, 0) == 0)) {
                        bestActionDistance = distance;
                        bestActionCurve = curve;
                    }
                }
                typeIndex = typeCount;
            }
            typeIndex++;
        } while (typeIndex < typeCount);
    }
    if (bestActionCurve != NULL) {
        bestCurve = bestActionCurve;
    }
    if (bestCurve != NULL) {
        return bestCurve->id;
    }
    return -1;
}

#define OBJFSA_WG(GRP) ((ObjfsaWalkGroup*)((char*)patchBase[0] + (GRP) * OBJFSA_PATCHGROUP_STRIDE + 0x3000))

int RomCurve_findShortestPathLink(RomCurveDef* startCurve, int unused1, int unused2, int* previousCurveId) {
    f32* queueDistanceBase;
    RomCurveDef* queueCurve;
    int directIndex;
    int directSlot;
    int directLinkId;
    RomCurveDef* directCurve;
    int startIndex;
    int candidateCount;
    int queueCount;
    int linkId;
    RomCurveDef* linkCurve;
    int insertIndex;
    int found;
    int i;
    int j;
    int linkSlot;
    f32 distance;
    f32 linkDistance;
    int candidateIds[ROMCURVE_LINK_SEARCH_RESULT_COUNT];
    f32 candidateDistances[ROMCURVE_LINK_SEARCH_RESULT_COUNT];
    int queueIndices[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
    f32 queueDistances[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
    u8 visited[ROMCURVE_MAX_CURVES];

    if (startCurve == 0) {
        return -1;
    }
    if (RomCurve_findByIdWithIndex(startCurve->id, &startIndex) == NULL) {
        return -1;
    }

    candidateCount = 0;
    directSlot = 0;
    for (; directSlot < ROMCURVE_LINK_COUNT; directSlot++) {
        queueDistanceBase = queueDistances;
        directLinkId = startCurve->linkIds[directSlot];
        if (directLinkId <= -1) {
            continue;
        }

        for (i = 0; i < ROMCURVE_MAX_CURVES; i++) {
            visited[i] = 0;
        }
        visited[startIndex] = 1;

        directCurve = RomCurve_findByIdWithIndex(startCurve->linkIds[directSlot], &directIndex);
        if (directCurve == 0) {
            continue;
        }

        distance = (directCurve->z - startCurve->z) * (directCurve->z - startCurve->z);
        queueDistances[0] = (directCurve->x - startCurve->x) * (directCurve->x - startCurve->x) +
                            (directCurve->y - startCurve->y) * (directCurve->y - startCurve->y) + distance;
        queueCount = 0;
        queueIndices[queueCount++] = directIndex;
        visited[directIndex] = 1;

        found = 0;
        do {
            if (queueCount > 0) {
                queueCount--;
                directIndex = queueIndices[queueCount];
                queueCurve = romCurves[directIndex];
                distance = queueDistances[queueCount];

                if (queueCurve->unk34 == 1) {
                    found = 1;
                    candidateDistances[candidateCount] = distance;
                    candidateIds[candidateCount++] = startCurve->linkIds[directSlot];
                    continue;
                }

                for (linkSlot = 0; linkSlot < ROMCURVE_LINK_COUNT; linkSlot++) {
                    linkId = queueCurve->linkIds[linkSlot];
                    if (linkId <= -1) {
                        continue;
                    }

                    linkCurve = RomCurve_findByIdWithIndex(linkId, &directIndex);
                    if (linkCurve == NULL || (s8)visited[directIndex] != 0 ||
                        queueCount >= ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY) {
                        continue;
                    }

                    linkDistance = (queueCurve->z - linkCurve->z) * (queueCurve->z - linkCurve->z) +
                                   (distance + (queueCurve->x - linkCurve->x) * (queueCurve->x - linkCurve->x) +
                                    (queueCurve->y - linkCurve->y) * (queueCurve->y - linkCurve->y));

                    insertIndex = 0;
                    while (insertIndex < queueCount && queueDistanceBase[insertIndex] > linkDistance) {
                        insertIndex++;
                    }
                    for (j = queueCount; j > insertIndex; j--) {
                        queueIndices[j] = queueIndices[j - 1];
                        queueDistances[j] = queueDistances[j - 1];
                    }
                    queueCount++;
                    queueDistances[insertIndex] = linkDistance;
                    queueIndices[insertIndex] = directIndex;
                    visited[directIndex] = 1;
                }
            } else {
                found = 1;
            }
        } while (!found);
    }

    if (candidateCount == 0) {
        return -1;
    }
    if (candidateCount == 1) {
        *previousCurveId = startCurve->id;
        return candidateIds[0];
    }
    if (candidateCount > 1) {
        for (i = 0; i < candidateCount; i++) {
            if (*previousCurveId == candidateIds[i]) {
                for (; i < candidateCount - 1; i++) {
                    candidateIds[i] = candidateIds[i + 1];
                    candidateDistances[i] = candidateDistances[i + 1];
                }
                candidateCount--;
            }
        }

        *previousCurveId = startCurve->id;
        j = 0;
        i = j;
        for (; i < candidateCount; i++) {
            if (candidateDistances[i] < candidateDistances[j]) {
                j = i;
            }
        }
        return candidateIds[j];
    }
    return -1;
}

int Objfsa_GetNearestAdjacentLink(RomCurveDef* curve, int preferredNeighborId, f32 x, f32 y, f32 z) {
    int bestNeighborIds[2];
    float bestDistances[2];
    RomCurveSegmentProjection segment;
    int i;
    int neighborId;
    RomCurveDef* neighborCurve;
    int slot;
    float dx;
    float dy;
    float dz;
    float dySq;
    float distance;

    bestNeighborIds[1] = -1;
    bestNeighborIds[0] = -1;
    bestDistances[1] = 5000000.0f;
    bestDistances[0] = 5000000.0f;

    segment.startX = curve->x;
    segment.startY = curve->y;
    segment.startZ = curve->z;

    for (i = 0; i < 4; i++) {
        neighborId = curve->linkIds[i];
        if (neighborId > -1) {
            neighborCurve = Objfsa_FindRomCurveById(neighborId);
            if ((void*)neighborCurve != NULL) {
                segment.endX = neighborCurve->x;
                segment.endY = neighborCurve->y;
                segment.endZ = neighborCurve->z;

                RomCurve_distanceToSegment(x, y, z, &segment);
                dx = segment.nearestX - x;
                dy = segment.nearestY - y;
                dz = segment.nearestZ - z;
                dySq = dy * dy;
                distance = dySq + dx * dx + dz * dz;
                slot = (u32)__cntlzw(preferredNeighborId - neighborId) >> 5;
                if (distance < bestDistances[slot]) {
                    bestDistances[slot] = distance;
                    bestNeighborIds[slot] = curve->linkIds[i];
                }
            }
        }
    }

    if (bestNeighborIds[0] != -1) {
        return bestNeighborIds[0];
    }
    if (bestNeighborIds[1] != -1) {
        return bestNeighborIds[1];
    }
    return -1;
}

int curves_findEnclosingLoopOfType17(f32 x, f32 y, f32 z) {
    u32 candidateIds[20];
    u32* top;
    int candidateCount;
    int category;
    RomCurveDef* curve;
    int id;
    int i;
    f32 out;

    candidateCount = 0;
    i = 0;
    for (; i < nRomCurves && candidateCount < 20; i++) {
        curve = (RomCurveDef*)romCurves[i];
        if (curve->type == ROMCURVE_TYPE_17) {
            candidateIds[candidateCount++] = curve->id;
        }
    }

    top = &candidateIds[candidateCount];
    while (candidateCount != 0) {
        if (curves_isPointInsideLoop(candidateIds[0], x, y, z, &out) != 0) {
            return candidateIds[0];
        }

        id = candidateIds[0];
        curve = (RomCurveDef*)RomCurve_FindByIdInline(id);
        category = curve->action;
        i = 0;
        while (i < candidateCount) {
            curve = (RomCurveDef*)RomCurve_FindByIdWithLimit(candidateIds[i], nRomCurves - 1);
            if (curve->action == category) {
                top--;
                candidateCount--;
                candidateIds[i] = candidateIds[candidateCount];
            } else {
                i++;
            }
        }
    }

    return -1;
}

f32 curves_getPathLength(RomCurveDef* startNode, RomCurveDef* endNode, f32* posA, f32* posB, f32 t1, f32 t2) {
    int cand1[4];
    int cand2[4];
    int cand3[4];
    int done;
    f32 total;
    int count;
    RomCurveDef* next;
    RomCurveDef* cur;
    int reachedForward;
    int atForwardEnd;
    RomCurveDef* found;
    int nextId;
    f32 dx;
    f32 dy;
    f32 dz;
    f32* tmpPos;

    if (startNode == endNode) {
        dx = posB[0] - posA[0];
        dy = posB[1] - posA[1];
        dz = posB[2] - posA[2];
        total = sqrtf(dx * dx + dy * dy + dz * dz);
        if (t2 < t1) {
            total = -total;
        }
    } else {
        reachedForward = 0;
        done = 0;
        found = startNode;
        while (done == 0) {
            atForwardEnd = Objfsa_RomCurveIsForwardEnd(found);
            if (atForwardEnd != 0) {
                done = 1;
                reachedForward = 0;
            } else {
                count = RomCurve_CollectForwardLinks(found, cand1);
                if (count != 0) {
                    nextId = cand1[randomGetRange(0, count - 1)];
                } else {
                    nextId = -1;
                }
                found = Objfsa_FindRomCurveById(nextId);
                if (found == endNode) {
                    done = 1;
                    reachedForward = 1;
                }
            }
        }

        if (reachedForward == 0) {
            cur = startNode;
            startNode = endNode;
            endNode = cur;
            tmpPos = posA;
            posA = posB;
            posB = tmpPos;
        }

        count = RomCurve_CollectForwardLinks(startNode, cand2);
        if (count != 0) {
            nextId = cand2[randomGetRange(0, count - 1)];
        } else {
            nextId = -1;
        }
        found = Objfsa_FindRomCurveById(nextId);
        startNode = found;
        dx = found->x - posA[0];
        dy = found->y - posA[1];
        dz = found->z - posA[2];
        total = sqrtf(dx * dx + dy * dy + dz * dz);
        done = 0;

        while (done == 0) {
            if (startNode == endNode) {
                done = 1;
                dx = posB[0] - startNode->x;
                dy = posB[1] - startNode->y;
                dz = posB[2] - startNode->z;
                total = total + sqrtf(dx * dx + dy * dy + dz * dz);
            } else {
                count = RomCurve_CollectForwardLinks(startNode, cand3);
                if (count != 0) {
                    nextId = cand3[randomGetRange(0, count - 1)];
                } else {
                    nextId = -1;
                }
                next = Objfsa_FindRomCurveById(nextId);
                dx = next->x - startNode->x;
                dy = next->y - startNode->y;
                dz = next->z - startNode->z;
                total = total + sqrtf(dx * dx + dy * dy + dz * dz);
                startNode = next;
            }
        }

        if (reachedForward == 0) {
            total = -total;
        }
    }
    return total;
}

void curves_getPos(RomCurveDef* curve, float* outX, float* outY, float* outZ, f32 phase) {
    f32 dx;
    f32 dy;
    f32 dz;
    int linkId;
    RomCurveDef* c2;
    int candidates[4];
    int count;

    count = RomCurve_CollectForwardLinks(curve, candidates);
    if (count != 0) {
        linkId = candidates[randomGetRange(0, count - 1)];
    } else {
        linkId = -1;
    }
    c2 = Objfsa_FindRomCurveById(linkId);

    if ((void*)c2 == NULL) {
        *outX = curve->x;
        *outY = curve->y;
        *outZ = curve->z;
    } else {
        dy = c2->y - curve->y;
        dz = c2->z - curve->z;
        dx = c2->x - curve->x;
        *outX = dx * phase + curve->x;
        *outY = dy * phase + curve->y;
        *outZ = dz * phase + curve->z;
    }
}

static inline int RomCurve_hasNoOpenLink(RomCurveDef* curve) {
    int k;

    for (k = 0; k < 4; k++) {
        if (curve->linkIds[k] != -1 && ((s8)curve->backwardLinkMask & (1 << k)) == 0) {
            return 0;
        }
    }
    return 1;
}

RomCurveDef* RomCurve_findProjectedCurveFromStart(RomCurveDef* curve, f32 x, f32 y, f32 z, f32* outPhase) {
    int projected;
    int linkId;
    float lateralOffset;
    float verticalOffset;
    float phase;
    int adjacentWindow[4];
    int candidates[4];
    u32 mask[1];
    int count[1];
    int n;
    int k;

    while (RomCurve_hasNoOpenLink(curve) == 0) {
        RomCurve_getAdjacentWindow(curve, adjacentWindow);
        projected =
            RomCurve_projectPointToAdjacentWindow(adjacentWindow, x, y, z, &lateralOffset, &verticalOffset, &phase);
        if (projected != 0 && lateralOffset > -300.0f && lateralOffset < 300.0f && verticalOffset > -100.0f &&
            verticalOffset < 100.0f) {
            *outPhase = phase;
            return curve;
        }

        count[0] = 0;
        mask[0] = 1;
        for (k = 0; k < 4; k++) {
            n = curve->linkIds[k];
            if (n > -1 && ((s8)(curve)->backwardLinkMask & mask[0]) == 0 && n != 0) {
                candidates[count[0]++] = n;
            }
            mask[0] <<= 1;
        }
        if (count[0] != 0) {
            linkId = candidates[randomGetRange(0, count[0] - 1)];
        } else {
            linkId = -1;
        }
        curve = Objfsa_FindRomCurveById(linkId);
    }

    *outPhase = ROMCURVE_ZERO;
    return curve;
}

int RomCurve_projectPointToAdjacentWindow(int* curveIds, f32 x, f32 y, f32 z, f32* outLateralOffset,
                                          f32* outVerticalOffset, f32* outPhase) {
    RomCurveDef* curves[4];
    f32 tdx;
    f32 tdz;
    f32 dx;
    f32 startPhase;
    f32 segmentDx;
    f32 dz;
    f32 tangentDz;
    f32 tangentDx;
    f32 segmentDz;
    f32 tangentLen;
    f32 numer;
    f32 x1;
    f32 z1;
    f32 endPhase;
    f32 segmentLen;
    int i;

    i = 0;
    while (i < 4) {
        curves[i] = RomCurve_FindByIdWithLimit(curveIds[i], nRomCurves - 1);
        i++;
    }

    segmentDx = (dx = curves[2]->x - curves[1]->x);
    segmentDz = (dz = curves[2]->z - curves[1]->z);
    if (curves[0] != NULL) {
        tdx = curves[1]->x - curves[0]->x;
        tdz = curves[1]->z - curves[0]->z;
    } else {
        tdx = dx;
        tdz = dz;
    }
    tangentDx = ROMCURVE_HALF * (tdx + dx);
    tangentDz = ROMCURVE_HALF * (tdz + dz);
    tangentLen = sqrtf(tangentDx * tangentDx + tangentDz * tangentDz);
    if (ROMCURVE_ZERO != tangentLen) {
        tangentDx = tangentDx / tangentLen;
        tangentDz = tangentDz / tangentLen;
    }

    x1 = curves[1]->x;
    z1 = curves[1]->z;
    tangentLen = (tangentDx * x1) + (tangentDz * z1);
    numer = -tangentLen;
    startPhase = tangentDx * segmentDx + tangentDz * segmentDz;
    if (ROMCURVE_ZERO != startPhase) {
        startPhase = -(numer + ((tangentDx * x) + (tangentDz * z))) / startPhase;
    }

    dx = curves[2]->x - x1;
    dz = curves[2]->z - z1;
    if (curves[3] != NULL) {
        tdx = curves[3]->x - curves[2]->x;
        tdz = curves[3]->z - curves[2]->z;
    } else {
        tdx = dx;
        tdz = dz;
    }
    tangentDx = ROMCURVE_HALF * (tdx + dx);
    tangentDz = ROMCURVE_HALF * (tdz + dz);
    tangentLen = sqrtf(tangentDx * tangentDx + tangentDz * tangentDz);
    if (ROMCURVE_ZERO != tangentLen) {
        tangentDx = tangentDx / tangentLen;
        tangentDz = tangentDz / tangentLen;
    }

    numer = -((tangentDx * curves[2]->x) + (tangentDz * curves[2]->z));
    endPhase = tangentDx * segmentDx + tangentDz * segmentDz;
    if (ROMCURVE_ZERO != endPhase) {
        endPhase = -(numer + ((tangentDx * x) + (tangentDz * z))) / endPhase;
    }

    /* tangentDx is reused as the projected phase from here on; tdz is reused
     * as the segment Y delta and startPhase's old value doubles as the
     * unnormalized lateral fallback (segmentDx/segmentDz still hold the raw
     * segment deltas, which equal dx/dz when segmentLen is degenerate). */
    tangentDx = -startPhase / (endPhase - startPhase);
    if ((tangentDx >= ROMCURVE_ZERO) && (tangentDx < ROMCURVE_ONE)) {
        f32 projX;
        f32 projY;
        f32 projZ;

        tdz = curves[2]->y - curves[1]->y;
        segmentLen = sqrtf(dx * dx + tdz * tdz + dz * dz);
        if (segmentLen > ROMCURVE_ZERO) {
            segmentLen = ROMCURVE_ONE / segmentLen;
            segmentDx = -dx * segmentLen;
            segmentDz = -dz * segmentLen;
        }

        tangentLen = dx * tangentDx + curves[1]->x;
        projX = tangentLen;
        projY = tdz * tangentDx + curves[1]->y;
        projZ = dz * tangentDx + curves[1]->z;
        *outLateralOffset = -((projX * segmentDz) - (projZ * segmentDx)) + (x * segmentDz - z * segmentDx);
        *outVerticalOffset = y - projY;
        *outPhase = tangentDx;
        return 1;
    }
    return 0;
}

int RomCurve_segmentIntersectsOriginRayXZ(f32 x, f32 unusedY, f32 z, RomCurveDef* a, RomCurveDef* b, f32 unusedW) {
    f32 ax;
    f32 bx;
    f32 az;
    f32 bz;
    f32 cross1;
    f32 sum1;
    ax = a->x;
    az = a->z;
    bx = b->x;
    bz = b->z;
    cross1 = bx * az - ax * bz;
    sum1 = cross1 + (x * (bz - az) + z * (ax - bx));
    if ((sum1 <= 0.0f && cross1 >= 0.0f) || (sum1 >= 0.0f && cross1 < 0.0f)) {
        f32 cross_a = -z * ax + x * az;
        f32 cross_b = -z * bx + x * bz;
        if ((cross_a <= 0.0f && cross_b >= 0.0f) || (cross_a >= 0.0f && cross_b < 0.0f)) {
            return 1;
        }
    }
    return 0;
}

int curves_isPointInsideLoop(int curveId, f32 x, f32 y, f32 z, f32* outDistance) {
    RomCurveDef* curve;
    RomCurveDef* nextCurve;
    int nextCurveId;
    int previousCurveId;
    int linkIndex;
    int hitCount;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;

    previousCurveId = curveId;
    previousCurveId |= curveId;
    curve = RomCurve_FindByIdInline(curveId);
    hitCount = 0;
    *outDistance = 200000.0f;
    do {
        nextCurveId = ROMCURVE_LINK_ID_NONE;
        linkIndex = 0;
        while ((linkIndex < ROMCURVE_LINK_COUNT) && (nextCurveId == (int)ROMCURVE_LINK_ID_NONE)) {
            if ((curve->backwardLinkMask & (1 << linkIndex)) == 0) {
                nextCurveId = curve->linkIds[linkIndex];
            }
            linkIndex++;
        }

        nextCurve = curve;
        if (nextCurveId != (int)ROMCURVE_LINK_ID_NONE) {
            nextCurve = RomCurve_FindByIdInline(nextCurveId);
            if (RomCurve_segmentIntersectsOriginRayXZ(x, y, z, curve, nextCurve, 1000.0f) != 0) {
                dx = curve->x - x;
                dy = curve->y - y;
                dz = curve->z - z;
                distance = sqrtf(dx * dx + dy * dy + dz * dz);
                if (distance < *outDistance) {
                    *outDistance = distance;
                }
                hitCount++;
            }
            previousCurveId = nextCurveId;
            curve = nextCurve;
        }
    } while ((previousCurveId != curveId) && (nextCurveId != (int)ROMCURVE_LINK_ID_NONE));

    return hitCount & 1;
}

int curves_findNearestOfType16(f32 x, f32 y, f32 z, int queryAll) {
    float dx;
    float dy;
    float dz;
    GameObject** objects;
    GameObject* obj;
    int i;
    RomCurveDef* curve;
    float distance;
    float nearestDistance;
    float nearestCurveId;
    int startIndex;
    int objectCount;

    objects = ObjList_GetObjects(&startIndex, &objectCount);
    nearestCurveId = ROMCURVE_NEG_ONE;
    nearestDistance = ROMCURVE_ZERO;
    for (i = 0; i < objectCount; i = i + 1) {
        obj = objects[i];
        if (((obj->anim.classId == 0x2c) && (obj->anim.mapEventSlot != queryAll)) &&
            (curve = (RomCurveDef*)obj->anim.placementData, curve != NULL) && curve->type == ROMCURVE_TYPE_16) {
            dx = obj->anim.worldPosX - x;
            dy = obj->anim.worldPosY - y;
            dz = obj->anim.worldPosZ - z;
            distance = sqrtf(dz * dz + (dx * dx + dy * dy));
            if (ROMCURVE_NEG_ONE == nearestCurveId || distance < nearestDistance) {
                nearestDistance = distance;
                nearestCurveId = (float)curve->id;
            }
        }
    }
    return nearestCurveId;
}

#define SQ(v) ((v) * (v))

int RomCurve_func13(u32 curveId, int typeFilter, int matchValue, int* outLink) {
    f32* distWrite;
    RomCurveDef* linkNode;
    RomCurveDef* cand;
    u32* idWrite;
    u32 candWalk;
    u32 cur;
    f32* probe;
    u32* idRead;
    f32* qscan;
    RomCurveDef* node;
    int li;
    int found;
    int count;
    int done;
    int k;
    RomCurveDef* start;
    f32* distRead;
    f32 newDist;
    f32* pq;
    int pos;
    int m;
    int best[2];
    int off;
    f32 curDist;
    char visited[ROMCURVE_MAX_CURVES];
    int queueIds[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
    f32 queueDist[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
    u32 resultIds[4];
    f32 bestDists[4];
    int idx;
    int startIdx;
    char resultLinks[4];

    start = RomCurve_findByIdWithIndex(curveId, &startIdx);
    if (start == NULL) {
        return -1;
    }
    found = 0;
    li = 0;
    cur = (u32)start;
    distRead = bestDists;
    probe = distRead;
    idRead = resultIds;
    for (; li < 4; cur += 4, li++) {
        qscan = queueDist;
        if (*(s32*)(cur + 0x1c) <= -1) {
            continue;
        }
        for (off = 0; off < ROMCURVE_MAX_CURVES; off++) {
            visited[off] = 0;
        }
        visited[startIdx] = 1;
        linkNode = RomCurve_findByIdWithIndex(*(s32*)(cur + 0x1c), &idx);
        if (linkNode == NULL) {
            continue;
        }
        queueDist[0] = SQ(linkNode->z - start->z) + (SQ(linkNode->x - start->x) + SQ(linkNode->y - start->y));
        count = 0;
        queueIds[count++] = idx;
        visited[idx] = 1;
        done = 0;
        distWrite = probe;
        idWrite = idRead;
        do {
            if (count > 0) {
                count--;
                idx = queueIds[count];
                node = romCurves[idx];
                curDist = queueDist[count];
                best[0] = 0;
                if ((((int)node->type == typeFilter) || (typeFilter == -1)) &&
                    ((((RomCurvePathNode*)node)->tag0 == matchValue ||
                      ((((RomCurvePathNode*)node)->tag1 == matchValue ||
                        (((RomCurvePathNode*)node)->tag2 == matchValue)))))) {
                    done = 1;
                    *distWrite = curDist;
                    if (found < 4) {
                        *idWrite = node->id;
                        probe++;
                        idRead++;
                        distWrite++;
                        idWrite++;
                        resultLinks[found++] = li;
                    }
                } else {
                    for (k = 0, candWalk = (u32)node; k < 4; candWalk += 4, k++) {
                        if (((*(s32*)(candWalk + 0x1c) > -1) &&
                             ((cand = RomCurve_findByIdWithIndex(*(s32*)(candWalk + 0x1c), &idx)) != NULL)) &&
                            (visited[idx] == 0) && (count < ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY)) {
                            newDist =
                                SQ(node->z - cand->z) + ((curDist + SQ(node->x - cand->x)) + SQ(node->y - cand->y));
                            pos = 0;
                            pq = qscan;
                            while ((pos < count) && (*pq > newDist)) {
                                pq++;
                                pos++;
                            }
                            for (m = count; m > pos; m--) {
                                queueIds[m] = queueIds[m - 1];
                                queueDist[m] = queueDist[m - 1];
                            }
                            count++;
                            queueDist[pos] = newDist;
                            queueIds[pos] = idx;
                            visited[idx] = 1;
                        }
                    }
                }
            } else {
                done = 1;
            }
        } while (!done);
    }
    if (found > 0) {
        best[1] = 0;
        best[0] = best[1];
        for (; best[0] < found; best[0]++) {
            if (*distRead < bestDists[best[1]]) {
                best[1] = best[0];
            }
            distRead++;
        }
        if (outLink != NULL) {
            *outLink = resultLinks[best[1]];
        }
        return resultIds[best[1]];
    }
    return -1;
}

int curves_findByAction(int act) {
    int i;

    for (i = 0; i < nRomCurves; i++) {
        RomCurveDef* c = romCurves[i];
        if (c->type == ROMCURVE_TYPE_ACTION) {
            if (c->action == act) {
                return c->id;
            }
        }
    }
    return -1;
}
int RomCurve_findLinkTowardNearestOfType(RomCurveDef* curve, int typeFilter, int actionFilter, int* previousCurveId) {
    f32* distWrite;
    u32 candWalk;
    u32 cur;
    f32* probe;
    f32* qscan;
    f32* distRead;
    RomCurveDef* cand;
    RomCurveDef* node;
    RomCurveDef* linkNode;
    int li;
    int found;
    int count;
    int done;
    int k;
    f32 newDist;
    f32* pq;
    int pos;
    int m;
    int j;
    int best[2];
    int off;
    f32 curDist;
    char visited[ROMCURVE_MAX_CURVES];
    int queueIds[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
    f32 queueDist[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
    int results[4];
    f32 bestDists[4];
    int idx;
    int startIdx;

    if (curve == NULL) {
        return -1;
    }
    if (RomCurve_findByIdWithIndex(curve->id, &startIdx) == NULL) {
        return -1;
    }
    found = 0;
    li = 0;
    cur = (u32)curve;
    distRead = bestDists;
    probe = distRead;
    for (; li < 4; cur += 4, li++) {
        qscan = queueDist;
        if (*(s32*)(cur + 0x1c) <= -1) {
            continue;
        }
        for (off = 0; off < ROMCURVE_MAX_CURVES; off++) {
            visited[off] = 0;
        }
        visited[startIdx] = 1;
        linkNode = RomCurve_findByIdWithIndex(*(s32*)(cur + 0x1c), &idx);
        if (linkNode == NULL) {
            continue;
        }
        queueDist[0] = SQ(linkNode->z - curve->z) + (SQ(linkNode->x - curve->x) + SQ(linkNode->y - curve->y));
        count = 0;
        queueIds[count++] = idx;
        visited[idx] = 1;
        done = 0;
        distWrite = probe;
        do {
            if (count > 0) {
                count--;
                idx = queueIds[count];
                node = romCurves[idx];
                curDist = queueDist[count];
                best[0] = 0;
                if (((int)node->type == typeFilter) && ((actionFilter == -1) || (actionFilter == node->action))) {
                    done = 1;
                    *distWrite = queueDist[count];
                    probe++;
                    distWrite++;
                    results[found++] = *(s32*)(cur + 0x1c);
                } else {
                    for (k = 0, candWalk = (u32)node; k < 4; candWalk += 4, k++) {
                        if (((*(s32*)(candWalk + 0x1c) > -1) &&
                             ((cand = RomCurve_findByIdWithIndex(*(s32*)(candWalk + 0x1c), &idx)) != NULL)) &&
                            (visited[idx] == 0) && (count < ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY)) {
                            newDist =
                                SQ(node->z - cand->z) + ((curDist + SQ(node->x - cand->x)) + SQ(node->y - cand->y));
                            pos = 0;
                            pq = qscan;
                            while ((pos < count) && (*pq > newDist)) {
                                pq++;
                                pos++;
                            }
                            for (m = count; m > pos; m--) {
                                queueIds[m] = queueIds[m - 1];
                                queueDist[m] = queueDist[m - 1];
                            }
                            count++;
                            queueDist[pos] = newDist;
                            queueIds[pos] = idx;
                            visited[idx] = 1;
                        }
                    }
                }
            } else {
                done = 1;
            }
        } while (!done);
    }
    if (found == 0) {
        return -1;
    }
    if (found == 1) {
        *previousCurveId = curve->id;
        return results[0];
    }
    if (found > 1) {
        for (j = 0; j < found; j++) {
            if (*previousCurveId == results[j]) {
                for (; j < found - 1; j++) {
                    results[j] = results[j + 1];
                    bestDists[j] = bestDists[j + 1];
                }
                found--;
            }
        }
        *previousCurveId = curve->id;
        best[1] = 0;
        best[0] = best[1];
        for (; best[0] < found; best[0]++) {
            if (*distRead < bestDists[best[1]]) {
                best[1] = best[0];
            }
            distRead++;
        }
        return results[best[1]];
    }
    return -1;
}

int RomCurve_getRandomLinkedOfTypes(RomCurveDef* curve, int* types, int typeCount, int* previousLinkId) {
    int candidateCount;
    int linkIndex;
    int typeIndex;
    int candidates[4];

    if (curve == NULL) {
        return -1;
    }
    candidateCount = 0;
    for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
        int linkId = curve->linkIds[linkIndex];
        if (linkId > -1) {
            RomCurveDef* linkedCurve = RomCurve_FindByIdInline(curve->linkIds[linkIndex]);

            for (typeIndex = 0; typeIndex < typeCount; typeIndex++) {
                if (linkedCurve->type == types[typeIndex]) {
                    candidates[candidateCount++] = curve->linkIds[linkIndex];
                    typeIndex = typeCount;
                }
            }
        }
    }
    if (candidateCount == 0) {
        return -1;
    }
    if (candidateCount == 1) {
        *previousLinkId = curve->id;
        return candidates[0];
    }
    if (candidateCount > 1) {
        for (typeIndex = 0; typeIndex < candidateCount; typeIndex++) {
            if (*previousLinkId == candidates[typeIndex]) {
                for (; typeIndex < candidateCount - 1; typeIndex++) {
                    candidates[typeIndex] = candidates[typeIndex + 1];
                }
                candidateCount--;
            }
        }
        *previousLinkId = curve->id;
        return candidates[randomGetRange(0, candidateCount - 1)];
    }
    return -1;
}

int curves_isNotPoint(RomCurveDef* curve) {
    int i;
    for (i = 0; i < 4; i++) {
        if (curve->linkIds[i] != -1 && (curve->backwardLinkMask & (1 << i)) == 0) {
            return 0;
        }
    }
    return 1;
}

int curves_isPoint(RomCurveDef* curve) {
    int i;
    for (i = 0; i < 4; i++) {
        if (curve->linkIds[i] != -1 && (curve->backwardLinkMask & (1 << i)) != 0) {
            return 0;
        }
    }
    return 1;
}

f32 curves_distXZ(f32 x, f32 z, u32 curveId) {
    RomCurveDef* curve;
    f32 dx;
    f32 dz;

    curve = RomCurve_FindByIdInline(curveId);
    if (curve != NULL) {
        dx = curve->x - x;
        dz = curve->z - z;
        return sqrtf(dx * dx + dz * dz);
    }

    return ROMCURVE_NEG_ONE;
}

f32 curves_distToObj(GameObject* obj, u32 curveId) {
    RomCurveDef* curve;
    f32 dx;
    f32 dy;
    f32 dz;

    curve = RomCurve_FindByIdInline(curveId);
    if (curve != NULL && (void*)obj != NULL) {
        dx = curve->x - obj->anim.localPosX;
        dy = curve->y - obj->anim.localPosY;
        dz = curve->z - obj->anim.localPosZ;
        return sqrtf(dx * dx + dy * dy + dz * dz);
    }

    return ROMCURVE_NEG_ONE;
}

#define ROMCURVE_PLACEMENT_ANGLE(v) ((ROMCURVE_ANGLE_PI * (f32)((s32)(v) << 8)) / ROMCURVE_HALF_CIRCLE_ANGLE)

static inline int RomCurve_noForwardLinks(RomCurveDef* curve) {
    int bit;
    s32* lp = curve->linkIds;

    for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++) {
        if ((s32)*lp++ != -1 && (curve->backwardLinkMask & (1 << bit)) == 0) {
            return 0;
        }
    }
    return 1;
}

static inline int RomCurve_noBackwardLinks(RomCurveDef* curve) {
    int bit;
    s32* lp = curve->linkIds;

    for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++) {
        if ((s32)*lp++ != -1 && (curve->backwardLinkMask & (1 << bit)) != 0) {
            return 0;
        }
    }
    return 1;
}

f32 curves_find(int type, int action, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ) {
    RomCurveDef* curve;
    RomCurveDef* linkedCurve;
    int curveIndex;
    int linkIndex;
    u32 linkId;
    f32 pointX;
    f32 pointY;
    f32 pointZ;
    f32 zero;
    f32 distance;
    f32 bestDistance;
    f32 absDistance;
    f32 absBestDistance;
    RomCurveSegmentProjection segment;

    pointX = x;
    pointY = y;
    pointZ = z;
    zero = ROMCURVE_ZERO;
    *outZ = zero;
    *outY = zero;
    *outX = zero;
    bestDistance = 5000000.0f;
    for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++) {
        curve = romCurves[curveIndex];
        if ((curve->action == action) && (curve->type == type)) {
            segment.startX = curve->x;
            segment.startY = curve->y;
            segment.startZ = curve->z;
            for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
                if (((s32)curve->backwardLinkMask & (1 << linkIndex)) == 0) {
                    linkId = curve->linkIds[linkIndex];
                    linkedCurve = RomCurve_FindByIdInline(linkId);

                    if (linkedCurve != NULL) {
                        segment.endX = linkedCurve->x;
                        segment.endY = linkedCurve->y;
                        segment.endZ = linkedCurve->z;
                        distance = RomCurve_distanceToSegment(pointX, pointY, pointZ, &segment);
                        absBestDistance = (bestDistance < ROMCURVE_ZERO) ? -bestDistance : bestDistance;
                        absDistance = (distance < ROMCURVE_ZERO) ? -distance : distance;
                        if (absDistance < absBestDistance) {
                            gRomCurveLastFindStart = curve;
                            gRomCurveLastFindEnd = linkedCurve;
                            bestDistance = distance;
                            *outX = segment.nearestX;
                            *outY = segment.nearestY;
                            *outZ = segment.nearestZ;
                        }
                    }
                }
            }
        }
    }
    return bestDistance;
}

void RomCurve_getLastFindSegment(RomCurveDef** startOut, RomCurveDef** endOut) {
    *startOut = gRomCurveLastFindStart;
    *endOut = gRomCurveLastFindEnd;
}

RomCurveDef* RomCurve_findByIdWithIndex(u32 curveId, int* outIndex) {
    int high;
    int low;
    int mid;

    *outIndex = -1;
    if ((int)curveId < 0) {
        return NULL;
    }
    high = nRomCurves + -1;
    low = 0;
    while (high >= low) {
        mid = high + low >> 1;
        if (curveId > RomCurve_GetId(romCurves[mid])) {
            low = mid + 1;
        } else if (curveId < RomCurve_GetId(romCurves[mid])) {
            high = mid + -1;
        } else {
            *outIndex = mid;
            return romCurves[mid];
        }
    }
    *outIndex = -1;
    return NULL;
}
int RomCurve_buildRandomPoints(RomCurveDef* curve, f32* outX, f32* outY, f32* outZ, s8* outTypes) {
    RomCurveDef* hold;
    int idsB[ROMCURVE_LINK_COUNT];
    RomCurveDef* next;
    int done;
    int n;
    int count;
    int id;
    f32 tz;
    int idsA[ROMCURVE_LINK_COUNT];

    done = RomCurve_noForwardLinks(curve) ? 1 : 0;
    n = 0;
    if (!done) {
        while (curve != NULL && !RomCurve_noForwardLinks(curve)) {
            count = RomCurve_CollectForwardLinks(curve, idsB);
            if (count != 0) {
                id = idsB[randomGetRange(0, count - 1)];
            } else {
                id = -1;
            }
            next = RomCurve_FindByIdInline(id);
            hold = next;
            if (next != NULL) {
                if (outTypes != NULL) {
                    outTypes[n >> 2] = curve->type;
                }
                outX[n] = curve->x;
                outY[n] = curve->y;
                outZ[n++] = curve->z;
                outX[n] = next->x;
                outY[n] = next->y;
                tz = next->z;
                outZ[n++] = tz;
                outX[n] =
                    ROMCURVE_TANGENT_SCALE * ((f32)curve->tangentMag * mathSinf(ROMCURVE_PLACEMENT_ANGLE(curve->yaw)));
                outY[n] = ROMCURVE_TANGENT_SCALE *
                          ((f32)curve->tangentMag * mathSinf(ROMCURVE_PLACEMENT_ANGLE(curve->pitch)));
                tz = ROMCURVE_TANGENT_SCALE * ((f32)curve->tangentMag * mathCosf(ROMCURVE_PLACEMENT_ANGLE(curve->yaw)));
                outZ[n++] = tz;
                outX[n] =
                    ROMCURVE_TANGENT_SCALE * ((f32)next->tangentMag * mathSinf(ROMCURVE_PLACEMENT_ANGLE(next->yaw)));
                outY[n] =
                    ROMCURVE_TANGENT_SCALE * ((f32)next->tangentMag * mathSinf(ROMCURVE_PLACEMENT_ANGLE(next->pitch)));
                tz = ROMCURVE_TANGENT_SCALE * ((f32)next->tangentMag * mathCosf(ROMCURVE_PLACEMENT_ANGLE(next->yaw)));
                outZ[n++] = tz;
            }
            curve = hold;
        }
    } else {
        while (curve != NULL && !RomCurve_noBackwardLinks(curve)) {
            count = RomCurve_CollectBackwardLinks(curve, idsA);
            if (count != 0) {
                id = idsA[randomGetRange(0, count - 1)];
            } else {
                id = -1;
            }
            next = RomCurve_FindByIdInline(id);
            if (next != NULL) {
                if (outTypes != NULL) {
                    outTypes[n >> 2] = curve->type;
                }
                outX[n] = curve->x;
                outY[n] = curve->y;
                outZ[n++] = curve->z;
                outX[n] = next->x;
                outY[n] = next->y;
                tz = next->z;
                outZ[n++] = tz;
                outX[n] =
                    ROMCURVE_TANGENT_SCALE * ((f32)curve->tangentMag * mathSinf(ROMCURVE_PLACEMENT_ANGLE(curve->yaw)));
                outY[n] = ROMCURVE_TANGENT_SCALE *
                          ((f32)curve->tangentMag * mathSinf(ROMCURVE_PLACEMENT_ANGLE(curve->pitch)));
                tz = ROMCURVE_TANGENT_SCALE * ((f32)curve->tangentMag * mathCosf(ROMCURVE_PLACEMENT_ANGLE(curve->yaw)));
                outZ[n++] = tz;
                outX[n] =
                    ROMCURVE_TANGENT_SCALE * ((f32)next->tangentMag * mathSinf(ROMCURVE_PLACEMENT_ANGLE(next->yaw)));
                outY[n] =
                    ROMCURVE_TANGENT_SCALE * ((f32)next->tangentMag * mathSinf(ROMCURVE_PLACEMENT_ANGLE(next->pitch)));
                tz = ROMCURVE_TANGENT_SCALE * ((f32)next->tangentMag * mathCosf(ROMCURVE_PLACEMENT_ANGLE(next->yaw)));
                outZ[n++] = tz;
            }
            curve = next;
        }
    }
    return n;
}
int RomCurve_countRandomPoints(RomCurveDef* curve) {
    int linkCount;
    int count;
    int id;
    int ids[ROMCURVE_LINK_COUNT];

    count = 1;
    while (curve != NULL && !RomCurve_noForwardLinks(curve)) {
        linkCount = RomCurve_CollectForwardLinks(curve, ids);
        if (linkCount != 0) {
            id = ids[randomGetRange(0, linkCount - 1)];
        } else {
            id = -1;
        }
        curve = RomCurve_FindByIdInline(id);
        if (curve != NULL) {
            count++;
        }
    }
    return count;
}

int RomCurve_buildAdjacentWindowPoints(u32* curveIds, float* outX, float* outY, float* outZ) {
    RomCurveDef** resolveCursor;
    float* outXStart;
    int foundCount;
    int remaining;
    int i;
    RomCurveDef* windowCurves[4];

    foundCount = 0;
    resolveCursor = windowCurves;
    outXStart = outX;
    for (i = 0; i < 4; i++) {
        windowCurves[i] = RomCurve_FindByIdInline(curveIds[i]);
        if (windowCurves[i] != NULL) {
            outX[i] = windowCurves[i]->x;
            outY[i] = windowCurves[i]->y;
            outZ[i] = windowCurves[i]->z;
            foundCount = foundCount + 1;
        }
    }

    if (((foundCount < 2) || (windowCurves[1] == NULL)) || (windowCurves[2] == NULL)) {
        return 0;
    }

    for (foundCount = 0, remaining = 4; remaining != 0; remaining--) {
        if (*resolveCursor == NULL) {
            if (foundCount == 0) {
                *outXStart = windowCurves[1]->x + (windowCurves[1]->x - windowCurves[2]->x);
                *outY = windowCurves[1]->y + (windowCurves[1]->y - windowCurves[2]->y);
                *outZ = windowCurves[1]->z + (windowCurves[1]->z - windowCurves[2]->z);
            } else if (foundCount == 3) {
                *outXStart = windowCurves[2]->x + (windowCurves[2]->x - windowCurves[1]->x);
                *outY = windowCurves[2]->y + (windowCurves[2]->y - windowCurves[1]->y);
                *outZ = windowCurves[2]->z + (windowCurves[2]->z - windowCurves[1]->z);
            }
        }
        resolveCursor = resolveCursor + 1;
        outXStart = outXStart + 1;
        outY = outY + 1;
        outZ = outZ + 1;
        foundCount = foundCount + 1;
    }
    return 1;
}

void RomCurve_getAdjacentWindow(RomCurveDef* curve, int* outIds) {
    RomCurveDef* adjacent;
    int linkId;
    int i;
    int j;

    outIds[0] = ROMCURVE_LINK_ID_NONE;
    outIds[1] = ROMCURVE_LINK_ID_NONE;
    outIds[2] = ROMCURVE_LINK_ID_NONE;
    outIds[3] = ROMCURVE_LINK_ID_NONE;
    if (curve == NULL) {
        return;
    }

    outIds[1] = curve->id;
    for (i = 0; i < ROMCURVE_LINK_COUNT; i++) {
        linkId = curve->linkIds[i];
        if (linkId != (int)ROMCURVE_LINK_ID_NONE) {
            if ((curve->backwardLinkMask & (1 << i)) != 0) {
                outIds[0] = linkId;
            } else if ((curve->backwardLinkMask & (1 << i)) == 0) {
                outIds[2] = linkId;
            }
        }
    }

    if (outIds[2] <= -1) {
        return;
    }
    adjacent = RomCurve_FindByIdInline(outIds[2]);

    if (adjacent == NULL) {
        return;
    }

    for (j = 0; j < ROMCURVE_LINK_COUNT; j++) {
        linkId = adjacent->linkIds[j];
        if (linkId != (int)ROMCURVE_LINK_ID_NONE) {
            if ((adjacent->backwardLinkMask & (1 << j)) == 0) {
                outIds[3] = linkId;
            }
        }
    }
}

int RomCurve_getFarthestAdjacentLink(RomCurveDef* curve, int excludeLinkId, f32 x, f32 y, f32 z) {
    int bestLink[2];
    f32 bestDistance[2];
    RomCurveSegmentProjection segment;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    u32 linkId;
    int linkIndex;
    int slot;
    RomCurveDef* linkedCurve;

    bestLink[1] = ROMCURVE_LINK_ID_NONE;
    bestLink[0] = ROMCURVE_LINK_ID_NONE;
    bestDistance[1] = ROMCURVE_ZERO;
    bestDistance[0] = ROMCURVE_ZERO;
    segment.startX = curve->x;
    segment.startY = curve->y;
    segment.startZ = curve->z;

    for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
        linkId = curve->linkIds[linkIndex];
        if ((s32)linkId > -1) {
            linkedCurve = RomCurve_FindByIdInline(linkId);

            if (linkedCurve != NULL) {
                segment.endX = linkedCurve->x;
                segment.endY = linkedCurve->y;
                segment.endZ = linkedCurve->z;
                RomCurve_distanceToSegment(x, y, z, &segment);
                dx = segment.nearestX - x;
                dy = segment.nearestY - y;
                dz = segment.nearestZ - z;
                distance = dx * dx + dy * dy + dz * dz;
                slot = (u32)__cntlzw(excludeLinkId - linkId) >> 5;
                if (distance > bestDistance[slot]) {
                    bestDistance[slot] = distance;
                    bestLink[slot] = curve->linkIds[linkIndex];
                }
            }
        }
    }

    if (bestLink[0] != (int)ROMCURVE_LINK_ID_NONE) {
        return bestLink[0];
    }
    if (bestLink[1] != (int)ROMCURVE_LINK_ID_NONE) {
        return bestLink[1];
    }
    return ROMCURVE_LINK_ID_NONE;
}

f32 RomCurve_distanceToSegment(f32 x, f32 y, f32 z, RomCurveSegmentProjection* segment) {
    f32 startY;
    f32 startX;
    f32 startZ;
    f32 endX;
    f32 endY;
    f32 endZ;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 projection;
    f32 nearestX;
    f32 nearestY;
    f32 nearestZ;
    f32 distance;

    endX = segment->endX;
    startX = segment->startX;
    deltaX = endX - startX;
    endY = segment->endY;
    startY = segment->startY;
    deltaY = endY - startY;
    endZ = segment->endZ;
    startZ = segment->startZ;
    deltaZ = endZ - startZ;
    if (((ROMCURVE_ZERO == deltaX) && (ROMCURVE_ZERO == deltaY)) && (ROMCURVE_ZERO == deltaZ)) {
        projection = ROMCURVE_ZERO;
    } else {
        projection = (deltaX * (x - startX) + deltaY * (y - startY) + deltaZ * (z - startZ)) /
                     (deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
    }
    if (projection < ROMCURVE_ZERO) {
        nearestX = startX;
        nearestY = startY;
        nearestZ = startZ;
        distance = -((startZ - z) * (startZ - z) + ((startX - x) * (startX - x) + (startY - y) * (startY - y)));
    } else if (projection > ROMCURVE_ONE) {
        nearestX = endX;
        nearestY = endY;
        nearestZ = endZ;
        distance = -((endZ - z) * (endZ - z) + ((endX - x) * (endX - x) + (endY - y) * (endY - y)));
    } else {
        nearestX = projection * deltaX + startX;
        nearestY = projection * deltaY + startY;
        nearestZ = projection * deltaZ + startZ;
        distance =
            (nearestZ - z) * (nearestZ - z) + ((nearestX - x) * (nearestX - x) + (nearestY - y) * (nearestY - y));
    }
    segment->nearestX = nearestX;
    segment->nearestY = nearestY;
    segment->nearestZ = nearestZ;
    return distance;
}

int RomCurve_getRandomBackwardLink(RomCurveDef* curve, int excludeLinkId) {
    int link;
    int count;
    u32 mask;
    int i;
    int result;
    int eligibleLinks[ROMCURVE_LINK_COUNT];

    count = 0;
    mask = 1;

    for (i = 0; i < ROMCURVE_LINK_COUNT; i = i + 1) {
        link = curve->linkIds[i];
        if ((link > -1) && ((curve->backwardLinkMask & mask) != 0) && (link != excludeLinkId)) {
            eligibleLinks[count++] = link;
        }
        mask = mask << 1;
    }

    if (count != 0) {
        result = eligibleLinks[randomGetRange(0, count - 1)];
    } else {
        result = -1;
    }
    return result;
}

int RomCurve_getLinkIds(RomCurveDef* curve, int excludeLinkId, int* outIds) {
    int linkId;
    int count;
    int i;

    count = 0;
    for (i = 0; i < 4; i++) {
        linkId = curve->linkIds[i];
        if (RomCurve_IsLinkIdValid(linkId) && linkId != excludeLinkId) {
            outIds[count++] = linkId;
        }
    }
    return count;
}

int RomCurve_getRandomForwardLink(RomCurveDef* curve, int excludeLinkId) {
    int link;
    int count;
    u32 mask;
    int i;
    int result;
    int eligibleLinks[ROMCURVE_LINK_COUNT];

    count = 0;
    mask = 1;

    for (i = 0; i < ROMCURVE_LINK_COUNT; i = i + 1) {
        link = curve->linkIds[i];
        if ((link > -1) && ((curve->backwardLinkMask & mask) == 0) && (link != excludeLinkId)) {
            eligibleLinks[count++] = link;
        }
        mask = mask << 1;
    }

    if (count != 0) {
        result = eligibleLinks[randomGetRange(0, count - 1)];
    } else {
        result = -1;
    }
    return result;
}

RomCurveDef* RomCurve_getById(u32 curveId) {
    int high;
    int low;
    int mid;

    if ((int)curveId < 0) {
        return 0;
    }
    high = nRomCurves - 1;
    low = 0;
    while (high >= low) {
        mid = (high + low) >> 1;
        if (curveId > RomCurve_GetId(romCurves[mid])) {
            low = mid + 1;
        } else if (curveId < RomCurve_GetId(romCurves[mid])) {
            high = mid - 1;
        } else {
            return (RomCurveDef*)romCurves[mid];
        }
    }
    return 0;
}

int RomCurve_find(f32 x, f32 y, f32 z, int* types, int typeCount, int action) {
    int curveIndex;
    int typeIndex;
    RomCurveDef* curve;
    RomCurveDef* bestCurve;
    RomCurveDef* bestActionCurve;
    f32 bestDistance;
    f32 bestActionDistance;
    f32 distance;
    f32 point[3];

    bestDistance = ROMCURVE_FIND_DISTANCE_INITIAL;
    bestCurve = NULL;
    bestActionDistance = bestDistance;
    bestActionCurve = NULL;
    point[0] = x;
    point[1] = y;
    point[2] = z;
    for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++) {
        curve = romCurves[curveIndex];
        typeIndex = 0;
        do {
            if ((typeCount <= 0) || (curve->type == types[typeIndex])) {
                distance = vec3f_distanceSquared(point, &curve->x);
                if (distance < bestDistance) {
                    bestDistance = distance;
                    bestCurve = curve;
                }
                if ((curve->action == action) && (distance < bestActionDistance)) {
                    bestActionDistance = distance;
                    bestActionCurve = curve;
                }
                typeIndex = typeCount;
            }
            typeIndex++;
        } while (typeIndex < typeCount);
    }
    if (bestActionCurve != NULL) {
        bestCurve = bestActionCurve;
    }
    if (bestCurve != NULL) {
        return bestCurve->id;
    }
    return -1;
}

void* RomCurve_getCurves(int* outCount) {
    *outCount = nRomCurves;
    return romCurves;
}

void RomCurve_remove(RomCurveDef* curve) {
    RomCurveDef** tableSlot;
    int sortedCurveCount;
    int removeIndex;

    removeIndex = 0;
    while ((removeIndex < nRomCurves) && (curve->id != romCurves[removeIndex]->id)) {
        removeIndex = removeIndex + 1;
    }

    sortedCurveCount = nRomCurves;
    if (removeIndex >= sortedCurveCount) {
        return;
    }

    nRomCurves = nRomCurves - 1;
    sortedCurveCount = nRomCurves;
    tableSlot = romCurves + removeIndex;
    for (; removeIndex < sortedCurveCount; removeIndex++) {
        tableSlot[0] = tableSlot[1];
        tableSlot = tableSlot + 1;
    }
}

void RomCurve_add(RomCurveDef* curve) {
    int sortedCurveCount;
    RomCurveDef** tailSlot;
    int insertIndex;

    sortedCurveCount = nRomCurves;
    if (sortedCurveCount == ROMCURVE_MAX_CURVES) {
        OSReport(sCurvesMaxRomCurvesExceeded);
        return;
    }

    insertIndex = 0;
    while ((insertIndex < sortedCurveCount) && (curve->id > romCurves[insertIndex]->id)) {
        insertIndex++;
    }

    for (tailSlot = romCurves + sortedCurveCount; insertIndex < sortedCurveCount; sortedCurveCount--) {
        tailSlot[0] = tailSlot[-1];
        tailSlot--;
    }

    nRomCurves++;
    romCurves[insertIndex] = curve;
}

void curves_initialise(void) {
    nRomCurves = 0x0;
}

void RomCurve_release(void) {
}

/* RomCurve_segmentIntersectsOriginRayXZ: 2D segment-intersection predicate.
 * Returns 1 if the segment between (x, z) and the origin in the xz-plane
 * crosses the segment between a and b. */

void RomCurve_initialise(void) {
}
typedef struct RomCurveDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback curvesInitialise;
    ObjectDescriptorCallback add;
    ObjectDescriptorCallback remove;
    ObjectDescriptorCallback getCurves;
    ObjectDescriptorCallback find;
    ObjectDescriptorCallback findNearObj;
    ObjectDescriptorCallback getById;
    ObjectDescriptorCallback curvesFind;
    ObjectDescriptorCallback distToObj;
    ObjectDescriptorCallback distXZ;
    ObjectDescriptorCallback getLastFindSegment;
    ObjectDescriptorCallback isPoint;
    ObjectDescriptorCallback isNotPoint;
    ObjectDescriptorCallback getRandomLinkedOfTypes;
    ObjectDescriptorCallback findLinkTowardNearestOfType;
    ObjectDescriptorCallback findByAction;
    ObjectDescriptorCallback slot13;
    ObjectDescriptorCallback findNearestOfType16;
    ObjectDescriptorCallback isPointInsideLoop;
    ObjectDescriptorCallback findEnclosingLoopOfType17;
    ObjectDescriptorCallback getRandomForwardLink;
    ObjectDescriptorCallback getLinkIds;
    ObjectDescriptorCallback getFarthestAdjacentLink;
    ObjectDescriptorCallback getRandomBackwardLink;
    ObjectDescriptorCallback getNearestAdjacentLink;
    ObjectDescriptorCallback findShortestPathLink;
    ObjectDescriptorCallback getAdjacentWindow;
    ObjectDescriptorCallback buildAdjacentWindowPoints;
    ObjectDescriptorCallback countRandomPoints;
    ObjectDescriptorCallback buildRandomPoints;
    ObjectDescriptorCallback projectPointToAdjacentWindow;
    ObjectDescriptorCallback findProjectedCurveFromStart;
    ObjectDescriptorCallback getPos;
    ObjectDescriptorCallback getPathLength;
    ObjectDescriptorCallback initCurve;
    ObjectDescriptorCallback goNextPoint;
    ObjectDescriptorCallback setClosed;
    ObjectDescriptorCallback setNextNode;
    ObjectDescriptorCallback goNextPointIndexed;
    ObjectDescriptorCallback getForwardControlPointId;
    ObjectDescriptorCallback getControlPointId;
    ObjectDescriptorCallback initFromCurveId;
} RomCurveDllInterface;

RomCurveDllInterface RomCurve_funcs = {
    0,
    0,
    0,
    0x2C0000,
    (ObjectDescriptorCallback)RomCurve_initialise,
    (ObjectDescriptorCallback)RomCurve_release,
    0,
    (ObjectDescriptorCallback)curves_initialise,
    (ObjectDescriptorCallback)RomCurve_add,
    (ObjectDescriptorCallback)RomCurve_remove,
    (ObjectDescriptorCallback)RomCurve_getCurves,
    (ObjectDescriptorCallback)RomCurve_find,
    (ObjectDescriptorCallback)curves_findNearObj,
    (ObjectDescriptorCallback)RomCurve_getById,
    (ObjectDescriptorCallback)curves_find,
    (ObjectDescriptorCallback)curves_distToObj,
    (ObjectDescriptorCallback)curves_distXZ,
    (ObjectDescriptorCallback)RomCurve_getLastFindSegment,
    (ObjectDescriptorCallback)curves_isPoint,
    (ObjectDescriptorCallback)curves_isNotPoint,
    (ObjectDescriptorCallback)RomCurve_getRandomLinkedOfTypes,
    (ObjectDescriptorCallback)RomCurve_findLinkTowardNearestOfType,
    (ObjectDescriptorCallback)curves_findByAction,
    (ObjectDescriptorCallback)RomCurve_func13,
    (ObjectDescriptorCallback)curves_findNearestOfType16,
    (ObjectDescriptorCallback)curves_isPointInsideLoop,
    (ObjectDescriptorCallback)curves_findEnclosingLoopOfType17,
    (ObjectDescriptorCallback)RomCurve_getRandomForwardLink,
    (ObjectDescriptorCallback)RomCurve_getLinkIds,
    (ObjectDescriptorCallback)RomCurve_getFarthestAdjacentLink,
    (ObjectDescriptorCallback)RomCurve_getRandomBackwardLink,
    (ObjectDescriptorCallback)Objfsa_GetNearestAdjacentLink,
    (ObjectDescriptorCallback)RomCurve_findShortestPathLink,
    (ObjectDescriptorCallback)RomCurve_getAdjacentWindow,
    (ObjectDescriptorCallback)RomCurve_buildAdjacentWindowPoints,
    (ObjectDescriptorCallback)RomCurve_countRandomPoints,
    (ObjectDescriptorCallback)RomCurve_buildRandomPoints,
    (ObjectDescriptorCallback)RomCurve_projectPointToAdjacentWindow,
    (ObjectDescriptorCallback)RomCurve_findProjectedCurveFromStart,
    (ObjectDescriptorCallback)curves_getPos,
    (ObjectDescriptorCallback)curves_getPathLength,
    (ObjectDescriptorCallback)RomCurve_initCurve,
    (ObjectDescriptorCallback)RomCurve_goNextPoint,
    (ObjectDescriptorCallback)RomCurve_setClosed,
    (ObjectDescriptorCallback)RomCurve_setNextNode,
    (ObjectDescriptorCallback)RomCurve_goNextPointIndexed,
    (ObjectDescriptorCallback)RomCurve_getForwardControlPointId,
    (ObjectDescriptorCallback)RomCurve_getControlPointId,
    (ObjectDescriptorCallback)RomCurve_initFromCurveId,
};
char sCurvesMaxRomCurvesExceeded[36] = "curves.c: MAX_ROMCURVES exceeded!!\n\000";
