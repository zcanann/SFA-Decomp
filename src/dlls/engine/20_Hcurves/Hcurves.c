#define TRACK_BBOX_FLAGS_S8
#include "dolphin/os/OSReport.h"
#include "main/dll/rom_curve_def.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/objfsa.h"
#include "main/dll/Hcurves_api.h"
#include "main/dll/rom_curve_interface.h"
#include "game/objects/object.h"
#include "main/curve.h"
#include "main/track_bbox_api.h"
#include "main/curve_eval.h"
#include "main/voxmaps.h"
#include "main/dll/dll_0015_curves.h"
#include "main/obj_list.h"
#include "main/gamebits.h"
#include "main/dll/modgfx.h"
#include "main/dll/dll_0014_unk.h"
#include "main/vecmath_distance_api.h"
#include "main/shader_api.h"
#include "string.h"
#include "main/dll/objfsa_internal.h"

static int sObjfsaUnused0;
int gObjfsaPatchCount;
int gObjfsaLastWalkGroupIndex;
int gObjfsaBlockFlagsChecksum;

extern char sObjfsaFoundNewWalkGroupPatch[];
extern char sObjfsaIsPointWithinPatchGroupError[];

extern char sObjfsaMissingPatchExitPoint0[];
extern char sObjfsaMissingPatchExitPoint1[];

#define OBJFSA_PHASE_LIMIT 1.0f

ObjfsaPatch gObjfsaPatches[0x3000 / sizeof(ObjfsaPatch)];
ObjfsaWalkGroup gObjfsaWalkGroups[0x1C48 / sizeof(ObjfsaWalkGroup)];
u8 gObjfsaWalkGroupActive[0xB8];

#define OBJFSA_CORNER(BASE, OFF, POSOFF) (f32)((f32) * (s8*)(OFF) * scale + *(f32*)((BASE) + (POSOFF)))
#define OBJFSA_SET_PLANE(P, K, XA, ZA)                                                                                 \
    normalLength = sqrtf(normalX * normalX + normalZ * normalZ);                                                       \
    if (normalLength) {                                                                                                \
        normalX = normalX / normalLength;                                                                              \
        normalZ = normalZ / normalLength;                                                                              \
    }                                                                                                                  \
    (P).planes[K].normalX = Objfsa_PackPlaneNormal(normalX);                                                           \
    (P).planes[K].normalZ = Objfsa_PackPlaneNormal(normalZ);                                                           \
    (P).planeOffsets[K] = -((f32)(P).planes[K].normalX * (XA) + (f32)(P).planes[K].normalZ * (ZA))
#define OBJFSA_NEWPATCH (patchBase[0][gObjfsaPatchCount])
#define OBJFSA_NEWPATCH_S16(F)                                                                                         \
    (*(s16*)((gObjfsaPatchCount * sizeof(ObjfsaPatch) + offsetof(ObjfsaPatch, F)) + (int)patchBase[0]))
#define OBJFSA_SET_NEWPATCH_PLANE(K, DXE, DZE, XA, ZA)                                                                 \
    plane = &OBJFSA_NEWPATCH.planes[K];                                                                                \
    planeOffset = &OBJFSA_NEWPATCH.planeOffsets[K];                                                                    \
    normalX = (DXE);                                                                                                   \
    normalZ = (DZE);                                                                                                   \
    normalLength = sqrtf(normalX * normalX + normalZ * normalZ);                                                       \
    if (normalLength) {                                                                                                \
        normalX = normalX / normalLength;                                                                              \
        normalZ = normalZ / normalLength;                                                                              \
    }                                                                                                                  \
    plane->normalX = Objfsa_PackPlaneNormal(normalX);                                                                  \
    plane->normalZ = Objfsa_PackPlaneNormal(normalZ);                                                                  \
    *(planeOffset) = -(plane->normalX * (XA) + plane->normalZ * (ZA))

static inline f32 RomCurveNode_GetHermiteTangent(RomCurveDef** nodePtr, int angleOffset, int useCos);
inline f32 objfsaCorner(s8 ofs, f32 scl, f32* base);

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

void RomCurve_swapEndpointNodes(RomCurveWalker* p) {
    u32* a = (u32*)&p->previousNode;
    u32* b = (u32*)&p->nextNode;
    *a ^= *b;
    *b ^= *a;
    *a ^= *b;
    if (p->phase >= OBJFSA_PHASE_LIMIT) {
        p->phase = 0.99f;
    }
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
        if (id > ((RomCurveDef*)romCurves[mid])->id) {
            lo = mid + 1;
        } else if (id < ((RomCurveDef*)romCurves[mid])->id) {
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

static inline int Objfsa_RomCurveIsForwardEnd(RomCurveDef* c) {
    int slot;

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

int RomCurve_setSegmentEndNode(RomCurveWalker* walker, RomCurveDef* curve) {
    RomCurveDef* B = curve;
    if (walker->currentNode == NULL || walker->nextNode == NULL || curve == 0) {
        return 1;
    }
    walker->nextNode = curve;
    if (walker->reverse != 0) {
        walker->hermX[0] = B->x;
        walker->hermX[2] =
            2.0f * ((float)(u32)B->tangentMag * mathSinf(3.1415927f * (float)((s32)B->yaw << 8) / 32768.0f));
        walker->hermY[0] = B->y;
        walker->hermY[2] =
            2.0f * ((float)(u32)B->tangentMag * mathSinf(3.1415927f * (float)((s32)B->pitch << 8) / 32768.0f));
        walker->hermZ[0] = B->z;
        walker->hermZ[2] =
            2.0f * ((float)(u32)B->tangentMag * mathCosf(3.1415927f * (float)((s32)B->yaw << 8) / 32768.0f));
    } else {
        walker->hermX2[1] = B->x;
        walker->hermX2[3] =
            2.0f * ((float)(u32)B->tangentMag * mathSinf(3.1415927f * (float)((s32)B->yaw << 8) / 32768.0f));
        walker->hermY2[1] = B->y;
        walker->hermY2[3] =
            2.0f * ((float)(u32)B->tangentMag * mathSinf(3.1415927f * (float)((s32)B->pitch << 8) / 32768.0f));
        walker->hermZ2[1] = B->z;
        walker->hermZ2[3] =
            2.0f * ((float)(u32)B->tangentMag * mathCosf(3.1415927f * (float)((s32)B->yaw << 8) / 32768.0f));
    }
    return 0;
}

static inline f32 RomCurveNode_GetHermiteTangent(RomCurveDef** nodePtr, int angleOffset, int useCos) {
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

int RomCurve_advanceToNextSegment(RomCurveWalker* state, RomCurveDef* targetCurve) {
    char* stateBytes;

    stateBytes = (char*)state;
    if (state->currentNode == NULL || state->nextNode == NULL || targetCurve == NULL) {
        return 1;
    }

    if (state->reverse != 0) {
        state->previousNode = state->currentNode;
        state->currentNode = state->nextNode;
        state->nextNode = targetCurve;

        memcpy(state->hermX2, state->hermX, sizeof(state->hermX2));
        memcpy(state->hermY2, state->hermY, sizeof(state->hermY2));
        memcpy(state->hermZ2, state->hermZ, sizeof(state->hermZ2));

        state->hermX[0] = ((RomCurveDef*)state->nextNode)->x;
        state->hermX[1] = ((RomCurveDef*)state->currentNode)->x;
        state->hermX[2] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2c, 0);
        state->hermX[3] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2c, 0);

        state->hermY[0] = ((RomCurveDef*)state->nextNode)->y;
        state->hermY[1] = ((RomCurveDef*)state->currentNode)->y;
        state->hermY[2] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2d, 0);
        state->hermY[3] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2d, 0);

        state->hermZ[0] = ((RomCurveDef*)state->nextNode)->z;
        state->hermZ[1] = ((RomCurveDef*)state->currentNode)->z;
        state->hermZ[2] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2c, 1);
        state->hermZ[3] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2c, 1);

        if (state->moveNetwork != 0) {
            curvesSetupMoveNetworkCurve(&state->curve);
            if (state->phase <= 0.0f) {
                state->phase = 0.01f;
            }
        }
    } else {
        state->previousNode = state->currentNode;
        state->currentNode = state->nextNode;
        state->nextNode = targetCurve;

        memcpy(state->hermX, state->hermX2, sizeof(state->hermX));
        memcpy(state->hermY, state->hermY2, sizeof(state->hermY));
        memcpy(state->hermZ, state->hermZ2, sizeof(state->hermZ));

        state->hermX2[0] = ((RomCurveDef*)state->currentNode)->x;
        state->hermX2[1] = ((RomCurveDef*)state->nextNode)->x;
        state->hermX2[2] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2c, 0);
        state->hermX2[3] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2c, 0);

        state->hermY2[0] = ((RomCurveDef*)state->currentNode)->y;
        state->hermY2[1] = ((RomCurveDef*)state->nextNode)->y;
        state->hermY2[2] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2d, 0);
        state->hermY2[3] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2d, 0);

        state->hermZ2[0] = ((RomCurveDef*)state->currentNode)->z;
        state->hermZ2[1] = ((RomCurveDef*)state->nextNode)->z;
        state->hermZ2[2] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2c, 1);
        state->hermZ2[3] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2c, 1);

        if (state->moveNetwork != 0) {
            curvesSetupMoveNetworkCurve(&state->curve);
            if (state->phase >= OBJFSA_PHASE_LIMIT) {
                state->phase = 0.99f;
            }
        }
    }

    return 0;
}
void RomCurve_stepClamped(RomCurveWalker* state, f32 dt) {
    if (state->phase <= 0.0f) {
        state->phase = 0.01f;
    } else if (state->phase >= OBJFSA_PHASE_LIMIT) {
        state->phase = 0.99f;
    }
    Curve_AdvanceAlongPath(&state->curve, dt);
}

int RomCurve_setupHermiteSegment(RomCurveWalker* state, RomCurveDef* fromCurve, RomCurveDef* toCurve,
                                 RomCurveDef* targetCurve) {
    if (state->reverse != 0) {
        state->currentNode = fromCurve;
        state->nextNode = toCurve;

        state->hermX[0] = ((RomCurveDef*)state->nextNode)->x;
        state->hermX[1] = ((RomCurveDef*)state->currentNode)->x;
        state->hermX[2] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2c, 0);
        state->hermX[3] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2c, 0);

        state->hermY[0] = ((RomCurveDef*)state->nextNode)->y;
        state->hermY[1] = ((RomCurveDef*)state->currentNode)->y;
        state->hermY[2] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2d, 0);
        state->hermY[3] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2d, 0);

        state->hermZ[0] = ((RomCurveDef*)state->nextNode)->z;
        state->hermZ[1] = ((RomCurveDef*)state->currentNode)->z;
        state->hermZ[2] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2c, 1);
        state->hermZ[3] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2c, 1);
    } else {
        state->currentNode = fromCurve;
        state->nextNode = toCurve;

        state->hermX2[0] = ((RomCurveDef*)state->currentNode)->x;
        state->hermX2[1] = ((RomCurveDef*)state->nextNode)->x;
        state->hermX2[2] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2c, 0);
        state->hermX2[3] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2c, 0);

        state->hermY2[0] = ((RomCurveDef*)state->currentNode)->y;
        state->hermY2[1] = ((RomCurveDef*)state->nextNode)->y;
        state->hermY2[2] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2d, 0);
        state->hermY2[3] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2d, 0);

        state->hermZ2[0] = ((RomCurveDef*)state->currentNode)->z;
        state->hermZ2[1] = ((RomCurveDef*)state->nextNode)->z;
        state->hermZ2[2] = RomCurveNode_GetHermiteTangent(&state->currentNode, 0x2c, 1);
        state->hermZ2[3] = RomCurveNode_GetHermiteTangent(&state->nextNode, 0x2c, 1);
    }

    if (RomCurve_advanceToNextSegment(state, targetCurve) != 0) {
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

RomCurveDef* Objfsa_FindNearestCurveType24(f32* pos, int walkGroupFilter, int subtypeFilter) {
    int count;
    RomCurveDef* hit;
    RomCurveDef* bestHit;
    RomCurveDef** list = (RomCurveDef**)(*gRomCurveInterface)->getCurves(&count);
    f32 minDist = 3.4028235e+38f;
    int i;
    bestHit = 0;
    for (i = count; i > 0; i--) {
        hit = *list;
        if (hit != 0 && hit->type == ROMCURVE_TYPE_TRICKY &&
            (walkGroupFilter == -1 || hit->walkGroup == walkGroupFilter) &&
            (subtypeFilter == -1 || hit->subtype == subtypeFilter)) {
            f32 dx = pos[0] - hit->x;
            f32 dy = pos[1] - hit->y;
            f32 d;
            f32 dz = pos[2] - hit->z;
            d = dy * dy;
            d += dx * dx;
            d += dz * dz;
            if (d < minDist) {
                minDist = d;
                bestHit = hit;
            }
        }
        list++;
    }
    return bestHit;
}

RomCurveDef* Objfsa_FindNearestEnabledCurveType24(f32* pos, int walkGroupFilter, int subtypeFilter) {
    int count;
    RomCurveDef** list;
    int i;
    RomCurveDef* hit;
    RomCurveDef* bestHit;
    s16 gbId;
    f32 minDist;
    RomCurveDef** tmp = (RomCurveDef**)(*gRomCurveInterface)->getCurves(&count);
    minDist = 3.4028235e+38f;
    bestHit = 0;
    i = 0;
    list = tmp;
    for (; i < count; i++) {
        hit = *list;
        if (hit != 0 && hit->type == ROMCURVE_TYPE_TRICKY &&
            (walkGroupFilter == -1 || hit->walkGroup == walkGroupFilter) &&
            (subtypeFilter == -1 || hit->subtype == subtypeFilter)) {
            gbId = hit->requiredBit;
            if (gbId == -1 || mainGetBit(gbId) != 0) {
                gbId = hit->forbiddenBit;
                if (gbId == -1 || mainGetBit(gbId) == 0) {
                    f32 dx = pos[0] - hit->x;
                    f32 dy = pos[1] - hit->y;
                    f32 d;
                    f32 dz = pos[2] - hit->z;
                    d = dy * dy;
                    d += dx * dx;
                    d += dz * dz;
                    if (d < minDist) {
                        minDist = d;
                        bestHit = hit;
                    }
                }
            }
        }
        list++;
    }
    return bestHit;
}

void walkPath_writeU16LE(u16 value, u8* outBytes) {
    int word = value;
    outBytes[0] = word;
    outBytes[1] = word >> 8;
}

#define WALKGROUP_TRY_RETURN(idx)                                                                                      \
    if (Objfsa_IsWalkGroupActive(idx)) {                                                                               \
        g = &gObjfsaWalkGroups[idx];                                                                                   \
        y = point[1];                                                                                                  \
        if (y < g->maxY && y > g->minY) {                                                                              \
            z = point[2];                                                                                              \
            x = point[0];                                                                                              \
            i[0] = (j[0] = 0);                                                                                         \
            j[0] = 0;                                                                                                  \
            for (; i[0] < 4; i[0]++, j[0] += 2) {                                                                      \
                if (g->planeOffsets[i[0]] + (x * (f32)((s16*)g)[j[0]] + z * (f32)((s16*)g)[j[0] + 1]) > 0.0f) {        \
                    break;                                                                                             \
                }                                                                                                      \
            }                                                                                                          \
            if (i[0] == 4) {                                                                                           \
                gObjfsaLastWalkGroupIndex = (idx);                                                                     \
                return (idx);                                                                                          \
            }                                                                                                          \
        }                                                                                                              \
    }

int Objfsa_GetNearestPatchExit(f32* point, f32* outVec, u16 patchGroupId) {
    u8 i;
    f32 d1;

    for (i = 0; i < 256; i++) {
        if (gObjfsaPatches[i].groupId == patchGroupId) {
            break;
        }
    }

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit0X;
    outVec[1] = point[1];
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit0Z;
    d1 = vec3f_distanceSquared(point, outVec);

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit1X;
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit1Z;

    if (vec3f_distanceSquared(point, outVec) < d1) {
        return 1;
    }

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit0X;
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit0Z;
    return 1;
}

int Objfsa_GetWalkGroupIndexForMove(float* prevPoint, float* nextPoint, u32 currentWalkGroupIndex) {
    ObjfsaWalkGroup* lwg;
    ObjfsaWalkGroup* wg;
    u32 lpidx;
    u16 groupIdx;
    u16 pgid;
    u8 i;
    u8 j;
    u8 m;
    u32 pidx;
    u8 k2;
    ObjfsaPatch* patch;
    int lidx;
    ObjfsaPatch* lp;
    u8 k;
    f32 y;
    for (k = 0, wg = &gObjfsaWalkGroups[currentWalkGroupIndex]; k < 4; k++) {
        pidx = wg->patchIndices[k];
        if (pidx == 0) {
            continue;
        }
        patch = &gObjfsaPatches[pidx];
        y = prevPoint[1];
        if (y < patch->maxY && y > patch->minY) {
            i = 0;
            j = 0;
            for (; i < 4; i++, j += 2) {
                if (patch->planeOffsets[i] +
                        (prevPoint[0] * (f32)((s16*)patch)[j] + prevPoint[2] * (f32)((s16*)patch)[j + 1]) >
                    0.0f) {
                    break;
                }
            }
            if (i == 4) {
                y = nextPoint[1];
                if (y < patch->maxY && y > patch->minY) {
                    i = 0;
                    j = 0;
                    for (; i < 4; i++, j += 2) {
                        if (patch->planeOffsets[i] +
                                (nextPoint[0] * (f32)((s16*)patch)[j] + nextPoint[2] * (f32)((s16*)patch)[j + 1]) >
                            0.0f) {
                            break;
                        }
                    }
                    if (i == 4) {
                        return currentWalkGroupIndex;
                    }
                }
            }
        }
    }

    for (m = 0; m < 4; m++) {
        pidx = wg->patchIndices[m];
        if (pidx == 0) {
            continue;
        }
        if (((currentWalkGroupIndex == 255) & (pgid = gObjfsaPatches[pidx].groupId)) != 0) {
            pidx = (int)(pgid & 0xff00) >> 8;
            lidx = pidx & 0xffff;
        } else {
            lidx = (u8)pgid;
        }
        for (k2 = 0, lwg = &gObjfsaWalkGroups[lidx & 0xffff]; k2 < 4; k2++) {
            lpidx = lwg->patchIndices[k2];
            if (lpidx == 0) {
                continue;
            }
            lp = &gObjfsaPatches[lpidx];
            if (lp->groupId != patch->groupId) {
                y = prevPoint[1];
                if (y < lp->maxY && y > lp->minY) {
                    i = 0;
                    j = 0;
                    for (; i < 4; i++, j += 2) {
                        if (lp->planeOffsets[i] +
                                (prevPoint[0] * (f32)((s16*)lp)[j] + prevPoint[2] * (f32)((s16*)lp)[j + 1]) >
                            0.0f) {
                            break;
                        }
                    }
                    if (i == 4) {
                        y = nextPoint[1];
                        if (y < lp->maxY && y > lp->minY) {
                            i = 0;
                            j = 0;
                            for (; i < 4; i++, j += 2) {
                                if (lp->planeOffsets[i] +
                                        (nextPoint[0] * (f32)((s16*)lp)[j] + nextPoint[2] * (f32)((s16*)lp)[j + 1]) >
                                    0.0f) {
                                    break;
                                }
                            }
                            if (i == 4) {
                                groupIdx = lidx;
                                OSReport(sObjfsaFoundNewWalkGroupPatch, groupIdx);
                                return groupIdx;
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}

int isPointWithinPatchGroup(float* point, u32 patchGroupIndex, int groupId) {
    u8 k;
    u32 pidx;
    u8 i;
    u8 j;
    ObjfsaPatch* patch;
    f32 y;

    for (k = 0; k < 4; k++) {
        pidx = gObjfsaWalkGroups[patchGroupIndex].patchIndices[k];
        if (pidx != 0) {
            patch = &gObjfsaPatches[pidx];
            if (patch->groupId == groupId) {
                y = point[1];
                if (y < patch->maxY && y > patch->minY) {
                    i = 0;
                    j = 0;
                    for (; i < 4; i++, j += 2) {
                        if (patch->planeOffsets[i] +
                                (point[0] * (f32)((s16*)patch)[j] + point[2] * (f32)((s16*)patch)[j + 1]) >
                            0.0f) {
                            break;
                        }
                    }
                }
                return (u32)__cntlzw(4 - i) >> 5;
            }
        }
    }
    OSReport(sObjfsaIsPointWithinPatchGroupError);
    return 0;
}

int getPatchGroup(float* point, int patchGroupIndex) {
    char* base;
    u8* active;
    char* wg;
    u8 k;
    u32 pidx;
    u8 i;
    u8 j;
    ObjfsaPatch* patch;
    f32 y;

    base = (char*)gObjfsaPatches;
    k = 0;
    active = (u8*)gObjfsaPatches + patchGroupIndex + OBJFSA_ACTIVE_WALKGROUPS_OFFSET;
    wg = (char*)gObjfsaPatches + patchGroupIndex * OBJFSA_PATCHGROUP_STRIDE + 0x3000;

    for (; k < 4; k++) {
        if (*active == 0) {
            continue;
        }
        pidx = ((ObjfsaWalkGroup*)wg)->patchIndices[k];
        if (pidx == 0) {
            continue;
        }
        patch = (ObjfsaPatch*)(base + pidx * 0x30);
        y = point[1];
        if (y < patch->maxY && y > patch->minY) {
            i = 0;
            j = 0;
            for (; i < 4; i++, j += 2) {
                if (patch->planeOffsets[i] + (point[0] * (f32)((s16*)patch)[j] + point[2] * (f32)((s16*)patch)[j + 1]) >
                    0.0f) {
                    break;
                }
            }
        }
        if (i == 4) {
            return patch->groupId;
        }
    }
    return 0;
}
int isInWalkGroupOrPatch(float* point) {
    s16* nz;
    s16* nx;
    char* offs;
    ObjfsaPatch* patch;
    int count;
    s16 i;
    s16 idx;
    f32 y;

    if (Objfsa_FindWalkGroupIndexAtPoint(point) != 0) {
        return 1;
    }

    idx = 1;
    patch = &gObjfsaPatches[1];
    count = gObjfsaPatchCount;
    for (; idx < count; patch++, idx++) {
        y = point[1];
        if (y < patch->maxY && y > patch->minY) {
            i = 0;
            nz = (s16*)patch;
            nx = (s16*)patch;
            offs = (char*)patch;
            for (; i < 4; offs += 4, i++, nz += 2, nx += 2) {
                if (*(f32*)(offs + 0x10) + (point[0] * nx[0] + point[2] * nz[1]) > 0.0f) {
                    break;
                }
            }
            if (i == 4) {
                return 1;
            }
        }
    }
    return 0;
}
int Objfsa_GetWalkGroupIndexAtPoint(float* point, ObjfsaWalkGroupPatchInfo* patchInfo) {
    u32 walkGroupIndex;
    ObjfsaWalkGroup* walkGroup;
    u8 patchSlot;
    u8 patchBit;
    u32 patchIndex;
    u8 planeIndex;
    u8 normalComponentIndex;
    ObjfsaPatch* patch;
    f32 y;

    walkGroupIndex = (u8)Objfsa_FindWalkGroupIndexAtPoint(point);
    if (patchInfo != NULL && walkGroupIndex != 0) {
        patchInfo->walkGroupIndex = walkGroupIndex;
        patchInfo->patchMask = 0;
        patchSlot = 0;
        patchBit = 1;
        walkGroup = &gObjfsaWalkGroups[walkGroupIndex];
        for (; patchSlot < OBJFSA_PATCHGROUP_PATCH_COUNT; patchSlot++, patchBit <<= 1) {
            patchIndex = walkGroup->patchIndices[patchSlot];
            if (patchIndex != 0) {
                patch = &gObjfsaPatches[patchIndex];
                patchInfo->patchGroupIds[patchSlot] = patch->groupId;
                y = point[1];
                if (y < patch->maxY && y > patch->minY) {
                    planeIndex = 0;
                    normalComponentIndex = 0;
                    for (; planeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; planeIndex++, normalComponentIndex += 2) {
                        if (patch->planeOffsets[planeIndex] +
                                (point[0] * (f32)patch->normalComponents[normalComponentIndex] +
                                 point[2] * (f32)patch->normalComponents[normalComponentIndex + 1]) >
                            0.0f) {
                            break;
                        }
                    }
                }
                /* Retail leaves planeIndex uninitialized or stale when Y is rejected. */
                if (planeIndex == OBJFSA_PATCHGROUP_PATCH_COUNT) {
                    patchInfo->patchMask |= patchBit;
                }
            } else {
                patchInfo->patchGroupIds[patchSlot] = 0;
            }
        }
    }
    return walkGroupIndex;
}
/* Returns the first rejecting X/Z plane, or the plane count when all contain the point. */
static inline u8 objfsaFindRejectingPatchPlane(ObjfsaPatch* patch, float* point) {
    f32 z;
    f32 x;
    u8 planeIndex;
    u8 normalComponentIndex;
    z = point[2];
    x = point[0];
    planeIndex = 0;
    normalComponentIndex = planeIndex;
    for (; planeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; planeIndex++, normalComponentIndex += 2) {
        if (patch->planeOffsets[planeIndex] + (x * (f32)patch->normalComponents[normalComponentIndex] +
                                               z * (f32)patch->normalComponents[normalComponentIndex + 1]) >
            0.0f) {
            break;
        }
    }
    return planeIndex;
}

int Objfsa_GetPatchGroupIdAtPoint(float* point) {
    int patchIndex;
    ObjfsaPatch* patch;

    for (patchIndex = 0; patchIndex < gObjfsaPatchCount; patchIndex++) {
        f32 y = point[1];
        patch = &gObjfsaPatches[patchIndex];
        if (y < patch->maxY && y > patch->minY) {
            if (objfsaFindRejectingPatchPlane(patch, point) == OBJFSA_PATCHGROUP_PATCH_COUNT) {
                return patch->groupId;
            }
        }
    }
    return 0;
}

int Objfsa_FindWalkGroupIndexAtPoint(float* point) {
    s16 upperGroupIndex;
    ObjfsaWalkGroup* lowerGroup;
    ObjfsaWalkGroup* finalGroup;
    s16 lowerGroupIndex;
    u8 normalIndex[1];
    f32 planeOffset;
    u8 edgeIndex[1];
    ObjfsaWalkGroup* walkGroup;
    f32 pointY;
    f32 pointX;
    f32 pointZCopy;
    f32 pointZ;

    lowerGroupIndex = gObjfsaLastWalkGroupIndex;
    if (gObjfsaLastWalkGroupIndex == OBJFSA_WALKGROUP_COUNT - 1) {
        upperGroupIndex = 0;
    } else {
        upperGroupIndex = 1;
        upperGroupIndex = gObjfsaLastWalkGroupIndex + upperGroupIndex;
    }

    while (lowerGroupIndex != upperGroupIndex) {
        if (gObjfsaWalkGroupActive[lowerGroupIndex]) {
            lowerGroup = &gObjfsaWalkGroups[lowerGroupIndex];
            walkGroup = lowerGroup;
            pointY = point[1];
            if (pointY < walkGroup->maxY && pointY > walkGroup->minY) {
                pointZCopy = point[2];
                pointX = point[0];
                pointZ = pointZCopy;
                edgeIndex[0] = (normalIndex[0] = 0);
                normalIndex[0] = 0;
                for (; edgeIndex[0] < 4; edgeIndex[0]++, normalIndex[0] += 2) {
                    if (walkGroup->planeOffsets[edgeIndex[0]] + (pointX * (f32)((s16*)walkGroup)[normalIndex[0]] +
                                                                 pointZ * (f32)((s16*)walkGroup)[normalIndex[0] + 1]) >
                        0.0f) {
                        break;
                    }
                }
                if (edgeIndex[0] == 4) {
                    gObjfsaLastWalkGroupIndex = lowerGroupIndex;
                    return lowerGroupIndex;
                }
            }
        }
        if (gObjfsaWalkGroupActive[upperGroupIndex]) {
            walkGroup = &gObjfsaWalkGroups[upperGroupIndex];
            pointY = point[1];
            if (pointY < walkGroup->maxY && pointY > walkGroup->minY) {
                pointZ = point[2];
                pointX = point[0];
                edgeIndex[0] = (normalIndex[0] = 0);
                normalIndex[0] = 0;
                for (; edgeIndex[0] < 4; edgeIndex[0]++, normalIndex[0] += 2) {
                    if (walkGroup->planeOffsets[edgeIndex[0]] + (pointX * (f32)((s16*)walkGroup)[normalIndex[0]] +
                                                                 pointZ * (f32)((s16*)walkGroup)[normalIndex[0] + 1]) >
                        0.0f) {
                        break;
                    }
                }
                if (edgeIndex[0] == 4) {
                    gObjfsaLastWalkGroupIndex = upperGroupIndex;
                    return upperGroupIndex;
                }
            }
        }

        lowerGroupIndex--;
        if (lowerGroupIndex == -1) {
            lowerGroupIndex = OBJFSA_WALKGROUP_COUNT - 1;
        }
        upperGroupIndex++;
        if (upperGroupIndex == OBJFSA_WALKGROUP_COUNT) {
            upperGroupIndex = 0;
        }
    }

    if (gObjfsaWalkGroupActive[lowerGroupIndex]) {
        finalGroup = &gObjfsaWalkGroups[lowerGroupIndex];
        walkGroup = finalGroup;
        pointY = point[1];
        if (pointY < walkGroup->maxY && pointY > walkGroup->minY) {
            pointZ = point[2];
            pointX = point[0];
            edgeIndex[0] = (normalIndex[0] = 0);
            normalIndex[0] = 0;
            for (; edgeIndex[0] < 4; edgeIndex[0]++, normalIndex[0] += 2) {
                planeOffset = walkGroup->planeOffsets[edgeIndex[0]];
                if (planeOffset + (pointX * (f32)((s16*)walkGroup)[normalIndex[0]] +
                                   (f32)((s16*)walkGroup)[normalIndex[0] + 1] * pointZ) >
                    0.0f) {
                    break;
                }
            }
            if (edgeIndex[0] == 4) {
                gObjfsaLastWalkGroupIndex = lowerGroupIndex;
                return lowerGroupIndex;
            }
        }
    }
    return 0;
}
inline f32 objfsaCorner(s8 ofs, f32 scl, f32* base) {
    return (f32)((f32)ofs * scl + *base);
}

inline int objfsaExitOutside(ObjfsaWalkGroup* g, s16 ex, s16 ez) {
    f32 exitFz;
    f32 exitFx;
    f32 zero;
    u8 edge;
    u8 normalIdx;

    zero = 0.0f;
    exitFz = (f32)ez;
    exitFx = (f32)ex;
    edge = 0;
    normalIdx = edge;
    for (; edge < 4; edge++, normalIdx += 2) {
        if (g->planeOffsets[edge] + (exitFx * (f32)((s16*)g)[normalIdx] + exitFz * (f32)((s16*)g)[normalIdx + 1]) >
            zero) {
            break;
        }
    }
    return edge != 4;
}

static s16 Objfsa_PackPlaneNormal(f32 normal) {
    return 32767.0f * normal;
}

void Objfsa_UpdateWalkGroupPatches(void) {
    char* edgeSlotCursor;
    u8 loadedBlockFlags[ROM_LIST_PAGE_COUNT];
    u8 patchWalkGroupPairs[364];
    f32 z1;
    f32 x1;
    ObjfsaPatch* newPatch;
    s8* edgeCoords;
    u8 groupB;
    ObjfsaPatch* patch;
    int flagIndex;
    int matchingPatchIndex;
    int curveCount;
    ObjfsaPatch* patchBase[1];
    ObjfsaWalkCurveDef** curveCursor;
    u8* groupPair;
    int curveIndex;
    int returnEdgeIndex;
    int edgeIndex;
    ObjfsaWalkCurveDef* curve;
    ObjfsaWalkCurveDef* linkedCurve;
    int exitMoveCount;
    int patchIndex;
    u8 walkGroupIndex;
    u8 groupA;
    int packedGroupId;
    u16 storedGroupId;
    u32 checksum;
    int searchIndex;
    ObjfsaPatchPlane* plane;
    f32* planeOffset;
    ObjfsaPatch* exitPatch;
    ObjfsaWalkCurveDef** curveList;
    ObjfsaPatch* patchCursor;
    f32 exitDeltaX;
    f32 exitDeltaZ;
    f32 exitStepDivisor;
    f32 cornerScale;
    f32 normalX;
    f32 normalZ;
    f32 normalLength;
    f32 x0;
    f32 z0;
    ObjfsaPatch* exitSourcePatch;
    f32 x2;
    f32 z2;
    f32 x3;
    f32 z3;
    f32 curveHeight;
    f32 linkedCurveHeight;
    s16 patchHeight;
    ObjfsaWalkGroup* walkGroup;
    ObjfsaWalkGroup* firstWalkGroup;
    ObjfsaWalkGroup* secondWalkGroup;
    s32* linkId;
    ObjfsaPatch* exitRecord;
    patchBase[0] = gObjfsaPatches;
    mapGetLoadedMapFlags(loadedBlockFlags);

    checksum = 1;
    for (flagIndex = 0; flagIndex < ROM_LIST_PAGE_COUNT; flagIndex++) {
        if (loadedBlockFlags[flagIndex] != 0) {
            checksum *= flagIndex;
        }
    }

    if (checksum != gObjfsaBlockFlagsChecksum) {
        gObjfsaBlockFlagsChecksum = checksum;
    } else {
        return;
    }

    {
        if (loadedBlockFlags[2] != 0 || loadedBlockFlags[0x34] != 0) {
            cornerScale = 14.0f;
        } else {
            cornerScale = 10.0f;
        }

        curveList = (ObjfsaWalkCurveDef**)(*gRomCurveInterface)->getCurves(&curveCount);
        memset(Objfsa_GetStorage(patchBase[0])->activeWalkGroups, 0, OBJFSA_WALKGROUP_COUNT);
        patchCursor = patchBase[0];
        for (patchIndex = 0; patchIndex < 256; patchIndex++) {
            patchCursor->groupId = 0;
            patchCursor++;
        }

        gObjfsaPatchCount = 1;
        for (curveIndex = 0, curveCursor = curveList; curveIndex < curveCount; curveIndex++) {
            curve = *curveCursor;
            if (curve->type == 0x26) {
                walkGroupIndex = curve->walkGroup;
                walkGroup = &((ObjfsaWalkGroup*)(patchBase[0] + 256))[walkGroupIndex];
                *(u8*)((walkGroupIndex + OBJFSA_ACTIVE_WALKGROUPS_OFFSET) + (int)patchBase[0]) = 1;

                x0 = objfsaCorner(curve->firstEdge[0], cornerScale, &curve->x);
                z0 = objfsaCorner(curve->firstEdge[1], cornerScale, &curve->z);
                x1 = objfsaCorner(curve->firstEdge[2], cornerScale, &curve->x);
                z1 = objfsaCorner(curve->firstEdge[3], cornerScale, &curve->z);

                normalX = z1 - z0;
                normalZ = x0 - x1;
                OBJFSA_SET_PLANE(*walkGroup, 0, x0, z0);

                x2 = objfsaCorner(curve->secondEdge[0], cornerScale, &curve->x);
                z2 = objfsaCorner(curve->secondEdge[1], cornerScale, &curve->z);
                normalX = z2 - z1;
                normalZ = x1 - x2;
                OBJFSA_SET_PLANE(*walkGroup, 1, x1, z1);

                x3 = objfsaCorner(curve->secondEdge[2], cornerScale, &curve->x);
                z3 = objfsaCorner(curve->secondEdge[3], cornerScale, &curve->z);
                normalX = z3 - z2;
                normalZ = x2 - x3;
                OBJFSA_SET_PLANE(*walkGroup, 2, x2, z2);

                normalX = objfsaCorner(curve->firstEdge[1], cornerScale, &curve->z) - z3;
                normalZ = x3 - objfsaCorner(curve->firstEdge[0], cornerScale, &curve->x);
                OBJFSA_SET_PLANE(*walkGroup, 3, x3, z3);

                walkGroup->maxY = (s16)(2.0f * curve->maxYExtent + curve->y);
                walkGroup->minY = (s16) - (2.0f * curve->minYExtent - curve->y);

                for (edgeIndex = 0, edgeSlotCursor = (char*)curve; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT;
                     edgeIndex++) {
                    walkGroup->patchIndices[edgeIndex] = 0;
                    linkId = (s32*)(edgeSlotCursor + offsetof(ObjfsaWalkCurveDef, linkIds));
                    if (*linkId > -1 &&
                        (linkedCurve = (ObjfsaWalkCurveDef*)(*gRomCurveInterface)->getById(*linkId)) != 0) {
                        groupA = curve->walkGroup;
                        groupB = linkedCurve->walkGroup;
                        if (groupA < groupB) {
                            packedGroupId = groupA | (groupB << 8);
                        } else {
                            packedGroupId = (groupA << 8) | groupB;
                        }

                        matchingPatchIndex = 1;
                        patchCursor = &patchBase[0][1];
                        for (searchIndex = 1; searchIndex < gObjfsaPatchCount; searchIndex++) {
                            if (packedGroupId == patchCursor->groupId) {
                                walkGroup->patchIndices[edgeIndex] = (u8)matchingPatchIndex;
                                break;
                            }
                            patchCursor++;
                            matchingPatchIndex++;
                        }

                        if (walkGroup->patchIndices[edgeIndex] == 0) {
                            returnEdgeIndex = 0;
                            if (curve->id != linkedCurve->linkIds[0] &&
                                (returnEdgeIndex = 1, curve->id != linkedCurve->linkIds[1]) &&
                                (returnEdgeIndex = 2, curve->id != linkedCurve->linkIds[2]) &&
                                (returnEdgeIndex = 3, curve->id != linkedCurve->linkIds[3])) {
                                returnEdgeIndex = 4;
                            }
                            walkGroup->patchIndices[edgeIndex] = gObjfsaPatchCount;
                            (newPatch = &patchBase[0][gObjfsaPatchCount])->groupId = (storedGroupId = packedGroupId);
                            patchWalkGroupPairs[gObjfsaPatchCount * 2] = curve->walkGroup;
                            patchWalkGroupPairs[gObjfsaPatchCount * 2 + 1] = linkedCurve->walkGroup;

                            edgeCoords = (s8*)(edgeSlotCursor + offsetof(ObjfsaWalkCurveDef, linkEdges));
                            x0 = objfsaCorner(edgeCoords[0], cornerScale, &curve->x);
                            z0 = objfsaCorner(edgeCoords[1], cornerScale, &curve->z);
                            x1 = objfsaCorner(edgeCoords[2], cornerScale, &curve->x);
                            z1 = objfsaCorner(edgeCoords[3], cornerScale, &curve->z);
                            newPatch->exit0X = (s16)((x0 + x1) / 2.0f);
                            newPatch->exit0Z = (s16)((z0 + z1) / 2.0f);

                            OBJFSA_SET_NEWPATCH_PLANE(0, z1 - z0, x0 - x1, x0, z0);

                            edgeCoords = (s8*)linkedCurve + returnEdgeIndex * sizeof(linkedCurve->linkEdges[0]);
                            x2 = objfsaCorner(edgeCoords[0x34], cornerScale, &linkedCurve->x);
                            z2 = objfsaCorner(edgeCoords[0x35], cornerScale, &linkedCurve->z);
                            OBJFSA_SET_NEWPATCH_PLANE(1, z2 - z1, x1 - x2, x1, z1);

                            x3 = objfsaCorner(edgeCoords[0x36], cornerScale, &linkedCurve->x);
                            z3 = objfsaCorner(edgeCoords[0x37], cornerScale, &linkedCurve->z);
                            (exitRecord = &OBJFSA_NEWPATCH)->exit1X = (s16)((x2 + x3) / 2.0f);
                            exitRecord->exit1Z = (s16)((z2 + z3) / 2.0f);

                            OBJFSA_SET_NEWPATCH_PLANE(2, z3 - z2, x2 - x3, x2, z2);

                            edgeCoords = (s8*)(edgeSlotCursor + offsetof(ObjfsaWalkCurveDef, linkEdges));
                            z0 = objfsaCorner(edgeCoords[1], cornerScale, &curve->z);
                            x0 = objfsaCorner(edgeCoords[0], cornerScale, &curve->x);
                            OBJFSA_SET_NEWPATCH_PLANE(3, z0 - z3, x3 - x0, x3, z3);

                            curveHeight = 2.0f * curve->maxYExtent + curve->y;
                            linkedCurveHeight = 2.0f * linkedCurve->maxYExtent + linkedCurve->y;
                            if (curveHeight > linkedCurveHeight) {
                                patchHeight = curveHeight;
                                OBJFSA_NEWPATCH_S16(maxY) = patchHeight;
                            } else {
                                patchHeight = linkedCurveHeight;
                                OBJFSA_NEWPATCH_S16(maxY) = patchHeight;
                            }
                            curveHeight = -(2.0f * curve->minYExtent - curve->y);
                            linkedCurveHeight = -(2.0f * linkedCurve->minYExtent - linkedCurve->y);
                            if (curveHeight < linkedCurveHeight) {
                                patchHeight = curveHeight;
                                OBJFSA_NEWPATCH_S16(minY) = patchHeight;
                            } else {
                                patchHeight = linkedCurveHeight;
                                OBJFSA_NEWPATCH_S16(minY) = patchHeight;
                            }
                            gObjfsaPatchCount++;
                        }
                    }
                    edgeSlotCursor += sizeof(curve->linkIds[0]);
                }
            }
            curveCursor++;
        }

        /* Keep each exit inside at least one of its two linked walk groups. */
        patchIndex = 1;
        groupPair = &patchWalkGroupPairs[2];
        exitStepDivisor = 20.0f;
        patch = &patchBase[0][1];
        for (; patchIndex < gObjfsaPatchCount; groupPair += 2, patch++, patchIndex++) {
            firstWalkGroup = &((ObjfsaWalkGroup*)(patchBase[0] + 256))[groupPair[0]];
            secondWalkGroup = &((ObjfsaWalkGroup*)(patchBase[0] + 256))[groupPair[1]];
            exitDeltaX = patch->exit1X - patch->exit0X;
            exitDeltaZ = patch->exit1Z - patch->exit0Z;

            exitMoveCount = 0;
            exitSourcePatch = exitPatch = patch;
            while (objfsaExitOutside(firstWalkGroup, exitPatch->exit0X, exitPatch->exit0Z) &&
                   objfsaExitOutside(secondWalkGroup, exitPatch->exit0X, exitPatch->exit0Z)) {
                patch->exit0X = (s16)(patch->exit0X + exitDeltaX / exitStepDivisor);
                patch->exit0Z = (s16)(patch->exit0Z + exitDeltaZ / exitStepDivisor);
                if (exitMoveCount++ == 100) {
                    OSReport(sObjfsaMissingPatchExitPoint0, patch->groupId & 0xff, patch->groupId >> 8);
                    break;
                }
            }

            exitMoveCount = 0;
            while (objfsaExitOutside(firstWalkGroup, exitPatch->exit1X, exitPatch->exit1Z) &&
                   objfsaExitOutside(secondWalkGroup, exitPatch->exit1X, exitPatch->exit1Z)) {
                exitPatch->exit1X = (s16)(exitSourcePatch->exit1X - exitDeltaX / exitStepDivisor);
                exitPatch->exit1Z = (s16)(exitPatch->exit1Z - exitDeltaZ / exitStepDivisor);
                if (exitMoveCount++ == 100) {
                    OSReport(sObjfsaMissingPatchExitPoint1, exitPatch->groupId & 0xff, exitPatch->groupId >> 8);
                    break;
                }
            }
        }
    }
}
void doNothing_onTrickyFree(void) {
}

void doNothing_onTrickyInit(void) {
}

char sObjfsaFoundNewWalkGroupPatch[] = "Found new walk group patch from walkgroup %d\n";
char sObjfsaIsPointWithinPatchGroupError[] = "Error in isPointWithinPatchGroup\n";
char sObjfsaMissingPatchExitPoint0[] = "Unable to find exit point 0 on patch between walkgroup %d and %d\n";
char sObjfsaMissingPatchExitPoint1[] = "Unable to find exit point 1 on patch between walkgroup %d and %d\n";
