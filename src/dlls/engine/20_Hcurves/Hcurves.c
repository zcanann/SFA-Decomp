#define OBJFSA_PATCH_EXIT_U16
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
    len = sqrtf(dxn * dxn + dzn * dzn);                                                                                \
    if (len)                                                                                                   \
    {                                                                                                                  \
        dxn = dxn / len;                                                                                               \
        dzn = dzn / len;                                                                                               \
    }                                                                                                                  \
    (P).planes[K].normalX = (s16)(32767.0f * dxn);                                                      \
    (P).planes[K].normalZ = (s16)(32767.0f * dzn);                                                      \
    (P).planeOffsets[K] = -((f32)(P).planes[K].normalX * (XA) + (f32)(P).planes[K].normalZ * (ZA))
#define OBJFSA_NEWPATCH (patchBase[0][gObjfsaPatchCount])
#define OBJFSA_NEWPATCH_S16(F)                                                                                        \
    (*(s16*)((gObjfsaPatchCount * sizeof(ObjfsaPatch) + offsetof(ObjfsaPatch, F)) + (int)patchBase[0]))
#define OBJFSA_SET_NEWPATCH_PLANE(K, DXE, DZE, XA, ZA)                                                                 \
    pl = &OBJFSA_NEWPATCH.planes[K];                                                                                   \
    po = &OBJFSA_NEWPATCH.planeOffsets[K];                                                                             \
    dxn = (DXE);                                                                                                       \
    dzn = (DZE);                                                                                                       \
    len = sqrtf(dxn * dxn + dzn * dzn);                                                                                \
    if (len)                                                                                                   \
    {                                                                                                                  \
        dxn = dxn / len;                                                                                               \
        dzn = dzn / len;                                                                                               \
    }                                                                                                                  \
    pl->normalX = (s16)(32767.0f * dxn);                                                                \
    pl->normalZ = (s16)(32767.0f * dzn);                                                                \
    *(po) = -(pl->normalX * (XA) + pl->normalZ * (ZA))

static inline f32 RomCurveNode_GetHermiteTangent(void** nodePtr, int angleOffset, int useCos);
inline f32 objfsaCorner(s8 ofs, f32 scl, f32* base);


static inline ObjfsaPatch* Objfsa_GetPatch(int patchIndex)
{
    return &gObjfsaPatches[patchIndex];
}

static inline ObjfsaStorage* Objfsa_GetStorage(ObjfsaPatch* patches)
{
    return (ObjfsaStorage*)patches;
}

static inline ObjfsaWalkGroup* Objfsa_GetWalkGroup(int groupIndex)
{
    return &gObjfsaWalkGroups[groupIndex];
}

static inline u8* Objfsa_GetPatchGroupPatchList(int groupIndex)
{
    return Objfsa_GetWalkGroup(groupIndex)->patchIndices;
}

static inline u8 Objfsa_IsWalkGroupActive(int groupIndex)
{
    return gObjfsaWalkGroupActive[groupIndex];
}

static inline int Objfsa_IsPointInsidePatch(const float* point, const ObjfsaPatch* patch)
{
    int edgeIndex;

    if (point[1] >= patch->maxY || patch->minY >= point[1])
    {
        return 0;
    }

    for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++)
    {
        if (patch->planeOffsets[edgeIndex] + point[0] * patch->planes[edgeIndex].normalX +
                point[2] * patch->planes[edgeIndex].normalZ >
            0.0f)
        {
            return 0;
        }
    }
    return 1;
}

static inline int Objfsa_IsPointInsideWalkGroup(const float* point, const ObjfsaWalkGroup* walkGroup)
{
    int edgeIndex;

    if (point[1] >= walkGroup->maxY || walkGroup->minY >= point[1])
    {
        return 0;
    }

    for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++)
    {
        if (walkGroup->planeOffsets[edgeIndex] + point[0] * walkGroup->planes[edgeIndex].normalX +
                point[2] * walkGroup->planes[edgeIndex].normalZ >
            0.0f)
        {
            return 0;
        }
    }
    return 1;
}

static inline u16 Objfsa_GetLinkedWalkGroup(u16 patchGroupId, u32 currentWalkGroupIndex)
{
    if (((__cntlzw(0xff - currentWalkGroupIndex) >> 5) & patchGroupId) != 0)
    {
        return (patchGroupId & 0xff00) >> 8;
    }
    return patchGroupId & 0xff;
}

void RomCurve_swapEndpointNodes(RomCurveWalker* p)
{
    u32* a = (u32*)&p->node9C;
    u32* b = (u32*)&p->nodeA4;
    *a ^= *b;
    *b ^= *a;
    *a ^= *b;
    if (p->phase >= OBJFSA_PHASE_LIMIT)
    {
        p->phase = 0.99f;
    }
}

static inline int Objfsa_FindRomCurveById(int curveId)
{
    int hi;
    int lo;
    int mid;
    u32 id;

    if (curveId < 0)
    {
        return 0;
    }

    hi = nRomCurves - 1;
    lo = 0;
    id = curveId;
    while (hi >= lo)
    {
        mid = (hi + lo) >> 1;
        if (id > ((RomCurveDef*)romCurves[mid])->id)
        {
            lo = mid + 1;
        }
        else if (id < ((RomCurveDef*)romCurves[mid])->id)
        {
            hi = mid - 1;
        }
        else
        {
            return (int)romCurves[mid];
        }
    }

    return 0;
}

static inline u32 RomCurve_GetId(RomCurveDef* curve)
{
    return curve->id;
}

static inline int RomCurve_IsLinkIdValid(int linkId)
{
    return -1 < linkId;
}

static inline RomCurveDef* RomCurve_FindByIdInline(u32 curveId)
{
    int high;
    int low;
    int mid;

    if ((s32)curveId < 0)
    {
        return NULL;
    }

    high = nRomCurves - 1;
    low = 0;
    while (high >= low)
    {
        mid = (high + low) >> 1;
        if (curveId > RomCurve_GetId(romCurves[mid]))
        {
            low = mid + 1;
        }
        else if (curveId < RomCurve_GetId(romCurves[mid]))
        {
            high = mid - 1;
        }
        else
        {
            return romCurves[mid];
        }
    }

    return NULL;
}

static inline RomCurveDef* RomCurve_FindByIdWithLimit(u32 curveId, int lim)
{
    int high;
    int low;
    int mid;

    if ((s32)curveId < 0)
    {
        return NULL;
    }

    high = lim;
    low = 0;
    while (high >= low)
    {
        mid = (high + low) >> 1;
        if (curveId > RomCurve_GetId(romCurves[mid]))
        {
            low = mid + 1;
        }
        else if (curveId < RomCurve_GetId(romCurves[mid]))
        {
            high = mid - 1;
        }
        else
        {
            return romCurves[mid];
        }
    }

    return NULL;
}

static inline int Objfsa_RomCurveIsBlocked(RomCurveDef* c)
{
    int slot;

    for (slot = 0; slot < 4; slot++)
    {
        if (c->linkIds[slot] != -1 && (c->blockedLinkMask & (1 << slot)) == 0)
        {
            return 0;
        }
    }
    return 1;
}

static inline int RomCurve_CollectUnblockedLinks(RomCurveDef* curve, int* ids)
{
    int link;
    int count;
    u32 mask;
    s32* lp;
    int i;

    count = 0;
    mask = 1;
    lp = curve->linkIds;
    for (i = 0; i < ROMCURVE_LINK_COUNT; i++)
    {
        link = *lp++;
        if ((link > -1) && ((curve->blockedLinkMask & mask) == 0) && (link != 0))
        {
            ids[count++] = link;
        }
        mask = mask << 1;
    }
    return count;
}

static inline int RomCurve_CollectBlockedLinks(RomCurveDef* curve, int* ids)
{
    int link;
    int count;
    u32 mask;
    s32* lp;
    int i;

    count = 0;
    mask = 1;
    lp = curve->linkIds;
    for (i = 0; i < ROMCURVE_LINK_COUNT; i++)
    {
        link = *lp++;
        if ((link > -1) && ((curve->blockedLinkMask & mask) != 0) && (link != 0))
        {
            ids[count++] = link;
        }
        mask = mask << 1;
    }
    return count;
}

int RomCurve_setSegmentEndNode(RomCurveWalker* walker, void* curve)
{
    RomCurveDef* B = (RomCurveDef*)curve;
    if (walker->nodeA0 == NULL || walker->nodeA4 == NULL || curve == 0)
        return 1;
    walker->nodeA4 = curve;
    if (walker->reverse != 0)
    {
        walker->hermX[0] = B->x;
        walker->hermX[2] = 2.0f * ((float)(u32)B->tangentMag *
                                  mathSinf(3.1415927f * (float)((s32)B->yaw << 8) / 32768.0f));
        walker->hermY[0] = B->y;
        walker->hermY[2] = 2.0f * ((float)(u32)B->tangentMag *
                                  mathSinf(3.1415927f * (float)((s32)B->pitch << 8) / 32768.0f));
        walker->hermZ[0] = B->z;
        walker->hermZ[2] = 2.0f * ((float)(u32)B->tangentMag *
                                  mathCosf(3.1415927f * (float)((s32)B->yaw << 8) / 32768.0f));
    }
    else
    {
        walker->hermX2[1] = B->x;
        walker->hermX2[3] = 2.0f * ((float)(u32)B->tangentMag *
                                  mathSinf(3.1415927f * (float)((s32)B->yaw << 8) / 32768.0f));
        walker->hermY2[1] = B->y;
        walker->hermY2[3] = 2.0f * ((float)(u32)B->tangentMag *
                                  mathSinf(3.1415927f * (float)((s32)B->pitch << 8) / 32768.0f));
        walker->hermZ2[1] = B->z;
        walker->hermZ2[3] = 2.0f * ((float)(u32)B->tangentMag *
                                  mathCosf(3.1415927f * (float)((s32)B->yaw << 8) / 32768.0f));
    }
    return 0;
}

static inline f32 RomCurveNode_GetHermiteTangent(void** nodePtr, int angleOffset, int useCos)
{
    f32 angle;
    f32 trig;

    angle = 3.1415927f * (f32)((s32) * (s8*)((char*)*nodePtr + angleOffset) << 8) / 32768.0f;
    if (useCos)
    {
        trig = mathCosf(angle);
    }
    else
    {
        trig = mathSinf(angle);
    }
    trig = (f32)(u32)((RomCurveDef*)*nodePtr)->tangentMag * trig;
    return 2.0f * trig;
}

int RomCurve_advanceToNextSegment(RomCurveWalker* state, void* targetCurve)
{
    char* stateBytes;

    stateBytes = (char*)state;
    if (state->nodeA0 == NULL || state->nodeA4 == NULL || targetCurve == NULL)
    {
        return 1;
    }

    if (state->reverse != 0)
    {
        state->node9C = state->nodeA0;
        state->nodeA0 = state->nodeA4;
        state->nodeA4 = targetCurve;

        memcpy(state->hermX2, state->hermX, sizeof(state->hermX2));
        memcpy(state->hermY2, state->hermY, sizeof(state->hermY2));
        memcpy(state->hermZ2, state->hermZ, sizeof(state->hermZ2));

        state->hermX[0] = ((RomCurveDef*)state->nodeA4)->x;
        state->hermX[1] = ((RomCurveDef*)state->nodeA0)->x;
        state->hermX[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 0);
        state->hermX[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 0);

        state->hermY[0] = ((RomCurveDef*)state->nodeA4)->y;
        state->hermY[1] = ((RomCurveDef*)state->nodeA0)->y;
        state->hermY[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2d, 0);
        state->hermY[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2d, 0);

        state->hermZ[0] = ((RomCurveDef*)state->nodeA4)->z;
        state->hermZ[1] = ((RomCurveDef*)state->nodeA0)->z;
        state->hermZ[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 1);
        state->hermZ[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 1);

        if (state->moveNetwork != 0)
        {
            curvesSetupMoveNetworkCurve(&state->curve);
            if (state->phase <= 0.0f)
            {
                state->phase = 0.01f;
            }
        }
    }
    else
    {
        state->node9C = state->nodeA0;
        state->nodeA0 = state->nodeA4;
        state->nodeA4 = targetCurve;

        memcpy(state->hermX, state->hermX2, sizeof(state->hermX));
        memcpy(state->hermY, state->hermY2, sizeof(state->hermY));
        memcpy(state->hermZ, state->hermZ2, sizeof(state->hermZ));

        state->hermX2[0] = ((RomCurveDef*)state->nodeA0)->x;
        state->hermX2[1] = ((RomCurveDef*)state->nodeA4)->x;
        state->hermX2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 0);
        state->hermX2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 0);

        state->hermY2[0] = ((RomCurveDef*)state->nodeA0)->y;
        state->hermY2[1] = ((RomCurveDef*)state->nodeA4)->y;
        state->hermY2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2d, 0);
        state->hermY2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2d, 0);

        state->hermZ2[0] = ((RomCurveDef*)state->nodeA0)->z;
        state->hermZ2[1] = ((RomCurveDef*)state->nodeA4)->z;
        state->hermZ2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 1);
        state->hermZ2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 1);

        if (state->moveNetwork != 0)
        {
            curvesSetupMoveNetworkCurve(&state->curve);
            if (state->phase >= OBJFSA_PHASE_LIMIT)
            {
                state->phase = 0.99f;
            }
        }
    }

    return 0;
}
void RomCurve_stepClamped(RomCurveWalker* state, f32 dt)
{
    if (state->phase <= 0.0f)
    {
        state->phase = 0.01f;
    }
    else if (state->phase >= OBJFSA_PHASE_LIMIT)
    {
        state->phase = 0.99f;
    }
    Curve_AdvanceAlongPath(&state->curve, dt);
}

int RomCurve_setupHermiteSegment(RomCurveWalker* state, void* fromCurve, void* toCurve, void* targetCurve)
{
    if (state->reverse != 0)
    {
        state->nodeA0 = fromCurve;
        state->nodeA4 = toCurve;

        state->hermX[0] = ((RomCurveDef*)state->nodeA4)->x;
        state->hermX[1] = ((RomCurveDef*)state->nodeA0)->x;
        state->hermX[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 0);
        state->hermX[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 0);

        state->hermY[0] = ((RomCurveDef*)state->nodeA4)->y;
        state->hermY[1] = ((RomCurveDef*)state->nodeA0)->y;
        state->hermY[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2d, 0);
        state->hermY[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2d, 0);

        state->hermZ[0] = ((RomCurveDef*)state->nodeA4)->z;
        state->hermZ[1] = ((RomCurveDef*)state->nodeA0)->z;
        state->hermZ[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 1);
        state->hermZ[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 1);
    }
    else
    {
        state->nodeA0 = fromCurve;
        state->nodeA4 = toCurve;

        state->hermX2[0] = ((RomCurveDef*)state->nodeA0)->x;
        state->hermX2[1] = ((RomCurveDef*)state->nodeA4)->x;
        state->hermX2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 0);
        state->hermX2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 0);

        state->hermY2[0] = ((RomCurveDef*)state->nodeA0)->y;
        state->hermY2[1] = ((RomCurveDef*)state->nodeA4)->y;
        state->hermY2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2d, 0);
        state->hermY2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2d, 0);

        state->hermZ2[0] = ((RomCurveDef*)state->nodeA0)->z;
        state->hermZ2[1] = ((RomCurveDef*)state->nodeA4)->z;
        state->hermZ2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 1);
        state->hermZ2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 1);
    }

    if (RomCurve_advanceToNextSegment(state, targetCurve) != 0)
    {
        return 1;
    }

    state->node94 = Curve_EvalHermite;
    state->node98 = Curve_BuildHermiteCoeffs;
    state->coeffX = state->hermX;
    state->coeffY = state->hermY;
    state->coeffZ = state->hermZ;
    state->moveNetwork = 8;
    curvesMove(&state->curve);
    return 0;
}


void* Objfsa_FindNearestCurveType24(f32* pos, int p4_filter, int p5_filter)
{
    int count;
    RomCurveDef* hit;
    RomCurveDef* bestHit;
    RomCurveDef** list = (RomCurveDef**)(*gRomCurveInterface)->getCurves(&count);
    f32 minDist = 3.4028235e+38f;
    int i;
    bestHit = 0;
    for (i = count; i > 0; i--)
    {
        hit = *list;
        if (hit != 0 && hit->type == ROMCURVE_TYPE_TRICKY &&
            (p4_filter == -1 || hit->walkGroup == p4_filter) &&
            (p5_filter == -1 || hit->unk1A == p5_filter))
        {
            f32 dx = pos[0] - hit->x;
            f32 dy = pos[1] - hit->y;
            f32 d;
            f32 dz = pos[2] - hit->z;
            d = dy * dy;
            d += dx * dx;
            d += dz * dz;
            if (d < minDist)
            {
                minDist = d;
                bestHit = hit;
            }
        }
        list++;
    }
    return bestHit;
}


void* Objfsa_FindNearestEnabledCurveType24(f32* pos, int p4_filter, int p5_filter)
{
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
    for (; i < count; i++)
    {
        hit = *list;
        if (hit != 0 && hit->type == ROMCURVE_TYPE_TRICKY &&
            (p4_filter == -1 || hit->walkGroup == p4_filter) &&
            (p5_filter == -1 || hit->unk1A == p5_filter))
        {
            gbId = hit->requiredBit;
            if (gbId == -1 || mainGetBit(gbId) != 0)
            {
                gbId = hit->forbiddenBit;
                if (gbId == -1 || mainGetBit(gbId) == 0)
                {
                    f32 dx = pos[0] - hit->x;
                    f32 dy = pos[1] - hit->y;
                    f32 d;
                    f32 dz = pos[2] - hit->z;
                    d = dy * dy;
                    d += dx * dx;
                    d += dz * dz;
                    if (d < minDist)
                    {
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

void walkPath_writeU16LE(u32 v, u8* dst)
{
    v = v & 0xffff;
    dst[0] = v;
    dst[1] = (u8)((s32)v >> 8);
}

#define WALKGROUP_TRY_RETURN(idx)                                                                                      \
    if (Objfsa_IsWalkGroupActive(idx))                                                                                 \
    {                                                                                                                  \
        g = &gObjfsaWalkGroups[idx];                                                                                   \
        y = point[1];                                                                                                  \
        if (y < g->maxY && y > g->minY)                                                                                \
        {                                                                                                              \
            z = point[2];                                                                                              \
            x = point[0];                                                                                              \
            i[0] = (j[0] = 0);                                                                                         \
            j[0] = 0;                                                                                                  \
            for (; i[0] < 4; i[0]++, j[0] += 2)                                                                        \
            {                                                                                                          \
                if (g->planeOffsets[i[0]] + (x * (f32)((s16*)g)[j[0]] + z * (f32)((s16*)g)[j[0] + 1]) > 0.0f)          \
                {                                                                                                      \
                    break;                                                                                             \
                }                                                                                                      \
            }                                                                                                          \
            if (i[0] == 4)                                                                                             \
            {                                                                                                          \
                gObjfsaLastWalkGroupIndex = (idx);                                                                     \
                return (idx);                                                                                          \
            }                                                                                                          \
        }                                                                                                              \
    }

int Objfsa_GetNearestPatchExit(f32* point, f32* outVec, u16 id)
{
    u8 i;
    f32 d1;

    for (i = 0; i < 256; i++)
    {
        if (gObjfsaPatches[i].groupId == id)
            break;
    }

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit0X;
    outVec[1] = point[1];
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit0Z;
    d1 = vec3f_distanceSquared(point, outVec);

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit1X;
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit1Z;

    if (vec3f_distanceSquared(point, outVec) < d1)
    {
        return 1;
    }

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit0X;
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit0Z;
    return 1;
}

int Objfsa_GetWalkGroupIndexForMove(float* prevPoint, float* nextPoint, u32 currentWalkGroupIndex)
{
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
    for (k = 0, wg = &gObjfsaWalkGroups[currentWalkGroupIndex]; k < 4; k++)
    {
        pidx = wg->patchIndices[k];
        if (pidx == 0)
        {
            continue;
        }
        patch = &gObjfsaPatches[pidx];
        y = prevPoint[1];
        if (y < patch->maxY && y > patch->minY)
        {
            i = 0;
            j = 0;
            for (; i < 4; i++, j += 2)
            {
                if (patch->planeOffsets[i] +
                        (prevPoint[0] * (f32)((s16*)patch)[j] + prevPoint[2] * (f32)((s16*)patch)[j + 1]) >
                    0.0f)
                {
                    break;
                }
            }
            if (i == 4)
            {
                y = nextPoint[1];
                if (y < patch->maxY && y > patch->minY)
                {
                    i = 0;
                    j = 0;
                    for (; i < 4; i++, j += 2)
                    {
                        if (patch->planeOffsets[i] +
                                (nextPoint[0] * (f32)((s16*)patch)[j] + nextPoint[2] * (f32)((s16*)patch)[j + 1]) >
                            0.0f)
                        {
                            break;
                        }
                    }
                    if (i == 4)
                    {
                        return currentWalkGroupIndex;
                    }
                }
            }
        }
    }

    for (m = 0; m < 4; m++)
    {
        pidx = wg->patchIndices[m];
        if (pidx == 0)
        {
            continue;
        }
        if (((currentWalkGroupIndex == 255) & (pgid = gObjfsaPatches[pidx].groupId)) != 0)
        {
            pidx = (int)(pgid & 0xff00) >> 8;
            lidx = pidx & 0xffff;
        }
        else
        {
            lidx = (u8)pgid;
        }
        for (k2 = 0, lwg = &gObjfsaWalkGroups[lidx & 0xffff]; k2 < 4; k2++)
        {
            lpidx = lwg->patchIndices[k2];
            if (lpidx == 0)
            {
                continue;
            }
            lp = &gObjfsaPatches[lpidx];
            if (lp->groupId != patch->groupId)
            {
                y = prevPoint[1];
                if (y < lp->maxY && y > lp->minY)
                {
                    i = 0;
                    j = 0;
                    for (; i < 4; i++, j += 2)
                    {
                        if (lp->planeOffsets[i] +
                                (prevPoint[0] * (f32)((s16*)lp)[j] + prevPoint[2] * (f32)((s16*)lp)[j + 1]) >
                            0.0f)
                        {
                            break;
                        }
                    }
                    if (i == 4)
                    {
                        y = nextPoint[1];
                        if (y < lp->maxY && y > lp->minY)
                        {
                            i = 0;
                            j = 0;
                            for (; i < 4; i++, j += 2)
                            {
                                if (lp->planeOffsets[i] +
                                        (nextPoint[0] * (f32)((s16*)lp)[j] + nextPoint[2] * (f32)((s16*)lp)[j + 1]) >
                                    0.0f)
                                {
                                    break;
                                }
                            }
                            if (i == 4)
                            {
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


int isPointWithinPatchGroup(float* point, u32 patchGroupIndex, int groupId)
{
    u8 k;
    u32 pidx;
    u8 i;
    u8 j;
    ObjfsaPatch* patch;
    f32 y;

    for (k = 0; k < 4; k++)
    {
        pidx = gObjfsaWalkGroups[patchGroupIndex].patchIndices[k];
        if (pidx != 0)
        {
            patch = &gObjfsaPatches[pidx];
            if (patch->groupId == groupId)
            {
                y = point[1];
                if (y < patch->maxY && y > patch->minY)
                {
                    i = 0;
                    j = 0;
                    for (; i < 4; i++, j += 2)
                    {
                        if (patch->planeOffsets[i] +
                                (point[0] * (f32)((s16*)patch)[j] + point[2] * (f32)((s16*)patch)[j + 1]) >
                            0.0f)
                        {
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


int getPatchGroup(float* point, int patchGroupIndex)
{
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

    for (; k < 4; k++)
    {
        if (*active == 0)
        {
            continue;
        }
        pidx = ((ObjfsaWalkGroup*)wg)->patchIndices[k];
        if (pidx == 0)
        {
            continue;
        }
        patch = (ObjfsaPatch*)(base + pidx * 0x30);
        y = point[1];
        if (y < patch->maxY && y > patch->minY)
        {
            i = 0;
            j = 0;
            for (; i < 4; i++, j += 2)
            {
                if (patch->planeOffsets[i] + (point[0] * (f32)((s16*)patch)[j] + point[2] * (f32)((s16*)patch)[j + 1]) >
                    0.0f)
                {
                    break;
                }
            }
        }
        if (i == 4)
        {
            return patch->groupId;
        }
    }
    return 0;
}
int isInWalkGroupOrPatch(float* point)
{
    s16* nz;
    s16* nx;
    char* offs;
    ObjfsaPatch* patch;
    int count;
    s16 i;
    s16 idx;
    f32 y;

    if (Objfsa_FindWalkGroupIndexAtPoint(point) != 0)
    {
        return 1;
    }

    idx = 1;
    patch = &gObjfsaPatches[1];
    count = gObjfsaPatchCount;
    for (; idx < count; patch++, idx++)
    {
        y = point[1];
        if (y < patch->maxY && y > patch->minY)
        {
            i = 0;
            nz = (s16*)patch;
            nx = (s16*)patch;
            offs = (char*)patch;
            for (; i < 4; offs += 4, i++, nz += 2, nx += 2)
            {
                if (*(f32*)(offs + 0x10) + (point[0] * nx[0] + point[2] * nz[1]) > 0.0f)
                {
                    break;
                }
            }
            if (i == 4)
            {
                return 1;
            }
        }
    }
    return 0;
}
int Objfsa_GetWalkGroupIndexAtPoint(float* point, ObjfsaWalkGroupPatchInfo* patchInfo)
{
    u32 wgi;
    ObjfsaWalkGroup* wg;
    u8 k;
    u8 mask;
    u32 pidx;
    u8 i;
    u8 j;
    ObjfsaPatch* patch;
    f32 y;

    wgi = (u8)Objfsa_FindWalkGroupIndexAtPoint(point);
    if (patchInfo != NULL && wgi != 0)
    {
        patchInfo->walkGroupIndex = wgi;
        patchInfo->patchMask = 0;
        k = 0;
        mask = 1;
        wg = &gObjfsaWalkGroups[wgi];
        for (; k < 4; k++, mask <<= 1)
        {
            pidx = wg->patchIndices[k];
            if (pidx != 0)
            {
                patch = &gObjfsaPatches[pidx];
                patchInfo->patchGroupIds[k] = patch->groupId;
                y = point[1];
                if (y < patch->maxY && y > patch->minY)
                {
                    i = 0;
                    j = 0;
                    for (; i < 4; i++, j += 2)
                    {
                        if (patch->planeOffsets[i] +
                                (point[0] * (f32)((s16*)patch)[j] + point[2] * (f32)((s16*)patch)[j + 1]) >
                            0.0f)
                        {
                            break;
                        }
                    }
                }
                if (i == 4)
                {
                    patchInfo->patchMask |= mask;
                }
            }
            else
            {
                patchInfo->patchGroupIds[k] = 0;
            }
        }
    }
    return wgi;
}
int Objfsa_GetPatchGroupIdAtPoint(float* point)
{
    int n;
    ObjfsaPatch* patch;

    for (n = 0; n < gObjfsaPatchCount; n++)
    {
        f32 y = point[1];
        patch = &gObjfsaPatches[n];
        if (y < patch->maxY && y > patch->minY)
        {
            f32 x;
            f32 z;
            u8 i[1];
            u8 j[1];
            z = point[2];
            x = point[0];
            i[0] = (j[0] = 0);
            j[0] = 0;
            for (; i[0] < 4; i[0]++, j[0] += 2)
            {
                if (patch->planeOffsets[i[0]] + (x * (f32)((s16*)patch)[j[0]] + z * (f32)((s16*)patch)[j[0] + 1]) >
                    0.0f)
                {
                    break;
                }
            }
            if (i[0] == 4)
            {
                return patch->groupId;
            }
        }
    }
    return 0;
}



int Objfsa_FindWalkGroupIndexAtPoint(float* point)
{
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
    if (gObjfsaLastWalkGroupIndex == OBJFSA_WALKGROUP_COUNT - 1)
    {
        upperGroupIndex = 0;
    }
    else
    {
        upperGroupIndex = 1;
        upperGroupIndex = gObjfsaLastWalkGroupIndex + upperGroupIndex;
    }

    while (lowerGroupIndex != upperGroupIndex)
    {
        if (gObjfsaWalkGroupActive[lowerGroupIndex])
        {
            lowerGroup = &gObjfsaWalkGroups[lowerGroupIndex];
            walkGroup = lowerGroup;
            pointY = point[1];
            if (pointY < walkGroup->maxY && pointY > walkGroup->minY)
            {
                pointZCopy = point[2];
                pointX = point[0];
                pointZ = pointZCopy;
                edgeIndex[0] = (normalIndex[0] = 0);
                normalIndex[0] = 0;
                for (; edgeIndex[0] < 4; edgeIndex[0]++, normalIndex[0] += 2)
                {
                    if (walkGroup->planeOffsets[edgeIndex[0]] +
                            (pointX * (f32)((s16*)walkGroup)[normalIndex[0]] +
                             pointZ * (f32)((s16*)walkGroup)[normalIndex[0] + 1]) >
                        0.0f)
                    {
                        break;
                    }
                }
                if (edgeIndex[0] == 4)
                {
                    gObjfsaLastWalkGroupIndex = lowerGroupIndex;
                    return lowerGroupIndex;
                }
            }
        }
        if (gObjfsaWalkGroupActive[upperGroupIndex])
        {
            walkGroup = &gObjfsaWalkGroups[upperGroupIndex];
            pointY = point[1];
            if (pointY < walkGroup->maxY && pointY > walkGroup->minY)
            {
                pointZ = point[2];
                pointX = point[0];
                edgeIndex[0] = (normalIndex[0] = 0);
                normalIndex[0] = 0;
                for (; edgeIndex[0] < 4; edgeIndex[0]++, normalIndex[0] += 2)
                {
                    if (walkGroup->planeOffsets[edgeIndex[0]] +
                            (pointX * (f32)((s16*)walkGroup)[normalIndex[0]] +
                             pointZ * (f32)((s16*)walkGroup)[normalIndex[0] + 1]) >
                        0.0f)
                    {
                        break;
                    }
                }
                if (edgeIndex[0] == 4)
                {
                    gObjfsaLastWalkGroupIndex = upperGroupIndex;
                    return upperGroupIndex;
                }
            }
        }

        lowerGroupIndex--;
        if (lowerGroupIndex == -1)
        {
            lowerGroupIndex = OBJFSA_WALKGROUP_COUNT - 1;
        }
        upperGroupIndex++;
        if (upperGroupIndex == OBJFSA_WALKGROUP_COUNT)
        {
            upperGroupIndex = 0;
        }
    }

    if (gObjfsaWalkGroupActive[lowerGroupIndex])
    {
        finalGroup = &gObjfsaWalkGroups[lowerGroupIndex];
        walkGroup = finalGroup;
        pointY = point[1];
        if (pointY < walkGroup->maxY && pointY > walkGroup->minY)
        {
            pointZ = point[2];
            pointX = point[0];
            edgeIndex[0] = (normalIndex[0] = 0);
            normalIndex[0] = 0;
            for (; edgeIndex[0] < 4; edgeIndex[0]++, normalIndex[0] += 2)
            {
                planeOffset = walkGroup->planeOffsets[edgeIndex[0]];
                if (planeOffset +
                        (pointX * (f32)((s16*)walkGroup)[normalIndex[0]] +
                         (f32)((s16*)walkGroup)[normalIndex[0] + 1] * pointZ) >
                    0.0f)
                {
                    break;
                }
            }
            if (edgeIndex[0] == 4)
            {
                gObjfsaLastWalkGroupIndex = lowerGroupIndex;
                return lowerGroupIndex;
            }
        }
    }
    return 0;
}
inline f32 objfsaCorner(s8 ofs, f32 scl, f32* base)
{
    return (f32)((f32)ofs * scl + *base);
}

inline int objfsaExitOutside(ObjfsaWalkGroup* g, s16 ex, s16 ez)
{
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
    for (; edge < 4; edge++, normalIdx += 2)
    {
        if (g->planeOffsets[edge] +
                (exitFx * (f32)((s16*)g)[normalIdx] + exitFz * (f32)((s16*)g)[normalIdx + 1]) >
            zero)
        {
            break;
        }
    }
    return edge != 4;
}

static void objfsaSetPlaneNormal(ObjfsaPatchPlane* pl, f32 dxn, f32 dzn)
{
    pl->normalX = (s16)(32767.0f * dxn);
    pl->normalZ = (s16)(32767.0f * dzn);
}

void Objfsa_UpdateWalkGroupPatches(void)
{
    char* slotPtr;
    u8 blockFlags[0x78];
    u8 pairs[364];
    f32 z1;
    f32 x1;
    ObjfsaPatch* np;
    s8* edgeCoords;
    u8 groupB;
    ObjfsaPatch* p;
    int flagIndex;
    int found;
    int curveCount;
    ObjfsaPatch* patchBase[1];
    ObjfsaWalkCurveDef** listWalk;
    u8* pp;
    int listIndex;
    int back;
    int slot;
    ObjfsaWalkCurveDef* curve;
    ObjfsaWalkCurveDef* linked;
    int iter;
    int pi;
    u8 gi;
    u8 groupA;
    int pairId;
    u16 pairGid;
    u32 checksum;
    int searchCount;
    ObjfsaPatchPlane* pl;
    f32* po;
    ObjfsaPatch* pC;
    ObjfsaWalkCurveDef** curveList;
    ObjfsaPatch* sp;
    f32 fdx;
    f32 fdz;
    f32 div;
    f32 scale;
    f32 dxn;
    f32 dzn;
    f32 len;
    f32 x0;
    f32 z0;
    ObjfsaPatch* pB;
    f32 x2;
    f32 z2;
    f32 x3;
    f32 z3;
    f32 fy0;
    f32 fy1;
    s16 fyv;
    ObjfsaWalkGroup* wg;
    ObjfsaWalkGroup* wgT;
    ObjfsaWalkGroup* wgBT;
    s32* linkId;
    ObjfsaPatch* ep;
    patchBase[0] = gObjfsaPatches;
    mapGetLoadedMapFlags(blockFlags);

    checksum = 1;
    for (flagIndex = 0; flagIndex < 120; flagIndex++)
    {
        if (blockFlags[flagIndex] != 0)
        {
            checksum *= flagIndex;
        }
    }

    if (checksum != gObjfsaBlockFlagsChecksum)
    {
        gObjfsaBlockFlagsChecksum = checksum;
    }
    else
    {
        return;
    }

    {
        if (blockFlags[2] != 0 || blockFlags[0x34] != 0)
        {
            scale = 14.0f;
        }
        else
        {
            scale = 10.0f;
        }

        curveList = (ObjfsaWalkCurveDef**)(*gRomCurveInterface)->getCurves(&curveCount);
        memset(Objfsa_GetStorage(patchBase[0])->activeWalkGroups, 0, OBJFSA_WALKGROUP_COUNT);
        sp = patchBase[0];
        for (pi = 0; pi < 256; pi++)
        {
            sp->groupId = 0;
            sp++;
        }

        gObjfsaPatchCount = 1;
        for (listIndex = 0, listWalk = curveList; listIndex < curveCount; listIndex++)
        {
            curve = *listWalk;
            if (curve->type == 0x26)
            {
                gi = curve->walkGroup;
                wg = &((ObjfsaWalkGroup*)(patchBase[0] + 256))[gi];
                *(u8*)((gi + OBJFSA_ACTIVE_WALKGROUPS_OFFSET) + (int)patchBase[0]) = 1;

                x0 = objfsaCorner(curve->firstEdge[0], scale, &curve->x);
                z0 = objfsaCorner(curve->firstEdge[1], scale, &curve->z);
                x1 = objfsaCorner(curve->firstEdge[2], scale, &curve->x);
                z1 = objfsaCorner(curve->firstEdge[3], scale, &curve->z);

                dxn = z1 - z0;
                dzn = x0 - x1;
                OBJFSA_SET_PLANE(*wg, 0, x0, z0);

                x2 = objfsaCorner(curve->secondEdge[0], scale, &curve->x);
                z2 = objfsaCorner(curve->secondEdge[1], scale, &curve->z);
                dxn = z2 - z1;
                dzn = x1 - x2;
                OBJFSA_SET_PLANE(*wg, 1, x1, z1);

                x3 = objfsaCorner(curve->secondEdge[2], scale, &curve->x);
                z3 = objfsaCorner(curve->secondEdge[3], scale, &curve->z);
                dxn = z3 - z2;
                dzn = x2 - x3;
                OBJFSA_SET_PLANE(*wg, 2, x2, z2);

                dxn = objfsaCorner(curve->firstEdge[1], scale, &curve->z) - z3;
                dzn = x3 - objfsaCorner(curve->firstEdge[0], scale, &curve->x);
                OBJFSA_SET_PLANE(*wg, 3, x3, z3);

                wg->maxY = (s16)(2.0f * curve->maxYExtent + curve->y);
                wg->minY = (s16)-(2.0f * curve->minYExtent - curve->y);

                for (slot = 0, slotPtr = (char*)curve; slot < 4; slot++)
                {
                    wg->patchIndices[slot] = 0;
                    linkId = (s32*)(slotPtr + 0x1c);
                    if (*linkId > -1 &&
                        (linked = (ObjfsaWalkCurveDef*)(*gRomCurveInterface)->getById(*linkId)) != 0)
                    {
                        groupA = curve->walkGroup;
                        groupB = linked->walkGroup;
                        if (groupA < groupB)
                        {
                            pairId = groupA | (groupB << 8);
                        }
                        else
                        {
                            pairId = (groupA << 8) | groupB;
                        }

                        found = 1;
                        sp = &patchBase[0][1];
                        for (searchCount = 1; searchCount < gObjfsaPatchCount; searchCount++)
                        {
                            if (pairId == sp->groupId)
                            {
                                wg->patchIndices[slot] = (u8)found;
                                break;
                            }
                            sp++;
                            found++;
                        }

                        if (wg->patchIndices[slot] == 0)
                        {
                            back = 0;
                            if (curve->id != linked->linkIds[0] &&
                                (back = 1, curve->id != linked->linkIds[1]) &&
                                (back = 2, curve->id != linked->linkIds[2]) &&
                                (back = 3, curve->id != linked->linkIds[3]))
                            {
                                back = 4;
                            }
                            wg->patchIndices[slot] = gObjfsaPatchCount;
                            (np = &patchBase[0][gObjfsaPatchCount])->groupId = (pairGid = pairId);
                            pairs[gObjfsaPatchCount * 2] = curve->walkGroup;
                            pairs[gObjfsaPatchCount * 2 + 1] = linked->walkGroup;

                            edgeCoords = (s8*)(slotPtr + 0x34);
                            x0 = objfsaCorner(edgeCoords[0], scale, &curve->x);
                            z0 = objfsaCorner(edgeCoords[1], scale, &curve->z);
                            x1 = objfsaCorner(edgeCoords[2], scale, &curve->x);
                            z1 = objfsaCorner(edgeCoords[3], scale, &curve->z);
                            np->exit0X = (s16)((x0 + x1) / 2.0f);
                            np->exit0Z = (s16)((z0 + z1) / 2.0f);

                            OBJFSA_SET_NEWPATCH_PLANE(0, z1 - z0, x0 - x1, x0, z0);

                            edgeCoords = (s8*)linked + back * 4;
                            x2 = objfsaCorner(edgeCoords[0x34], scale, &linked->x);
                            z2 = objfsaCorner(edgeCoords[0x35], scale, &linked->z);
                            OBJFSA_SET_NEWPATCH_PLANE(1, z2 - z1, x1 - x2, x1, z1);

                            x3 = objfsaCorner(edgeCoords[0x36], scale, &linked->x);
                            z3 = objfsaCorner(edgeCoords[0x37], scale, &linked->z);
                            (ep = &OBJFSA_NEWPATCH)->exit1X = (s16)((x2 + x3) / 2.0f);
                            ep->exit1Z = (s16)((z2 + z3) / 2.0f);

                            OBJFSA_SET_NEWPATCH_PLANE(2, z3 - z2, x2 - x3, x2, z2);

                            edgeCoords = (s8*)(slotPtr + 0x34);
                            z0 = objfsaCorner(edgeCoords[1], scale, &curve->z);
                            x0 = objfsaCorner(edgeCoords[0], scale, &curve->x);
                            OBJFSA_SET_NEWPATCH_PLANE(3, z0 - z3, x3 - x0, x3, z3);

                            fy0 = 2.0f * curve->maxYExtent + curve->y;
                            fy1 = 2.0f * linked->maxYExtent + linked->y;
                            if (fy0 > fy1)
                            {
                                fyv = fy0;
                                OBJFSA_NEWPATCH_S16(maxY) = fyv;
                            }
                            else
                            {
                                fyv = fy1;
                                OBJFSA_NEWPATCH_S16(maxY) = fyv;
                            }
                            fy0 = -(2.0f * curve->minYExtent - curve->y);
                            fy1 = -(2.0f * linked->minYExtent - linked->y);
                            if (fy0 < fy1)
                            {
                                fyv = fy0;
                                OBJFSA_NEWPATCH_S16(minY) = fyv;
                            }
                            else
                            {
                                fyv = fy1;
                                OBJFSA_NEWPATCH_S16(minY) = fyv;
                            }
                            gObjfsaPatchCount++;
                        }
                    }
                    slotPtr += 4;
                }
            }
            listWalk++;
        }

        pi = 1;
        pp = &pairs[2];
        div = 20.0f;
        p = &patchBase[0][1];
        for (; pi < gObjfsaPatchCount; pp += 2, p++, pi++)
        {
            wgT = &((ObjfsaWalkGroup*)(patchBase[0] + 256))[pp[0]];
            wgBT = &((ObjfsaWalkGroup*)(patchBase[0] + 256))[pp[1]];
            fdx = p->exit1X - p->exit0X;
            fdz = p->exit1Z - p->exit0Z;

            iter = 0;
            pB = pC = p;
            while (objfsaExitOutside(wgT, pC->exit0X, pC->exit0Z) &&
                   objfsaExitOutside(wgBT, pC->exit0X, pC->exit0Z))
            {
                p->exit0X = (s16)(p->exit0X + fdx / div);
                p->exit0Z = (s16)(p->exit0Z + fdz / div);
                if (iter++ == 100)
                {
                    OSReport(sObjfsaMissingPatchExitPoint0, p->groupId & 0xff, p->groupId >> 8);
                    break;
                }
            }

            iter = 0;
            while (objfsaExitOutside(wgT, pC->exit1X, pC->exit1Z) &&
                   objfsaExitOutside(wgBT, pC->exit1X, pC->exit1Z))
            {
                pC->exit1X = (s16)(pB->exit1X - fdx / div);
                pC->exit1Z = (s16)(pC->exit1Z - fdz / div);
                if (iter++ == 100)
                {
                    OSReport(sObjfsaMissingPatchExitPoint1, pC->groupId & 0xff, pC->groupId >> 8);
                    break;
                }
            }
        }
    }
}
void doNothing_onTrickyFree(void)
{
}

void doNothing_onTrickyInit(void)
{
}

char sObjfsaFoundNewWalkGroupPatch[] = "Found new walk group patch from walkgroup %d\n";
char sObjfsaIsPointWithinPatchGroupError[] = "Error in isPointWithinPatchGroup\n";
char sObjfsaMissingPatchExitPoint0[] = "Unable to find exit point 0 on patch between walkgroup %d and %d\n";
char sObjfsaMissingPatchExitPoint1[] = "Unable to find exit point 1 on patch between walkgroup %d and %d\n";
