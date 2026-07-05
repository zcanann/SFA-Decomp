/*
 * DLL 0x14 - RomCurve navigation library + ObjFSA walk-group spatial query.
 *
 * Two related subsystems back AI pathing on this DLL's maps:
 *
 *  - RomCurve_ / curves_ : the curve network. romCurves[] holds the loaded
 *    curve defs (nRomCurves entries); curves register/unregister through
 *    curves_addCurveDef/curves_remove and are looked up by id, type, action
 *    or proximity. Walkers (RomCurveWalker) step along a curve, pick the next
 *    control point/linked curve (RomCurve_goNextPoint, RomCurve_func29, the
 *    getControlPointId_2A/2B link choosers) and clamp progress. Curve type
 *    and action filters select among candidate links; many queries pick a
 *    random eligible link via randomGetRange.
 *
 *  - Objfsa_*: a flat-2D patch / walk-group subdivision. A walk group and its
 *    patches each store four edge half-planes (normalX/normalZ + offset) plus
 *    a Y range; a point is "inside" when it sits below every plane and within
 *    the Y span. Objfsa_GetWalkGroupIndexAtPoint / Objfsa_GetPatchGroupIdAtPoint
 *    resolve which group/patch contains a world point, with a per-call cache
 *    of the last hit group index.
 *
 * The whole DLL is exposed to the rest of the game through gRomCurveInterface;
 * it owns no game objects of its own.
 */
#include "main/dll/objfsa_romcurve.h"
#include "main/dll/objfsa.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
extern void OSReport(const char* msg, ...);

/* RomCurveWalker now lives in main/dll/curve_walker.h (lifted per the
 * deref-cleanup wave; curves.h re-exports it). */

#include "main/dll/dll_0015_curves.h"
#include "main/objlib.h"
#include "main/gamebits.h"
#include "main/dll/modgfx.h"
#include "string.h"
#include "main/dll/dll_0014_unk.h"

RomCurveDef* romCurves[ROMCURVE_MAX_CURVES];
extern int objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, void* hit, int obj, int p7,
                              int p8, int p9, int p10);

extern f32 sqrtf(f32 x);
extern u32 countLeadingZeros();
extern void voxmaps_worldToGrid(f32* in, s16* out);
extern int voxmaps_traceLine(s16* start, s16* end, void* coordOut, u8* occOut, int skipFirst);
extern const f32 lbl_803E063C;
extern f32 lbl_803E0640;
extern f32 gFloatOne;
extern f32 lbl_803E05F0;
extern f32 lbl_803E0644;
extern int gObjfsaBlockFlagsChecksum;
extern int gObjfsaLastWalkGroupIndex;
extern int gObjfsaPatchCount;
extern char sObjfsaFoundNewWalkGroupPatch[];
extern char sObjfsaIsPointWithinPatchGroupError[];

#define OBJFSA_PATCHGROUP_PATCH_COUNT 4
#define OBJFSA_PATCHGROUP_STRIDE 0x28
#define OBJFSA_ACTIVE_WALKGROUPS_OFFSET 0x4C48
#define OBJFSA_WALKGROUP_COUNT 0xB5

typedef struct ObjfsaPatchPlane
{
    s16 normalX;
    s16 normalZ;
} ObjfsaPatchPlane;

typedef struct ObjfsaPatch
{
    ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
    f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
    s16 maxY;
    s16 minY;
    u16 groupId;
    s16 exit0X;
    s16 exit0Z;
    s16 exit1X;
    s16 exit1Z;
    u8 pad2E[2];
} ObjfsaPatch;

typedef struct ObjfsaWalkGroup
{
    ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
    f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
    s16 maxY;
    s16 minY;
    u8 patchIndices[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroup;

typedef struct ObjfsaWalkGroupPatchInfo
{
    u8 walkGroupIndex;
    u8 patchMask;
    u16 patchGroupIds[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroupPatchInfo;

ObjfsaPatch gObjfsaPatches[0x3000 / sizeof(ObjfsaPatch)];
ObjfsaWalkGroup gObjfsaWalkGroups[0x1C48 / sizeof(ObjfsaWalkGroup)];
u8 gObjfsaWalkGroupActive[0xB8];

#pragma scheduling on
#pragma peephole on

extern f32 lbl_803E05C8;
extern f32 lbl_803E05CC;
extern f32 lbl_803E05F4;
extern f32 lbl_803E05D0;
extern f32 gRomCurveAnglePi;
extern f32 lbl_803E05D8;
extern f32 lbl_803E0610;
extern f32 gRomCurveAnglePi2;
extern f32 lbl_803E0618;
extern void Curve_BuildHermiteCoeffs(void);
extern f32 Curve_EvalHermite(f32 t, f32* values, f32* outTangent);
extern void curvesMove(float* state);
extern void curvesSetupMoveNetworkCurve(float* state);
extern f32 gFloatZero;
extern f32 gFloatNegOne;
extern f32 lbl_803E0648;
extern f32 lbl_803E064C;
extern f32 lbl_803E0650;
extern f32 lbl_803E0654;
extern f32 gObjfsaNearestDistInit;
extern f32 lbl_803E0600;
extern f32 lbl_803E0604;
extern f32 gObjfsaPlaneNormalScale;
extern f32 lbl_803E0608;
extern f32 lbl_803E060C;
extern char sObjfsaMissingPatchExitPoint0[];
extern char sObjfsaMissingPatchExitPoint1[];
extern f32 vec3f_distanceSquared(f32 * posA, f32 * posB);
extern f32 gFloatHalf;
extern f32 lbl_803E065C;
extern f32 lbl_803E0660;
extern const f32 gRomCurveFindDistInit;

static inline ObjfsaPatch* Objfsa_GetPatch(int patchIndex)
{
    return &gObjfsaPatches[patchIndex];
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
        if (patch->planeOffsets[edgeIndex] +
            point[0] * patch->planes[edgeIndex].normalX +
            point[2] * patch->planes[edgeIndex].normalZ >
            lbl_803E05F0)
        {
            return 0;
        }
    }
    return 1;
}

static inline int Objfsa_IsPointInsideWalkGroup(const float* point,
                                                const ObjfsaWalkGroup* walkGroup)
{
    int edgeIndex;

    if (point[1] >= walkGroup->maxY || walkGroup->minY >= point[1])
    {
        return 0;
    }

    for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++)
    {
        if (walkGroup->planeOffsets[edgeIndex] +
            point[0] * walkGroup->planes[edgeIndex].normalX +
            point[2] * walkGroup->planes[edgeIndex].normalZ >
            lbl_803E05F0)
        {
            return 0;
        }
    }
    return 1;
}

static inline u16 Objfsa_GetLinkedWalkGroup(u16 patchGroupId, u32 currentWalkGroupIndex)
{
    if (((countLeadingZeros(0xff - currentWalkGroupIndex) >> 5) & patchGroupId) != 0)
    {
        return (patchGroupId & 0xff00) >> 8;
    }
    return patchGroupId & 0xff;
}

#pragma opt_loop_invariants off
#pragma scheduling off
int curves_findNearObj(int obj, int* curveTypes, int typeCount, int action, char bboxMode)
{
    int curveIndex;
    ObjfsaRomCurveDef* curve;
    ObjfsaRomCurveDef* bestCurve;
    ObjfsaRomCurveDef* bestActionCurve;
    f32 bestDistance;
    f32 bestActionDistance;
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
    u64 objPos;

    bestDistance = lbl_803E063C;
    bestCurve = NULL;
    bestActionDistance = bestDistance;
    bestActionCurve = NULL;

    objPos = obj + 0xc;
    curvePos[0] = *(f32*)objPos;
    curvePos[1] = lbl_803E0640 + *(f32*)(obj + 0x10);
    curvePos[2] = *(f32*)(obj + 0x14);
    voxmaps_worldToGrid(curvePos, objGrid);

    for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++)
    {
        curve = (ObjfsaRomCurveDef*)romCurves[curveIndex];
        typeIndex = 0;
        do
        {
            if ((curve->type == curveTypes[typeIndex]) || (typeCount <= 0))
            {
                dx = curve->x - ((GameObject*)obj)->anim.localPosX;
                dy = curve->y - ((GameObject*)obj)->anim.localPosY;
                dz = curve->z - ((GameObject*)obj)->anim.localPosZ;
                distance = sqrtf(dz * dz + (dx * dx + dy * dy));
                if (distance < bestDistance)
                {
                    curvePos[0] = curve->x;
                    curvePos[1] = lbl_803E0640 + curve->y;
                    curvePos[2] = curve->z;
                    voxmaps_worldToGrid(curvePos, curveGrid);
                    traceResult = voxmaps_traceLine(curveGrid, objGrid, NULL, &traceHit, 0);
                    if (((traceHit == 1) || (traceResult != 0)) &&
                        (objBboxFn_800640cc((f32*)(obj + 0xc), curvePos, gFloatOne, 0, bboxHit, obj,
                                            bboxMode, -1, 0, 0) == 0))
                    {
                        bestDistance = distance;
                        bestCurve = curve;
                    }
                }
                if ((curve->action == action) && (distance < bestActionDistance))
                {
                    curvePos[0] = curve->x;
                    curvePos[1] = lbl_803E0640 + curve->y;
                    curvePos[2] = curve->z;
                    voxmaps_worldToGrid(curvePos, curveGrid);
                    traceResult = voxmaps_traceLine(curveGrid, objGrid, NULL, &traceHit, 0);
                    if (((traceHit == 1) || (traceResult != 0)) &&
                        (objBboxFn_800640cc((f32*)(obj + 0xc), curvePos, gFloatOne, 0, bboxHit, obj,
                                            bboxMode, -1, 0, 0) == 0))
                    {
                        bestActionDistance = distance;
                        bestActionCurve = curve;
                    }
                }
                typeIndex = typeCount;
            }
            typeIndex++;
        }
        while (typeIndex < typeCount);
    }
    if (bestActionCurve != NULL)
    {
        bestCurve = bestActionCurve;
    }
    if (bestCurve != NULL)
    {
        return bestCurve->id;
    }
    return -1;
}

#pragma opt_loop_invariants reset
#pragma scheduling on
static inline int Objfsa_FindRomCurveById(int curveId)
{
    int curve;
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
        curve = (int)romCurves[mid];
        if (id > ((ObjfsaRomCurveDef*)curve)->id)
        {
            lo = mid + 1;
        }
        else if (id < ((ObjfsaRomCurveDef*)curve)->id)
        {
            hi = mid - 1;
        }
        else
        {
            return curve;
        }
    }

    return 0;
}

#pragma scheduling off
#pragma peephole off
static inline int Objfsa_RomCurveIsBlocked(int curve)
{
    int slot;
    ObjfsaRomCurveDef* c = (ObjfsaRomCurveDef*)curve;

    for (slot = 0; slot < 4; slot++)
    {
        if (c->linkIds[slot] != -1 &&
            (c->blockedLinkMask & (1 << slot)) == 0)
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
    int i;

    count = 0;
    mask = 1;
    for (i = 0; i < ROMCURVE_LINK_COUNT; i++)
    {
        link = curve->linkIds[i];
        if ((-1 < link) && ((curve->blockedLinkMask & mask) == 0) && (link != 0))
        {
            ids[count++] = link;
        }
        mask = mask << 1;
    }
    return count;
}

f32 curves_lengthFn24(u32 a, u32 b, f32* posA, f32* posB, f32 t1, f32 t2)
{
    int cand1[4];
    int cand2[4];
    int cand3[4];
    int done;
    int slot;
    u32 mask;
    f32 total;
    int count;
    int next;
    u32 cur;
    int n;
    int reachedForward;
    int blocked;
    int found;
    int k;
    int nextId;
    f32 dx;
    f32 dy;
    f32 dz;
    f32* tmpPos;

    if (a == b)
    {
        dx = posB[0] - posA[0];
        dy = posB[1] - posA[1];
        dz = posB[2] - posA[2];
        total = sqrtf(dx * dx + dy * dy + dz * dz);
        if (t2 < t1)
        {
            total = -total;
        }
        goto done_exit;
    }

    reachedForward = 0;
    done = 0;
    found = a;
    while (done == 0)
    {
        blocked = Objfsa_RomCurveIsBlocked(found);
        if (blocked != 0)
        {
            done = 1;
            reachedForward = 0;
        }
        else
        {
            count = RomCurve_CollectUnblockedLinks((RomCurveDef*)found, cand1);
            if (count != 0)
            {
                nextId = cand1[randomGetRange(0, count - 1)];
            }
            else
            {
                nextId = -1;
            }
            found = Objfsa_FindRomCurveById(nextId);
            if (found == b)
            {
                done = 1;
                reachedForward = 1;
            }
        }
    }

    if (reachedForward == 0)
    {
        cur = a;
        a = b;
        b = cur;
        tmpPos = posA;
        posA = posB;
        posB = tmpPos;
    }

    count = RomCurve_CollectUnblockedLinks((RomCurveDef*)a, cand2);
    if (count != 0)
    {
        nextId = cand2[randomGetRange(0, count - 1)];
    }
    else
    {
        nextId = -1;
    }
    found = Objfsa_FindRomCurveById(nextId);
    a = found;
    dx = ((ObjfsaRomCurveDef*)found)->x - posA[0];
    dy = ((ObjfsaRomCurveDef*)found)->y - posA[1];
    dz = ((ObjfsaRomCurveDef*)found)->z - posA[2];
    total = sqrtf(dx * dx + dy * dy + dz * dz);
    done = 0;

    while (done == 0)
    {
        if (a == b)
        {
            done = 1;
            dx = posB[0] - ((ObjfsaRomCurveDef*)a)->x;
            dy = posB[1] - ((ObjfsaRomCurveDef*)a)->y;
            dz = posB[2] - ((ObjfsaRomCurveDef*)a)->z;
            total = total + sqrtf(dx * dx + dy * dy + dz * dz);
        }
        else
        {
            count = RomCurve_CollectUnblockedLinks((RomCurveDef*)a, cand3);
            if (count != 0)
            {
                nextId = cand3[randomGetRange(0, count - 1)];
            }
            else
            {
                nextId = -1;
            }
            next = Objfsa_FindRomCurveById(nextId);
            dx = ((ObjfsaRomCurveDef*)next)->x - ((ObjfsaRomCurveDef*)a)->x;
            dy = ((ObjfsaRomCurveDef*)next)->y - ((ObjfsaRomCurveDef*)a)->y;
            dz = ((ObjfsaRomCurveDef*)next)->z - ((ObjfsaRomCurveDef*)a)->z;
            total = total + sqrtf(dx * dx + dy * dy + dz * dz);
            a = next;
        }
    }

    if (reachedForward == 0)
    {
        total = -total;
    }
done_exit:
    return total;
}

#pragma opt_loop_invariants off
int walkGroupFn_800db3e4(float* prevPoint, float* nextPoint, u32 currentWalkGroupIndex)
{
    u8 k;
    u8* lwg;
    ObjfsaWalkGroup* wg;
    u32 lpidx;
    u32 clz;
    u16 lidx;
    u16 pgid;
    u8 i;
    u8 j;
    u8 m;
    u32 pidx;
    u8 k2;
    ObjfsaPatch* patch;
    ObjfsaPatch* lp;
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
                    (prevPoint[0] * (f32)((s16*)patch)[j] +
                        prevPoint[2] * (f32)((s16*)patch)[j + 1]) >
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
                            (nextPoint[0] * (f32)((s16*)patch)[j] +
                                nextPoint[2] * (f32)((s16*)patch)[j + 1]) >
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
        clz = (u32)__cntlzw(0xff - currentWalkGroupIndex) >> 5;
        pgid = gObjfsaPatches[pidx].groupId;
        if (((int)clz & pgid) != 0)
        {
            lidx = (int)(pgid & 0xff00) >> 8;
        }
        else
        {
            lidx = pgid & 0xff;
        }
        for (k2 = 0, lwg = (u8*)gObjfsaWalkGroups + lidx * OBJFSA_PATCHGROUP_STRIDE; k2 < 4; k2++)
        {
            lpidx = lwg[k2 + 0x24];
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
                            (prevPoint[0] * (f32)((s16*)lp)[j] +
                                prevPoint[2] * (f32)((s16*)lp)[j + 1]) >
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
                                    (nextPoint[0] * (f32)((s16*)lp)[j] +
                                        nextPoint[2] * (f32)((s16*)lp)[j + 1]) >
                                    0.0f)
                                {
                                    break;
                                }
                            }
                            if (i == 4)
                            {
                                OSReport(sObjfsaFoundNewWalkGroupPatch, lidx);
                                return lidx;
                            }
                        }
                    }
                }
            }
        }
    }

    return 0;
}
#pragma opt_loop_invariants reset

u32 isPointWithinPatchGroup(float* point, u32 patchGroupIndex, int groupId)
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
                            (point[0] * (f32)((s16*)patch)[j] +
                                point[2] * (f32)((s16*)patch)[j + 1]) >
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
        pidx = *(u8*)(wg + k + 0x24);
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
                if (patch->planeOffsets[i] +
                    (point[0] * (f32)((s16*)patch)[j] +
                        point[2] * (f32)((s16*)patch)[j + 1]) >
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

#pragma peephole on
u32 isInWalkGroupOrPatch(float* point)
{
    s16* nz;
    s16* nx;
    char* offs;
    ObjfsaPatch* patch;
    int count;
    s16 i;
    s16 idx;
    f32 y;

    if (mathFn_800dbff0(point) != 0)
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
                if (*(f32*)(offs + 0x10) +
                    (point[0] * nx[0] + point[2] * nz[1]) >
                    0.0f)
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

#pragma peephole off
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

    wgi = (u8)mathFn_800dbff0(point);
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
                            (point[0] * (f32)((s16*)patch)[j] +
                                point[2] * (f32)((s16*)patch)[j + 1]) >
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

u16 Objfsa_GetPatchGroupIdAtPoint(float* point)
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
            u8 i;
            u8 j;
            z = point[2];
            x = point[0];
            j = i = 0;
            for (; i < 4; i++, j += 2)
            {
                if (patch->planeOffsets[i] +
                    (x * (f32)((s16*)patch)[j] + z * (f32)((s16*)patch)[j + 1]) >
                    0.0f)
                {
                    break;
                }
            }
            if (i == 4)
            {
                return patch->groupId;
            }
        }
    }
    return 0;
}

#define WALKGROUP_TRY_RETURN(idx)                                                  \
    if (Objfsa_IsWalkGroupActive(idx)) {                                           \
        g = &gObjfsaWalkGroups[idx];                                                    \
        y = point[1];                                                              \
        if (y < g->maxY && y > g->minY) {                                \
            x = point[0];                                                          \
            z = point[2];                                                          \
            i = 0;                                                                 \
            j = i;                                                                 \
            for (; i < 4; i++, j += 2) {                                           \
                if (g->planeOffsets[i] +                                           \
                        (x * (f32)((s16 *)g)[j] + z * (f32)((s16 *)g)[j + 1]) >    \
                    0.0f) {                                                        \
                    break;                                                         \
                }                                                                  \
            }                                                                      \
            if (i == 4) {                                                          \
                gObjfsaLastWalkGroupIndex = (idx);                                              \
                return (idx);                                                      \
            }                                                                      \
        }                                                                          \
    }

#pragma opt_common_subs off
int mathFn_800dbff0(float* point)
{
    s16 up;
    s16 down;
    u8 j;
    u8 i;
    ObjfsaWalkGroup* g;
    f32 y;
    f32 x;
    f32 z;

    down = gObjfsaLastWalkGroupIndex;
    if (gObjfsaLastWalkGroupIndex == OBJFSA_WALKGROUP_COUNT - 1)
    {
        up = 0;
    }
    else
    {
        up = gObjfsaLastWalkGroupIndex + 1;
    }

    while (down != up)
    {
        WALKGROUP_TRY_RETURN(down);
        WALKGROUP_TRY_RETURN(up);

        down--;
        if (down == -1)
        {
            down = OBJFSA_WALKGROUP_COUNT - 1;
        }
        up++;
        if (up == OBJFSA_WALKGROUP_COUNT)
        {
            up = 0;
        }
    }

    WALKGROUP_TRY_RETURN(down);
    return 0;
}
#pragma opt_common_subs on

#pragma scheduling on
#pragma peephole on
void doNothing_onTrickyFree(void)
{
}

void doNothing_onTrickyInit(void)
{
}

#pragma scheduling off
#pragma peephole off
int fn_800D9F38(void* a, void* b)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    char* A = a;
    char* B = b;
    if (*(u32*)(A + 0xa0) == 0 || *(u32*)(A + 0xa4) == 0 || b == 0) return 1;
    *(void**)(A + 0xa4) = b;
    if (*(int*)(A + 0x80) != 0)
    {
        f32 t;
        *(f32*)(A + 0xa8) = *(f32*)(B + 0x8);
        t = (float)(u32) * (u8*)(B + 0x2e) *
            mathSinf(gRomCurveAnglePi * (float)((s32)((s8) * (B + 0x2c)) << 8) / lbl_803E05D8);
        *(f32*)(A + 0xb0) = lbl_803E05D0 * t;
        *(f32*)(A + 0xc8) = *(f32*)(B + 0xc);
        t = (float)(u32) * (u8*)(B + 0x2e) *
            mathSinf(gRomCurveAnglePi * (float)((s32)((s8) * (B + 0x2d)) << 8) / lbl_803E05D8);
        *(f32*)(A + 0xd0) = lbl_803E05D0 * t;
        *(f32*)(A + 0xe8) = *(f32*)(B + 0x10);
        t = (float)(u32) * (u8*)(B + 0x2e) *
            mathCosf(gRomCurveAnglePi * (float)((s32)((s8) * (B + 0x2c)) << 8) / lbl_803E05D8);
        *(f32*)(A + 0xf0) = lbl_803E05D0 * t;
    }
    else
    {
        f32 t;
        *(f32*)(A + 0xbc) = *(f32*)(B + 0x8);
        t = (float)(u32) * (u8*)(B + 0x2e) *
            mathSinf(gRomCurveAnglePi * (float)((s32)((s8) * (B + 0x2c)) << 8) / lbl_803E05D8);
        *(f32*)(A + 0xc4) = lbl_803E05D0 * t;
        *(f32*)(A + 0xdc) = *(f32*)(B + 0xc);
        t = (float)(u32) * (u8*)(B + 0x2e) *
            mathSinf(gRomCurveAnglePi * (float)((s32)((s8) * (B + 0x2d)) << 8) / lbl_803E05D8);
        *(f32*)(A + 0xe4) = lbl_803E05D0 * t;
        *(f32*)(A + 0xfc) = *(f32*)(B + 0x10);
        t = (float)(u32) * (u8*)(B + 0x2e) *
            mathCosf(gRomCurveAnglePi * (float)((s32)((s8) * (B + 0x2c)) << 8) / lbl_803E05D8);
        *(f32*)(A + 0x104) = lbl_803E05D0 * t;
    }
    return 0;
}

void RomCurve_setA4(void* a, void* b)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    char* A = a;
    f32 t;
    if (b != 0 && (u32)b != *(u32*)(A + 0xa4))
    {
        *(void**)(A + 0xa4) = b;
        *(f32*)(A + 0xbc) = *(f32*)((*(char**)(A + 0xa4)) + 0x8);
        t = (float)(u32) * (u8*)((*(char**)(A + 0xa4)) + 0x2e) *
            mathSinf(gRomCurveAnglePi2 * (float)((s32)((s8) * ((*(char**)(A + 0xa4)) + 0x2c)) << 8) / lbl_803E0618);
        *(f32*)(A + 0xc4) = lbl_803E0610 * t;
        *(f32*)(A + 0xdc) = *(f32*)((*(char**)(A + 0xa4)) + 0xc);
        t = (float)(u32) * (u8*)((*(char**)(A + 0xa4)) + 0x2e) *
            mathSinf(gRomCurveAnglePi2 * (float)((s32)((s8) * ((*(char**)(A + 0xa4)) + 0x2d)) << 8) / lbl_803E0618);
        *(f32*)(A + 0xe4) = lbl_803E0610 * t;
        *(f32*)(A + 0xfc) = *(f32*)((*(char**)(A + 0xa4)) + 0x10);
        t = (float)(u32) * (u8*)((*(char**)(A + 0xa4)) + 0x2e) *
            mathCosf(gRomCurveAnglePi2 * (float)((s32)((s8) * ((*(char**)(A + 0xa4)) + 0x2c)) << 8) / lbl_803E0618);
        *(f32*)(A + 0x104) = lbl_803E0610 * t;
    }
}

int RomCurve_setClosed(RomCurveWalker* state, int closed)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    float savedPhase;
    float t;
    void* tmpCurve;

    if (closed == state->reverse)
    {
        return 0;
    }
    if (state->nodeA0 == 0 || state->node9C == 0)
    {
        return 1;
    }

    savedPhase = state->phase;
    state->reverse = closed;
    tmpCurve = state->node9C;
    state->node9C = state->nodeA4;
    state->nodeA4 = tmpCurve;

    state->hermX2[0] = *(f32*)((char*)state->nodeA0 + 0x8);
    state->hermX2[1] = *(f32*)((char*)state->nodeA4 + 0x8);
    t = (float)(u32) * (u8*)((char*)state->nodeA0 + 0x2e) *
        mathSinf(gRomCurveAnglePi2 *
            (float)((s32)((s8) * ((char*)state->nodeA0 + 0x2c)) << 8) /
            lbl_803E0618);
    state->hermX2[2] = lbl_803E0610 * t;
    t = (float)(u32) * (u8*)((char*)state->nodeA4 + 0x2e) *
        mathSinf(gRomCurveAnglePi2 *
            (float)((s32)((s8) * ((char*)state->nodeA4 + 0x2c)) << 8) /
            lbl_803E0618);
    state->hermX2[3] = lbl_803E0610 * t;

    state->hermY2[0] = *(f32*)((char*)state->nodeA0 + 0xc);
    state->hermY2[1] = *(f32*)((char*)state->nodeA4 + 0xc);
    t = (float)(u32) * (u8*)((char*)state->nodeA0 + 0x2e) *
        mathSinf(gRomCurveAnglePi2 *
            (float)((s32)((s8) * ((char*)state->nodeA0 + 0x2d)) << 8) /
            lbl_803E0618);
    state->hermY2[2] = lbl_803E0610 * t;
    t = (float)(u32) * (u8*)((char*)state->nodeA4 + 0x2e) *
        mathSinf(gRomCurveAnglePi2 *
            (float)((s32)((s8) * ((char*)state->nodeA4 + 0x2d)) << 8) /
            lbl_803E0618);
    state->hermY2[3] = lbl_803E0610 * t;

    state->hermZ2[0] = *(f32*)((char*)state->nodeA0 + 0x10);
    state->hermZ2[1] = *(f32*)((char*)state->nodeA4 + 0x10);
    t = (float)(u32) * (u8*)((char*)state->nodeA0 + 0x2e) *
        mathCosf(gRomCurveAnglePi2 *
            (float)((s32)((s8) * ((char*)state->nodeA0 + 0x2c)) << 8) / lbl_803E0618);
    state->hermZ2[2] = lbl_803E0610 * t;
    t = (float)(u32) * (u8*)((char*)state->nodeA4 + 0x2e) *
        mathCosf(gRomCurveAnglePi2 *
            (float)((s32)((s8) * ((char*)state->nodeA4 + 0x2c)) << 8) / lbl_803E0618);
    state->hermZ2[3] = lbl_803E0610 * t;

    if (RomCurve_goNextPoint(state) != 0)
    {
        return 1;
    }

    state->node94 = Curve_EvalHermite;
    state->node98 = Curve_BuildHermiteCoeffs;
    state->coeffX = state->hermX;
    state->coeffY = state->hermY;
    state->coeffZ = state->hermZ;
    state->moveNetwork = 8;
    curvesMove((float*)state);
    state->phase = savedPhase;
    return 0;
}

#define ROMCURVE_REFRESH_CONTROL(secondOff)                                       \
    *(f32 *)(stateBytes + 0xb8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0x8);    \
    *(f32 *)(stateBytes + 0xbc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0x8); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathSinf(gRomCurveAnglePi2 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2c) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xc0) = lbl_803E0610 * t;                               \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathSinf(gRomCurveAnglePi2 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2c) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xc4) = lbl_803E0610 * t;                               \
    *(f32 *)(stateBytes + 0xd8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0xc);    \
    *(f32 *)(stateBytes + 0xdc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0xc); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathSinf(gRomCurveAnglePi2 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2d) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xe0) = lbl_803E0610 * t;                               \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathSinf(gRomCurveAnglePi2 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2d) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xe4) = lbl_803E0610 * t;                               \
    *(f32 *)(stateBytes + 0xf8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0x10);   \
    *(f32 *)(stateBytes + 0xfc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0x10); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathCosf(gRomCurveAnglePi2 *                                                        \
            (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2c) << 8) / lbl_803E0618); \
    *(f32 *)(stateBytes + 0x100) = lbl_803E0610 * t;                              \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathCosf(gRomCurveAnglePi2 *                                                        \
            (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2c) << 8) / \
            lbl_803E0618);                                                        \
    *(f32 *)(stateBytes + 0x104) = lbl_803E0610 * t

u8 RomCurve_goNextPoint(RomCurveWalker* state)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    char* stateBytes;
    int low;
    int high;
    int mid;
    int neighborId;
    int nextCurve;
    float t;

    if (state == NULL)
    {
        return 1;
    }
    stateBytes = (char*)state;
    if (state->nodeA0 == NULL || state->nodeA4 == NULL)
    {
        return 1;
    }

    state->node9C = state->nodeA0;
    state->nodeA0 = state->nodeA4;
    memcpy(stateBytes + 0xa8, stateBytes + 0xb8, 0x10);
    memcpy(stateBytes + 0xc8, stateBytes + 0xd8, 0x10);
    memcpy(stateBytes + 0xe8, stateBytes + 0xf8, 0x10);

    if (state->reverse != 0)
    {
        int candA[4];
        u32 mask;
        int countA;
        int curveA;
        int nid;
        curveA = *(s32*)&state->nodeA0;
        countA = 0;
        mask = 1;
        for (low = 0; low < 4; low++, mask <<= 1)
        {
            nid = *(s32*)(curveA + 0x1c + low * 4);
            if (nid > -1 && (*(s8*)(curveA + 0x1b) & mask) != 0 && nid != -1)
            {
                candA[countA++] = nid;
            }
        }
        neighborId = countA != 0 ? candA[randomGetRange(0, countA - 1)] : -1;
    }
    else
    {
        int candB[4];
        u32 mask;
        int countB;
        int curveB;
        int nid;
        curveB = *(s32*)&state->nodeA0;
        countB = 0;
        mask = 1;
        for (low = 0; low < 4; low++, mask <<= 1)
        {
            nid = *(s32*)(curveB + 0x1c + low * 4);
            if (nid > -1 && (*(s8*)(curveB + 0x1b) & mask) == 0 && nid != -1)
            {
                candB[countB++] = nid;
            }
        }
        neighborId = countB != 0 ? candB[randomGetRange(0, countB - 1)] : -1;
    }

    if (neighborId == -1)
    {
        goto clearAndReturn;
    }

    if (neighborId < 0)
    {
        nextCurve = 0;
    }
    else
    {
        low = 0;
        high = nRomCurves - 1;
        while (high >= low)
        {
            mid = (high + low) >> 1;
            if ((u32)neighborId > ((ObjfsaRomCurveDef*)(s32)romCurves[mid])->id)
            {
                low = mid + 1;
            }
            else if ((u32)neighborId < ((ObjfsaRomCurveDef*)(s32)romCurves[mid])->id)
            {
                high = mid - 1;
            }
            else
            {
                nextCurve = (s32)romCurves[mid];
                goto found;
            }
        }
        nextCurve = 0;
    found:;
    }

    *(s32*)&state->nodeA4 = nextCurve;
    if (state->nodeA4 == NULL)
    {
        goto clearAndReturn;
    }

    if (state->reverse != 0)
    {
        ROMCURVE_REFRESH_CONTROL(0x9c);
    }
    else
    {
        ROMCURVE_REFRESH_CONTROL(0xa4);
    }

    if (state->moveNetwork != 0)
    {
        curvesSetupMoveNetworkCurve((float*)state);
    }
    if (state->reverse != 0)
    {
        ((void (*)(float*, double))Curve_AdvanceAlongPath)((float*)state, gFloatNegOne);
    }
    else
    {
        ((void (*)(float*, double))Curve_AdvanceAlongPath)((float*)state, gFloatOne);
    }
    return 0;
clearAndReturn:
    state->nodeA4 = NULL;
    return 1;
}

#pragma scheduling on
#pragma peephole on
static inline f32 RomCurveNode_GetHermiteTangent(void** nodePtr, int angleOffset, int useCos)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    f32 angle;
    f32 trig;

    angle = gRomCurveAnglePi * (f32)((s32) * (s8*)((char*)*nodePtr + angleOffset) << 8) / lbl_803E05D8;
    if (useCos)
    {
        trig = mathCosf(angle);
    }
    else
    {
        trig = mathSinf(angle);
    }
    trig = (f32)(u32) * (u8*)((char*)*nodePtr + 0x2e) * trig;
    return lbl_803E05D0 * trig;
}

int RomCurve_getControlPointId_2A(int curve, int exclude, int pickIdx);
int RomCurve_getControlPointId_2B(int curve, int exclude, int pickIdx);

static inline int RomCurve_pickRandomControlPointId_2A(int curve)
{
    int neighbor;
    int count;
    u32 mask;
    int i;
    int result;
    int candidates[4];

    count = 0;
    mask = 1;
    for (i = 0; i < 4; i = i + 1)
    {
        neighbor = ((RomCurveDef*)curve)->linkIds[i];
        if ((-1 < neighbor) && ((((RomCurveDef*)curve)->blockedLinkMask & mask) == 0) && (neighbor != -1))
        {
            candidates[count++] = neighbor;
        }
        mask = mask << 1;
    }
    if (count != 0)
    {
        result = candidates[randomGetRange(0, count - 1)];
    }
    else
    {
        result = -1;
    }
    return result;
}

static inline int RomCurve_pickRandomControlPointId_2B(int curve)
{
    int neighbor;
    int count;
    u32 mask;
    int i;
    int result;
    int candidates[4];

    count = 0;
    mask = 1;
    for (i = 0; i < 4; i = i + 1)
    {
        neighbor = ((RomCurveDef*)curve)->linkIds[i];
        if ((-1 < neighbor) && ((((RomCurveDef*)curve)->blockedLinkMask & mask) != 0) && (neighbor != -1))
        {
            candidates[count++] = neighbor;
        }
        mask = mask << 1;
    }
    if (count != 0)
    {
        result = candidates[randomGetRange(0, count - 1)];
    }
    else
    {
        result = -1;
    }
    return result;
}

#pragma scheduling off
#pragma peephole off
int RomCurve_func29(RomCurveWalker* state, int pickIdx)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    char* stateBytes;
    int nextId;
    int nextCurve;
    f32 t;

    if (state == NULL)
    {
        return 1;
    }

    stateBytes = (char*)state;
    if (state->nodeA0 == NULL || state->nodeA4 == NULL)
    {
        return 1;
    }

    state->node9C = state->nodeA0;
    state->nodeA0 = state->nodeA4;
    memcpy(stateBytes + 0xa8, stateBytes + 0xb8, 0x10);
    memcpy(stateBytes + 0xc8, stateBytes + 0xd8, 0x10);
    memcpy(stateBytes + 0xe8, stateBytes + 0xf8, 0x10);

    if (state->reverse != 0)
    {
        nextId = RomCurve_getControlPointId_2B(*(s32*)&state->nodeA0, -1, pickIdx);
    }
    else
    {
        nextId = RomCurve_getControlPointId_2A(*(s32*)&state->nodeA0, -1, pickIdx);
    }

    if (nextId == -1)
    {
        goto failClear;
    }

    nextCurve = Objfsa_FindRomCurveById(nextId);
    *(s32*)&state->nodeA4 = nextCurve;
    if (state->nodeA4 == NULL)
    {
        goto fail;
    }

    if (state->reverse != 0)
    {
        ROMCURVE_REFRESH_CONTROL(0x9c);
    }
    else
    {
        ROMCURVE_REFRESH_CONTROL(0xa4);
    }

    if (state->moveNetwork != 0)
    {
        curvesSetupMoveNetworkCurve((float*)state);
    }

    if (state->reverse != 0)
    {
        ((void (*)(float*, double))Curve_AdvanceAlongPath)((float*)state, gFloatNegOne);
    }
    else
    {
        ((void (*)(float*, double))Curve_AdvanceAlongPath)((float*)state, gFloatOne);
    }

    return 0;

failClear:
    state->nodeA4 = NULL;
fail:
    return 1;
}

int RomCurve_getControlPointId_2A(int curve, int exclude, int pickIdx)
{
    int candidates[4];
    int neighbor;
    int count = 0;
    u32 mask = 1;
    int i;
    for (i = 0; i < 4; i++)
    {
        neighbor = ((ObjfsaRomCurveDef*)curve)->linkIds[i];
        if (neighbor > -1 && ((s32)((ObjfsaRomCurveDef*)curve)->blockedLinkMask & mask) == 0 && neighbor != exclude)
        {
            candidates[count++] = neighbor;
        }
        mask <<= 1;
    }
    if (count != 0)
    {
        if (pickIdx > count - 1) pickIdx = count - 1;
        if (pickIdx == -1)
        {
            pickIdx = randomGetRange(0, count - 1);
        }
        return candidates[pickIdx];
    }
    return -1;
}

int RomCurve_getControlPointId_2B(int curve, int exclude, int pickIdx)
{
    int candidates[4];
    int neighbor;
    int count = 0;
    u32 mask = 1;
    int i;
    for (i = 0; i < 4; i++)
    {
        neighbor = ((ObjfsaRomCurveDef*)curve)->linkIds[i];
        if (neighbor > -1 && ((s32)((ObjfsaRomCurveDef*)curve)->blockedLinkMask & mask) != 0 && neighbor != exclude)
        {
            candidates[count++] = neighbor;
        }
        mask <<= 1;
    }
    if (count != 0)
    {
        if (pickIdx > count - 1) pickIdx = count - 1;
        if (pickIdx == -1)
        {
            pickIdx = randomGetRange(0, count - 1);
        }
        return candidates[pickIdx];
    }
    return -1;
}

int RomCurve_findProjectedCurveFromStart(int curve, f32 x, f32 y, f32 z, float* outPhase)
{
    extern u32 RomCurve_getAdjacentWindow(); /* #57 */
    extern int RomCurve_projectPointToAdjacentWindow(); /* #57 */
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

    goto loopTest;
    do
    {
        RomCurve_getAdjacentWindow(curve, adjacentWindow);
        projected = RomCurve_projectPointToAdjacentWindow(adjacentWindow, x, y, z,
                                                          &lateralOffset, &verticalOffset, &phase);
        if (projected != 0 && lateralOffset > lbl_803E0648 && lateralOffset < lbl_803E064C &&
            verticalOffset > lbl_803E0650 && verticalOffset < lbl_803E0654)
        {
            *outPhase = phase;
            return curve;
        }

        count[0] = 0;
        mask[0] = 1;
        for (k = 0; k < 4; k++)
        {
            n = ((ObjfsaRomCurveDef*)curve)->linkIds[k];
            if (n > -1 && ((s8)((ObjfsaRomCurveDef*)curve)->blockedLinkMask & mask[0]) == 0 && n != 0)
            {
                candidates[count[0]++] = n;
            }
            mask[0] <<= 1;
        }
        if (count[0] != 0)
        {
            linkId = candidates[randomGetRange(0, count[0] - 1)];
        }
        else
        {
            linkId = -1;
        }
        curve = Objfsa_FindRomCurveById(linkId);
    loopTest:
        for (k = 0; k < 4; k++)
        {
            if (((ObjfsaRomCurveDef*)curve)->linkIds[k] != -1 &&
                ((s8)((ObjfsaRomCurveDef*)curve)->blockedLinkMask & (1 << k)) == 0)
            {
                k = 0;
                goto checkLoop;
            }
        }
        k = 1;
    checkLoop:
        if (k != 0)
        {
            break;
        }
    } while (1);

    *outPhase = gFloatZero;
    return curve;
}

void curves_getPos(int curve, float* outX, float* outY, float* outZ, f32 phase)
{
    f32 dx;
    f32 dy;
    f32 dz;
    int linkId;
    int c2;
    int candidates[4];
    int count;

    count = RomCurve_CollectUnblockedLinks((RomCurveDef*)curve, candidates);
    if (count != 0)
    {
        linkId = candidates[randomGetRange(0, count - 1)];
    }
    else
    {
        linkId = -1;
    }
    c2 = Objfsa_FindRomCurveById(linkId);

    if ((void*)c2 == NULL)
    {
        *outX = ((ObjfsaRomCurveDef*)curve)->x;
        *outY = ((ObjfsaRomCurveDef*)curve)->y;
        *outZ = ((ObjfsaRomCurveDef*)curve)->z;
    }
    else
    {
        dy = ((ObjfsaRomCurveDef*)c2)->y - ((ObjfsaRomCurveDef*)curve)->y;
        dz = ((ObjfsaRomCurveDef*)c2)->z - ((ObjfsaRomCurveDef*)curve)->z;
        dx = ((ObjfsaRomCurveDef*)c2)->x - ((ObjfsaRomCurveDef*)curve)->x;
        *outX = dx * phase + ((ObjfsaRomCurveDef*)curve)->x;
        *outY = dy * phase + ((ObjfsaRomCurveDef*)curve)->y;
        *outZ = dz * phase + ((ObjfsaRomCurveDef*)curve)->z;
    }
}

int RomCurve_func2C(RomCurveWalker* state, int unused, int startCurveId)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    char* stateBytes;
    u32 currentCurve;
    int nextId;
    int nextCurve;
    f32 t;

    if (state == NULL)
    {
        goto fail;
    }
    if (startCurveId == -1)
    {
        goto fail;
    }

    stateBytes = (char*)state;
    if (state->reverse != 0)
    {
        *(s32*)&state->nodeA0 = Objfsa_FindRomCurveById(startCurveId);
        nextId = RomCurve_pickRandomControlPointId_2A(*(s32*)&state->nodeA0);
        if (nextId == -1)
        {
            return 1;
        }
        startCurveId = nextId;
    }

    currentCurve = Objfsa_FindRomCurveById(startCurveId);
    *(s32*)&state->nodeA0 = currentCurve;
    if (currentCurve == 0)
    {
        state->nodeA0 = NULL;
        return 1;
    }

    if (state->reverse == 0)
    {
        nextId = RomCurve_pickRandomControlPointId_2A(*(s32*)&state->nodeA0);
    }
    else
    {
        nextId = RomCurve_pickRandomControlPointId_2B(*(s32*)&state->nodeA0);
    }
    if (nextId == -1)
    {
        return 1;
    }

    nextCurve = Objfsa_FindRomCurveById(nextId);
    *(s32*)&state->nodeA4 = nextCurve;
    if (nextCurve == 0)
    {
        state->nodeA4 = NULL;
        return 1;
    }

    ROMCURVE_REFRESH_CONTROL(0xa4);
    if (RomCurve_goNextPoint(state) != 0)
    {
        return 1;
    }

    state->node94 = Curve_EvalHermite;
    state->node98 = Curve_BuildHermiteCoeffs;
    state->coeffX = state->hermX;
    state->coeffY = state->hermY;
    state->coeffZ = state->hermZ;
    state->moveNetwork = 8;
    curvesMove((float*)state);
    return 0;
fail:
    return 1;
}

int RomCurve_get(RomCurveWalker* state, int obj, int* curveTypes, int curveType, f32 maxDistance)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    char* stateBytes;
    int curveId;
    u32 currentCurve;
    int nextId;
    int nextCurve;
    int distanceCurve;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    f32 t;

    if (state == NULL)
    {
        goto fail;
    }

    stateBytes = (char*)state;
    curveId = ((int (*)(int, int*, int, int, char))curves_findNearObj)(obj, curveTypes, 1, curveType, 0xc);
    if (curveId == -1)
    {
        goto fail;
    }

    if (state->reverse != 0)
    {
        *(s32*)&state->nodeA0 = Objfsa_FindRomCurveById(curveId);
        nextId = RomCurve_pickRandomControlPointId_2A(*(s32*)&state->nodeA0);
        if (nextId == -1)
        {
            return 1;
        }
        curveId = nextId;
    }

    currentCurve = Objfsa_FindRomCurveById(curveId);
    *(s32*)&state->nodeA0 = currentCurve;
    if (currentCurve == 0)
    {
        state->nodeA0 = NULL;
        return 1;
    }

    if (state->reverse == 0)
    {
        nextId = RomCurve_pickRandomControlPointId_2A(*(s32*)&state->nodeA0);
    }
    else
    {
        nextId = RomCurve_pickRandomControlPointId_2B(*(s32*)&state->nodeA0);
    }
    if (nextId == -1)
    {
        return 1;
    }

    nextCurve = Objfsa_FindRomCurveById(nextId);
    *(s32*)&state->nodeA4 = nextCurve;
    if (nextCurve == 0)
    {
        state->nodeA4 = NULL;
        return 1;
    }

    if (maxDistance != gFloatZero)
    {
        if (state->reverse != 0)
        {
            distanceCurve = *(s32*)&state->nodeA4;
            dx = *(f32*)(distanceCurve + 0x8) - ((GameObject*)obj)->anim.localPosX;
            dy = *(f32*)(distanceCurve + 0xc) - ((GameObject*)obj)->anim.localPosY;
            dz = *(f32*)(distanceCurve + 0x10) - ((GameObject*)obj)->anim.localPosZ;
        }
        else
        {
            distanceCurve = *(s32*)&state->nodeA0;
            dx = *(f32*)(distanceCurve + 0x8) - ((GameObject*)obj)->anim.localPosX;
            dy = *(f32*)(distanceCurve + 0xc) - ((GameObject*)obj)->anim.localPosY;
            dz = *(f32*)(distanceCurve + 0x10) - ((GameObject*)obj)->anim.localPosZ;
        }
        distance = sqrtf(dx * dx + dy * dy + dz * dz);
        if (distance > maxDistance)
        {
            return 1;
        }
    }

    ROMCURVE_REFRESH_CONTROL(0xa4);
    if (RomCurve_goNextPoint(state) != 0)
    {
        return 1;
    }

    state->node94 = Curve_EvalHermite;
    state->node98 = Curve_BuildHermiteCoeffs;
    state->coeffX = state->hermX;
    state->coeffY = state->hermY;
    state->coeffZ = state->hermZ;
    state->moveNetwork = 8;
    curvesMove((float*)state);
    return 0;
fail:
    return 1;
}

int RomCurve_func1C(u32 startCurve, int unused1, int unused2, int* previousCurveId)
{
    f32* scanBase;
    u32 cur;
    int queueCurve;
    int directIndex;
    int directSlot;
    int directLinkId;
    u32 directCurve;
    int startIndex;
    int candidateCount;
    int queueCount;
    int linkId;
    int linkCurve;
    int insertIndex;
    int selectedIndex;
    int found;
    int i;
    int j;
    int linkSlot;
    f32 distance;
    f32 linkDistance;
    int candidateIds[4];
    f32 candidateDistances[4];
    int queueIndices[40];
    f32 queueDistances[40];
    u8 visited[ROMCURVE_MAX_CURVES];

    if (startCurve == 0)
    {
        return -1;
    }
    if (RomCurve_findByIdWithIndex(*(s32*)(startCurve + 0x14), &startIndex) == NULL)
    {
        return -1;
    }

    candidateCount = 0;
    for (directSlot = 0, cur = startCurve, scanBase = queueDistances; directSlot < 4;
         directSlot++, cur += 4)
    {
        directLinkId = *(s32*)(cur + 0x1c);
        if (directLinkId <= -1)
        {
            continue;
        }

        for (i = 0; i < ROMCURVE_MAX_CURVES; i++)
        {
            visited[i] = 0;
        }
        visited[startIndex] = 1;

        directCurve = (u32)RomCurve_findByIdWithIndex(*(s32*)(cur + 0x1c), &directIndex);
        if (directCurve == 0)
        {
            continue;
        }

        distance = (*(f32*)(directCurve + 0x10) - *(f32*)(startCurve + 0x10)) *
                   (*(f32*)(directCurve + 0x10) - *(f32*)(startCurve + 0x10));
        queueDistances[0] =
            (*(f32*)(directCurve + 0x8) - *(f32*)(startCurve + 0x8)) *
                (*(f32*)(directCurve + 0x8) - *(f32*)(startCurve + 0x8)) +
            (*(f32*)(directCurve + 0xc) - *(f32*)(startCurve + 0xc)) *
                (*(f32*)(directCurve + 0xc) - *(f32*)(startCurve + 0xc)) +
            distance;
        queueCount = 0;
        queueIndices[queueCount++] = directIndex;
        visited[directIndex] = 1;

        found = 0;
        do
        {
            if (queueCount > 0)
            {
            queueCount--;
            directIndex = queueIndices[queueCount];
            queueCurve = (int)romCurves[directIndex];
            distance = queueDistances[queueCount];

            if (*(u8*)(queueCurve + 0x34) == 1)
            {
                found = 1;
                candidateDistances[candidateCount] = distance;
                candidateIds[candidateCount++] = *(s32*)(cur + 0x1c);
                continue;
            }

            for (linkSlot = 0; linkSlot < 4; linkSlot++)
            {
                linkId = *(s32*)((queueCurve + linkSlot * 4) + 0x1c);
                if (linkId <= -1)
                {
                    continue;
                }

                linkCurve = (int)RomCurve_findByIdWithIndex(linkId, &directIndex);
                if ((void*)linkCurve == NULL || (s8)visited[directIndex] != 0 || queueCount >= ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY)
                {
                    continue;
                }

                linkDistance =
                    (*(f32*)(queueCurve + 0x10) - *(f32*)(linkCurve + 0x10)) *
                        (*(f32*)(queueCurve + 0x10) - *(f32*)(linkCurve + 0x10)) +
                    (distance +
                     (*(f32*)(queueCurve + 0x8) - *(f32*)(linkCurve + 0x8)) *
                         (*(f32*)(queueCurve + 0x8) - *(f32*)(linkCurve + 0x8)) +
                     (*(f32*)(queueCurve + 0xc) - *(f32*)(linkCurve + 0xc)) *
                         (*(f32*)(queueCurve + 0xc) - *(f32*)(linkCurve + 0xc)));

                insertIndex = 0;
                while (insertIndex < queueCount && scanBase[insertIndex] > linkDistance)
                {
                    insertIndex++;
                }
                for (j = queueCount; j > insertIndex; j--)
                {
                    queueIndices[j] = queueIndices[j - 1];
                    queueDistances[j] = queueDistances[j - 1];
                }
                queueCount++;
                queueDistances[insertIndex] = linkDistance;
                queueIndices[insertIndex] = directIndex;
                visited[directIndex] = 1;
            }
            }
            else
            {
                found = 1;
            }
        } while (!found);
    }

    if (candidateCount == 0)
    {
        return -1;
    }
    if (candidateCount == 1)
    {
        *previousCurveId = *(s32*)(startCurve + 0x14);
        return candidateIds[0];
    }
    if (candidateCount > 1)
    {
        for (i = 0; i < candidateCount; i++)
        {
            if (*previousCurveId == candidateIds[i])
            {
                for (; i < candidateCount - 1; i++)
                {
                    candidateIds[i] = candidateIds[i + 1];
                    candidateDistances[i] = candidateDistances[i + 1];
                }
                candidateCount--;
            }
        }

        *previousCurveId = *(s32*)(startCurve + 0x14);
        selectedIndex = 0;
        for (i = 0; i < candidateCount; i++)
        {
            if (candidateDistances[i] < candidateDistances[selectedIndex])
            {
                selectedIndex = i;
            }
        }
        return candidateIds[selectedIndex];
    }
    return -1;
}

#pragma peephole on
void RomCurve_stepClamped(RomCurveWalker* state, f32 dt)
{
    if (state->phase <= lbl_803E05F0)
    {
        state->phase = lbl_803E05F4;
    }
    else if (state->phase >= lbl_803E05C8)
    {
        state->phase = lbl_803E05CC;
    }
    Curve_AdvanceAlongPath(state, dt);
}

#pragma peephole off
int curveFn_800da23c(RomCurveWalker* state, void* targetCurve)
{
    char* stateBytes;

    stateBytes = (char*)state;
    if (state->nodeA0 == NULL ||
        state->nodeA4 == NULL ||
        targetCurve == NULL)
    {
        return 1;
    }

    if (state->reverse != 0)
    {
        state->node9C = state->nodeA0;
        state->nodeA0 = state->nodeA4;
        state->nodeA4 = targetCurve;

        memcpy(stateBytes + 0xb8, stateBytes + 0xa8, 0x10);
        memcpy(stateBytes + 0xd8, stateBytes + 0xc8, 0x10);
        memcpy(stateBytes + 0xf8, stateBytes + 0xe8, 0x10);

        state->hermX[0] = *(f32*)((char*)state->nodeA4 + 0x8);
        state->hermX[1] = *(f32*)((char*)state->nodeA0 + 0x8);
        state->hermX[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 0);
        state->hermX[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 0);

        state->hermY[0] = *(f32*)((char*)state->nodeA4 + 0xc);
        state->hermY[1] = *(f32*)((char*)state->nodeA0 + 0xc);
        state->hermY[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2d, 0);
        state->hermY[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2d, 0);

        state->hermZ[0] = *(f32*)((char*)state->nodeA4 + 0x10);
        state->hermZ[1] = *(f32*)((char*)state->nodeA0 + 0x10);
        state->hermZ[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 1);
        state->hermZ[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 1);

        if (state->moveNetwork != 0)
        {
            curvesSetupMoveNetworkCurve((float*)state);
            if (state->phase <= lbl_803E05F0)
            {
                state->phase = lbl_803E05F4;
            }
        }
    }
    else
    {
        state->node9C = state->nodeA0;
        state->nodeA0 = state->nodeA4;
        state->nodeA4 = targetCurve;

        memcpy(stateBytes + 0xa8, stateBytes + 0xb8, 0x10);
        memcpy(stateBytes + 0xc8, stateBytes + 0xd8, 0x10);
        memcpy(stateBytes + 0xe8, stateBytes + 0xf8, 0x10);

        state->hermX2[0] = *(f32*)((char*)state->nodeA0 + 0x8);
        state->hermX2[1] = *(f32*)((char*)state->nodeA4 + 0x8);
        state->hermX2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 0);
        state->hermX2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 0);

        state->hermY2[0] = *(f32*)((char*)state->nodeA0 + 0xc);
        state->hermY2[1] = *(f32*)((char*)state->nodeA4 + 0xc);
        state->hermY2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2d, 0);
        state->hermY2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2d, 0);

        state->hermZ2[0] = *(f32*)((char*)state->nodeA0 + 0x10);
        state->hermZ2[1] = *(f32*)((char*)state->nodeA4 + 0x10);
        state->hermZ2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 1);
        state->hermZ2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 1);

        if (state->moveNetwork != 0)
        {
            curvesSetupMoveNetworkCurve((float*)state);
            if (state->phase >= lbl_803E05C8)
            {
                state->phase = lbl_803E05CC;
            }
        }
    }

    return 0;
}

int fn_800DA980(RomCurveWalker* state, void* fromCurve, void* toCurve, void* targetCurve)
{
    if (state->reverse != 0)
    {
        state->nodeA0 = fromCurve;
        state->nodeA4 = toCurve;

        state->hermX[0] = *(f32*)((char*)state->nodeA4 + 0x8);
        state->hermX[1] = *(f32*)((char*)state->nodeA0 + 0x8);
        state->hermX[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 0);
        state->hermX[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 0);

        state->hermY[0] = *(f32*)((char*)state->nodeA4 + 0xc);
        state->hermY[1] = *(f32*)((char*)state->nodeA0 + 0xc);
        state->hermY[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2d, 0);
        state->hermY[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2d, 0);

        state->hermZ[0] = *(f32*)((char*)state->nodeA4 + 0x10);
        state->hermZ[1] = *(f32*)((char*)state->nodeA0 + 0x10);
        state->hermZ[2] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 1);
        state->hermZ[3] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 1);
    }
    else
    {
        state->nodeA0 = fromCurve;
        state->nodeA4 = toCurve;

        state->hermX2[0] = *(f32*)((char*)state->nodeA0 + 0x8);
        state->hermX2[1] = *(f32*)((char*)state->nodeA4 + 0x8);
        state->hermX2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 0);
        state->hermX2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 0);

        state->hermY2[0] = *(f32*)((char*)state->nodeA0 + 0xc);
        state->hermY2[1] = *(f32*)((char*)state->nodeA4 + 0xc);
        state->hermY2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2d, 0);
        state->hermY2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2d, 0);

        state->hermZ2[0] = *(f32*)((char*)state->nodeA0 + 0x10);
        state->hermZ2[1] = *(f32*)((char*)state->nodeA4 + 0x10);
        state->hermZ2[2] = RomCurveNode_GetHermiteTangent(&state->nodeA0, 0x2c, 1);
        state->hermZ2[3] = RomCurveNode_GetHermiteTangent(&state->nodeA4, 0x2c, 1);
    }

    if (curveFn_800da23c(state, targetCurve) != 0)
    {
        return 1;
    }

    state->node94 = Curve_EvalHermite;
    state->node98 = Curve_BuildHermiteCoeffs;
    state->coeffX = state->hermX;
    state->coeffY = state->hermY;
    state->coeffZ = state->hermZ;
    state->moveNetwork = 8;
    curvesMove((float*)state);
    return 0;
}

void* Objfsa_FindNearestCurveType24(int pos, int p4_filter, int p5_filter)
{
    int count;
    int* hit;
    int* bestHit;
    int** list = (int**)(*gRomCurveInterface)->getCurves(&count);
    f32 minDist = gObjfsaNearestDistInit;
    int i;
    bestHit = 0;
    for (i = count; i > 0; i--)
    {
        hit = *list;
        if (hit != 0
            && (s8) * ((u8*)hit + 0x19) == 0x24
            && (p4_filter == -1 || *((u8*)hit + 3) == p4_filter)
            && (p5_filter == -1 || (s8) * ((u8*)hit + 0x1A) == p5_filter))
        {
            f32 dx = *(f32*)pos - *(f32*)((char*)hit + 8);
            f32 dy = *(f32*)(pos + 4) - *(f32*)((char*)hit + 0xC);
            f32 d;
            f32 dz = *(f32*)(pos + 8) - *(f32*)((char*)hit + 0x10);
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

void* Objfsa_FindNearestEnabledCurveType24(int pos, int p4_filter, int p5_filter)
{
    int count;
    int** list;
    int i;
    int* hit;
    int* bestHit;
    s16 gbId;
    f32 minDist;
    int** tmp = (int**)(*gRomCurveInterface)->getCurves(&count);
    minDist = gObjfsaNearestDistInit;
    bestHit = 0;
    i = 0;
    list = tmp;
    for (; i < count; i++)
    {
        hit = *list;
        if (hit != 0
            && (s8) * ((u8*)hit + 0x19) == 0x24
            && (p4_filter == -1 || *((u8*)hit + 3) == p4_filter)
            && (p5_filter == -1 || (s8) * ((u8*)hit + 0x1A) == p5_filter))
        {
            gbId = *(s16*)((char*)hit + 0x30);
            if (gbId == -1 || GameBit_Get(gbId) != 0)
            {
                gbId = *(s16*)((char*)hit + 0x32);
                if (gbId == -1 || GameBit_Get(gbId) == 0)
                {
                    f32 dx = *(f32*)pos - *(f32*)((char*)hit + 8);
                    f32 dy = *(f32*)(pos + 4) - *(f32*)((char*)hit + 0xC);
                    f32 d;
                    f32 dz = *(f32*)(pos + 8) - *(f32*)((char*)hit + 0x10);
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

#define OBJFSA_CORNER(BASE, OFF, POSOFF)                                        \
    (f32)((f32)*(s8 *)(OFF) * scale + *(f32 *)((BASE) + (POSOFF)))

#define OBJFSA_SET_PLANE(P, K, XA, ZA)                                          \
    len = sqrtf(dxn * dxn + dzn * dzn);                                         \
    if (len != lbl_803E05F0) {                                                  \
        dxn = dxn / len;                                                        \
        dzn = dzn / len;                                                        \
    }                                                                           \
    (P).planes[K].normalX = (s16)(gObjfsaPlaneNormalScale * dxn);                          \
    (P).planes[K].normalZ = (s16)(gObjfsaPlaneNormalScale * dzn);                          \
    (P).planeOffsets[K] = -((f32)(P).planes[K].normalX * (XA) +                 \
                            (f32)(P).planes[K].normalZ * (ZA))

#define OBJFSA_WG(GRP) ((ObjfsaWalkGroup *)((char *)patchBase + (GRP) * OBJFSA_PATCHGROUP_STRIDE + 0x3000))

#define OBJFSA_EXIT_INSIDE(WGP, XF, ZF)                                         \
    exitFz = (f32)(ZF);                                                             \
    exitFx = (f32)(XF);                                                             \
    for (edge = 0, normalIdx = 0; edge < 4; edge++, normalIdx += 2) {                                                   \
        if ((WGP)->planeOffsets[edge] +                                   \
                (exitFx * (f32)((s16 *)(WGP))[normalIdx] +                 \
                 exitFz * (f32)((s16 *)(WGP))[normalIdx + 1]) >          \
            zero) {                                                     \
            break;                                                              \
        }                                                                       \
    }

#define OBJFSA_NEWPATCH (patchBase[gObjfsaPatchCount])

#define OBJFSA_SET_NEWPATCH_PLANE(K, DXE, DZE, XA, ZA)                          \
    po = &OBJFSA_NEWPATCH.planeOffsets[K];                                      \
    pl = &OBJFSA_NEWPATCH.planes[K];                                            \
    dxn = (DXE);                                                                \
    dzn = (DZE);                                                                \
    len = sqrtf(dxn * dxn + dzn * dzn);                                         \
    if (len != lbl_803E05F0) {                                                  \
        dxn = dxn / len;                                                        \
        dzn = dzn / len;                                                        \
    }                                                                           \
    pl->normalX = (s16)(gObjfsaPlaneNormalScale * dxn);                         \
    pl->normalZ = (s16)(gObjfsaPlaneNormalScale * dzn);                         \
    *(po) = -((f32)pl->normalX * (XA) +                                         \
              (f32)pl->normalZ * (ZA))

#pragma opt_propagation off
void walkgroupFindExitPointFn_800dc398(void)
{
    ObjfsaPatch* patchBase = gObjfsaPatches;
    u8 blockFlags[0x78];
    u8 pairs[364];
    ObjfsaPatch* np;
    u8 groupB;
    char* slotPtr;
    int flagIndex;
    int found;
    int curveCount;
    u8* pp;
    int** listWalk;
    int listIndex;
    int back;
    int slot;
    int curve;
    u32 linked;
    int iter;
    int pi;
    u32 gi;
    u8 groupA;
    u8 edge;
    u8 normalIdx;
    int pairId;
    int checksum;
    int searchCount;
    ObjfsaWalkGroup* wg;
    ObjfsaWalkGroup* wgB;
    ObjfsaPatchPlane* pl;
    f32* po;
    int** curveList;
    ObjfsaPatch* sp;
    ObjfsaPatch* p;
    char* lp;
    f32 fdx;
    f32 fdz;
    f32 div;
    f32 scale;
    f32 dxn;
    f32 dzn;
    f32 len;
    f32 exitFx;
    f32 exitFz;
    f32 x0;
    f32 z0;
    f32 x1;
    f32 z1;
    f32 x2;
    f32 z2;
    f32 x3;
    f32 z3;
    f32 fy0;
    f32 fy1;
    f32 zero;
    mapBlockFn_80059c2c(blockFlags);

    checksum = 1;
    for (flagIndex = 0; flagIndex < 120; flagIndex++)
    {
        if (blockFlags[flagIndex] != 0)
        {
            checksum *= flagIndex;
        }
    }

    if ((u32)checksum != gObjfsaBlockFlagsChecksum)
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
            scale = lbl_803E0600;
        }
        else
        {
            scale = lbl_803E0604;
        }

        curveList = (int**)(*gRomCurveInterface)->getCurves(&curveCount);
        memset((char*)patchBase + OBJFSA_ACTIVE_WALKGROUPS_OFFSET, 0, OBJFSA_WALKGROUP_COUNT);
        sp = patchBase;
        for (pi = 8; pi != 0; pi--)
        {
            sp[0].groupId = 0;
            sp[1].groupId = 0;
            sp[2].groupId = 0;
            sp[3].groupId = 0;
            sp[4].groupId = 0;
            sp[5].groupId = 0;
            sp[6].groupId = 0;
            sp[7].groupId = 0;
            sp[8].groupId = 0;
            sp[9].groupId = 0;
            sp[10].groupId = 0;
            sp[11].groupId = 0;
            sp[12].groupId = 0;
            sp[13].groupId = 0;
            sp[14].groupId = 0;
            sp[15].groupId = 0;
            sp[16].groupId = 0;
            sp[17].groupId = 0;
            sp[18].groupId = 0;
            sp[19].groupId = 0;
            sp[20].groupId = 0;
            sp[21].groupId = 0;
            sp[22].groupId = 0;
            sp[23].groupId = 0;
            sp[24].groupId = 0;
            sp[25].groupId = 0;
            sp[26].groupId = 0;
            sp[27].groupId = 0;
            sp[28].groupId = 0;
            sp[29].groupId = 0;
            sp[30].groupId = 0;
            sp[31].groupId = 0;
            sp += 32;
        }

        gObjfsaPatchCount = 1;
        for (listIndex = 0, listWalk = curveList; listIndex < curveCount; listIndex++)
        {
            curve = (int)*listWalk;
            if (*(s8*)(curve + 0x19) == 0x26)
            {
                gi = *(u8*)(curve + 3);
                wg = &((ObjfsaWalkGroup*)patchBase)[gi];
                wg = (ObjfsaWalkGroup*)((char*)wg + 0x3000);
                *((u8*)patchBase + gi + OBJFSA_ACTIVE_WALKGROUPS_OFFSET) = 1;

                x0 = OBJFSA_CORNER(curve, curve + 0x4, 0x8);
                z0 = OBJFSA_CORNER(curve, curve + 0x5, 0x10);
                x1 = OBJFSA_CORNER(curve, curve + 0x6, 0x8);
                z1 = OBJFSA_CORNER(curve, curve + 0x7, 0x10);

                dxn = z1 - z0;
                dzn = x0 - x1;
                OBJFSA_SET_PLANE(*wg, 0, x0, z0);

                x2 = OBJFSA_CORNER(curve, curve + 0x30, 0x8);
                z2 = OBJFSA_CORNER(curve, curve + 0x31, 0x10);
                dxn = z2 - z1;
                dzn = x1 - x2;
                OBJFSA_SET_PLANE(*wg, 1, x1, z1);

                x3 = OBJFSA_CORNER(curve, curve + 0x32, 0x8);
                z3 = OBJFSA_CORNER(curve, curve + 0x33, 0x10);
                dxn = z3 - z2;
                dzn = x2 - x3;
                OBJFSA_SET_PLANE(*wg, 2, x2, z2);

                dxn = OBJFSA_CORNER(curve, curve + 0x5, 0x10) - z3;
                dzn = x3 - OBJFSA_CORNER(curve, curve + 0x4, 0x8);
                OBJFSA_SET_PLANE(*wg, 3, x3, z3);

                wg->maxY = (s16)(lbl_803E05D0 * (f32) * (s8*)(curve + 0x18) +
                    *(f32*)(curve + 0xc));
                wg->minY = (s16) - (lbl_803E05D0 * (f32) * (s8*)(curve + 0x1a) -
                    *(f32*)(curve + 0xc));

                for (slot = 0, slotPtr = (char*)curve; slot < 4; slot++)
                {
                    wg->patchIndices[slot] = 0;
                    if (*(s32*)(slotPtr + 0x1c) > -1 &&
                        (linked = (u32)(*gRomCurveInterface)->getById(*(s32*)(slotPtr + 0x1c))) != 0)
                    {
                        groupA = *(u8*)(curve + 3);
                        groupB = *(u8*)(linked + 3);
                        if (groupA < groupB)
                        {
                            pairId = groupA | (groupB << 8);
                        }
                        else
                        {
                            pairId = (groupA << 8) | groupB;
                        }

                        found = 1;
                        sp = &patchBase[1];
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
                            if (*(u32*)(linked + 0x1c) != *(u32*)(curve + 0x14) &&
                                (back = 1, *(u32*)(linked + 0x20) != *(u32*)(curve + 0x14)) &&
                                (back = 2, *(u32*)(linked + 0x24) != *(u32*)(curve + 0x14)) &&
                                (back = 3, *(u32*)(linked + 0x28) != *(u32*)(curve + 0x14)))
                            {
                                back = 4;
                            }
                            wg->patchIndices[slot] = gObjfsaPatchCount;
                            np = &patchBase[gObjfsaPatchCount];
                            np->groupId = pairId;
                            pairs[gObjfsaPatchCount * 2] = *(u8*)(curve + 3);
                            pairs[gObjfsaPatchCount * 2 + 1] = *(u8*)(linked + 3);

                            x0 = OBJFSA_CORNER(curve, slotPtr + 0x34, 0x8);
                            z0 = OBJFSA_CORNER(curve, slotPtr + 0x35, 0x10);
                            x1 = OBJFSA_CORNER(curve, slotPtr + 0x36, 0x8);
                            z1 = OBJFSA_CORNER(curve, slotPtr + 0x37, 0x10);
                            np->exit0X = (s16)((x0 + x1) * lbl_803E0608);
                            np->exit0Z = (s16)((z0 + z1) * lbl_803E0608);

                            OBJFSA_SET_NEWPATCH_PLANE(0, z1 - z0, x0 - x1, x0, z0);

                            lp = (char*)(linked + back * 4);
                            x2 = OBJFSA_CORNER(linked, lp + 0x34, 0x8);
                            z2 = OBJFSA_CORNER(linked, lp + 0x35, 0x10);
                            OBJFSA_SET_NEWPATCH_PLANE(1, z2 - z1, x1 - x2, x1, z1);

                            x3 = OBJFSA_CORNER(linked, lp + 0x36, 0x8);
                            z3 = OBJFSA_CORNER(linked, lp + 0x37, 0x10);
                            np = &OBJFSA_NEWPATCH;
                            np->exit1X = (s16)((x2 + x3) * lbl_803E0608);
                            np->exit1Z = (s16)((z2 + z3) * lbl_803E0608);

                            OBJFSA_SET_NEWPATCH_PLANE(2, z3 - z2, x2 - x3, x2, z2);

                            OBJFSA_SET_NEWPATCH_PLANE(3, OBJFSA_CORNER(curve, slotPtr + 0x35, 0x10) - z3,
                                                       x3 - OBJFSA_CORNER(curve, slotPtr + 0x34, 0x8), x3, z3);

                            fy0 = lbl_803E05D0 * (f32) * (s8*)(curve + 0x18) +
                                *(f32*)(curve + 0xc);
                            fy1 = lbl_803E05D0 * (f32) * (s8*)(linked + 0x18) +
                                *(f32*)(linked + 0xc);
                            if (fy0 > fy1)
                            {
                                OBJFSA_NEWPATCH.maxY = fy0;
                            }
                            else
                            {
                                OBJFSA_NEWPATCH.maxY = fy1;
                            }
                            fy0 = -(lbl_803E05D0 * (f32) * (s8*)(curve + 0x1a) -
                                *(f32*)(curve + 0xc));
                            fy1 = -(lbl_803E05D0 * (f32) * (s8*)(linked + 0x1a) -
                                *(f32*)(linked + 0xc));
                            if (fy0 < fy1)
                            {
                                OBJFSA_NEWPATCH.minY = fy0;
                            }
                            else
                            {
                                OBJFSA_NEWPATCH.minY = fy1;
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
        zero = lbl_803E05F0;
        div = lbl_803E060C;
        p = &patchBase[1];
        for (; pi < gObjfsaPatchCount; pp += 2, p++, pi++)
        {
            wg = &((ObjfsaWalkGroup*)patchBase)[pp[0]];
            wg = (ObjfsaWalkGroup*)((char*)wg + 0x3000);
            wgB = &((ObjfsaWalkGroup*)patchBase)[pp[1]];
            wgB = (ObjfsaWalkGroup*)((char*)wgB + 0x3000);
            fdx = (f32)(p->exit1X - p->exit0X);
            fdz = (f32)(p->exit1Z - p->exit0Z);

            iter = 0;
            goto scan0;
        update0:
            p->exit0X = (s16)((f32)p->exit0X + fdx / div);
            p->exit0Z = (s16)((f32)p->exit0Z + fdz / div);
            if (iter++ == 100)
            {
                OSReport(sObjfsaMissingPatchExitPoint0, p->groupId & 0xff,
                         (int)(u32)p->groupId >> 8);
                goto exit0Done;
            }
        scan0:
            OBJFSA_EXIT_INSIDE(wg, p->exit0X, p->exit0Z);
            if (edge != 4)
            {
                OBJFSA_EXIT_INSIDE(wgB, p->exit0X, p->exit0Z);
                if (edge != 4) goto update0;
            }

        exit0Done:
            iter = 0;
            goto scan1;
        update1:
            p->exit1X = (s16)((f32)p->exit1X - fdx / div);
            p->exit1Z = (s16)((f32)p->exit1Z - fdz / div);
            if (iter++ == 100)
            {
                OSReport(sObjfsaMissingPatchExitPoint1, p->groupId & 0xff,
                         (int)(u32)p->groupId >> 8);
                goto exit1Done;
            }
        scan1:
            OBJFSA_EXIT_INSIDE(wg, p->exit1X, p->exit1Z);
            if (edge != 4)
            {
                OBJFSA_EXIT_INSIDE(wgB, p->exit1X, p->exit1Z);
                if (edge != 4) goto update1;
            }
        exit1Done:
            ;
        }
    }
}
#pragma opt_propagation reset

int RomCurve_func1B(int curve, int preferredNeighborId, f32 x, f32 y, f32 z)
{
    int bestNeighborIds[2];
    float bestDistances[2];
    RomCurveSegmentProjection segment;
    int i;
    int neighborId;
    int neighborCurve;
    int slot;
    float dx;
    float dy;
    float dz;
    float dySq;
    float distance;

    bestNeighborIds[1] = -1;
    bestNeighborIds[0] = -1;
    bestDistances[1] = lbl_803E0644;
    bestDistances[0] = lbl_803E0644;

    segment.startX = ((ObjfsaRomCurveDef*)curve)->x;
    segment.startY = ((ObjfsaRomCurveDef*)curve)->y;
    segment.startZ = ((ObjfsaRomCurveDef*)curve)->z;

    for (i = 0; i < 4; i++)
    {
        neighborId = ((ObjfsaRomCurveDef*)curve)->linkIds[i];
        if (neighborId > -1)
        {
            neighborCurve = Objfsa_FindRomCurveById(neighborId);
            if ((void*)neighborCurve != NULL)
            {
                segment.endX = ((ObjfsaRomCurveDef*)neighborCurve)->x;
                segment.endY = ((ObjfsaRomCurveDef*)neighborCurve)->y;
                segment.endZ = ((ObjfsaRomCurveDef*)neighborCurve)->z;

                RomCurve_distanceToSegment(x, y, z, &segment);
                dx = segment.nearestX - x;
                dy = segment.nearestY - y;
                dz = segment.nearestZ - z;
                dySq = dy * dy;
                distance = dySq + dx * dx + dz * dz;
                slot = (u32)__cntlzw(preferredNeighborId - neighborId) >> 5;
                if (distance < bestDistances[slot])
                {
                    bestDistances[slot] = distance;
                    bestNeighborIds[slot] = ((ObjfsaRomCurveDef*)curve)->linkIds[i];
                }
            }
        }
    }

    if (bestNeighborIds[0] != -1)
    {
        return bestNeighborIds[0];
    }
    if (bestNeighborIds[1] != -1)
    {
        return bestNeighborIds[1];
    }
    return -1;
}

int RomCurve_func16(double x, double y, double z)
{
    extern int curves_distFn15(); /* #57 */
    u32 candidateIds[20];
    u32* top;
    int candidateCount;
    int category;
    int i;
    int curve;
    int* curveList;
    int out;
    int currentCurve;

    candidateCount = 0;
    i = 0;
    curveList = (int*)romCurves;
    for (; i < nRomCurves && candidateCount < 20; i++)
    {
        curve = curveList[i];
        if (((ObjfsaRomCurveDef*)curve)->type == 0x17)
        {
            candidateIds[candidateCount++] = ((ObjfsaRomCurveDef*)curve)->id;
        }
    }

    top = &candidateIds[candidateCount];
    while (candidateCount != 0)
    {
        if (curves_distFn15(candidateIds[0], x, y, z, &out) != 0)
        {
            return candidateIds[0];
        }

        currentCurve = Objfsa_FindRomCurveById(candidateIds[0]);
        category = ((ObjfsaRomCurveDef*)currentCurve)->action;
        i = 0;
        while (i < candidateCount)
        {
            currentCurve = Objfsa_FindRomCurveById(candidateIds[i]);
            if (((ObjfsaRomCurveDef*)currentCurve)->action == category)
            {
                candidateCount--;
                candidateIds[i] = candidateIds[candidateCount];
            }
            else
            {
                i++;
            }
        }
    }

    return -1;
}

void walkPath_writeU16LE(u32 v, u8* dst)
{
    v = v & 0xffff;
    dst[0] = v;
    dst[1] = (u8)((s32)v >> 8);
}

#pragma scheduling on
void fn_800D9EE8(float* p)
{
    u32* a = (u32*)((char*)p + 0x9c);
    u32* b = (u32*)((char*)p + 0xa4);
    *a ^= *b;
    *b ^= *a;
    *a ^= *b;
    if (*p >= lbl_803E05C8)
    {
        *p = lbl_803E05CC;
    }
}

#pragma scheduling off
int fn_800DB240(int p1, f32* outVec, u16 id)
{
    extern f32 vec3f_distanceSquared(int, int); /* #57 */
    u8 i;
    f32 d1;

    for (i = 0; i < 256; i++)
    {
        if (gObjfsaPatches[i].groupId == id) break;
    }

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit0X;
    outVec[1] = *(f32*)(p1 + 4);
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit0Z;
    d1 = vec3f_distanceSquared(p1, (int)outVec);

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit1X;
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit1Z;

    if (vec3f_distanceSquared(p1, (int)outVec) < d1)
    {
        return 1;
    }

    outVec[0] = (f32)(s32)gObjfsaPatches[i].exit0X;
    outVec[2] = (f32)(s32)gObjfsaPatches[i].exit0Z;
    return 1;
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
    RomCurveDef* curve;
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
        curve = romCurves[mid];
        if (curveId > curve->id)
        {
            low = mid + 1;
        }
        else if (curveId < curve->id)
        {
            high = mid - 1;
        }
        else
        {
            return curve;
        }
    }

    return NULL;
}

int RomCurve_segmentIntersectsOriginRayXZ(f32 x, f32 unusedY, f32 z, RomCurveDef* a,
                                          RomCurveDef* b, f32 unusedW);

static inline RomCurveDef* RomCurve_FindByIdWithLimit(u32 curveId, int lim)
{
    RomCurveDef* curve;
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
        curve = romCurves[mid];
        if (curveId > curve->id)
        {
            low = mid + 1;
        }
        else if (curveId < curve->id)
        {
            high = mid - 1;
        }
        else
        {
            return curve;
        }
    }

    return NULL;
}

#pragma opt_propagation off
u32
RomCurve_projectPointToAdjacentWindow(f32 x, f32 y, f32 z, u32* curveIds,
                                      float* outLateralOffset, float* outVerticalOffset,
                                      float* outPhase)
{
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
    int lim;
    RomCurveDef** cp;
    int i;

    i = 0;
    cp = curves;
    lim = nRomCurves - 1;
    while (i < 4)
    {
        *cp = RomCurve_FindByIdWithLimit(*curveIds, lim);
        curveIds++;
        cp++;
        i++;
    }

    dx = curves[2]->x - curves[1]->x;
    segmentDx = dx;
    dz = curves[2]->z - curves[1]->z;
    segmentDz = dz;
    if (curves[0] != NULL)
    {
        tdx = curves[1]->x - curves[0]->x;
        tdz = curves[1]->z - curves[0]->z;
    }
    else
    {
        tdx = dx;
        tdz = dz;
    }
    tangentDx = gFloatHalf * (tdx + dx);
    tangentDz = gFloatHalf * (tdz + dz);
    tangentLen = sqrtf(tangentDx * tangentDx + tangentDz * tangentDz);
    if ((*(f32*)&gFloatZero) != tangentLen)
    {
        tangentDx = tangentDx / tangentLen;
        tangentDz = tangentDz / tangentLen;
    }

    x1 = curves[1]->x;
    z1 = curves[1]->z;
    tangentLen = (tangentDx * x1) + (tangentDz * z1);
    numer = -tangentLen;
    startPhase = tangentDx * segmentDx + tangentDz * segmentDz;
    if (gFloatZero != startPhase)
    {
        startPhase =
            -(numer + ((tangentDx * x) + (tangentDz * z))) / startPhase;
    }

    dx = curves[2]->x - x1;
    dz = curves[2]->z - z1;
    if (curves[3] != NULL)
    {
        tdx = curves[3]->x - curves[2]->x;
        tdz = curves[3]->z - curves[2]->z;
    }
    else
    {
        tdx = dx;
        tdz = dz;
    }
    tangentDx = gFloatHalf * (tdx + dx);
    tangentDz = gFloatHalf * (tdz + dz);
    tangentLen = sqrtf(tangentDx * tangentDx + tangentDz * tangentDz);
    if ((*(f32*)&gFloatZero) != tangentLen)
    {
        tangentDx = tangentDx / tangentLen;
        tangentDz = tangentDz / tangentLen;
    }

    numer = -((tangentDx * curves[2]->x) + (tangentDz * curves[2]->z));
    endPhase = tangentDx * segmentDx + tangentDz * segmentDz;
    if (gFloatZero != endPhase)
    {
        endPhase =
            -(numer + ((tangentDx * x) + (tangentDz * z))) / endPhase;
    }

    /* tangentDx is reused as the projected phase from here on; tdz is reused
     * as the segment Y delta and startPhase's old value doubles as the
     * unnormalized lateral fallback (segmentDx/segmentDz still hold the raw
     * segment deltas, which equal dx/dz when segmentLen is degenerate). */
    tangentDx = -startPhase / (endPhase - startPhase);
    if ((tangentDx >= *(f32*)(int)&gFloatZero) && (tangentDx < gFloatOne))
    {
        f32 projX;
        f32 projY;
        f32 projZ;

        tdz = curves[2]->y - curves[1]->y;
        segmentLen = sqrtf(dx * dx + tdz * tdz + dz * dz);
        if (segmentLen > (*(f32*)&gFloatZero))
        {
            segmentLen = gFloatOne / segmentLen;
            segmentDx = -dx * segmentLen;
            segmentDz = -dz * segmentLen;
        }

        projX = dx * tangentDx + curves[1]->x;
        projY = tdz * tangentDx + curves[1]->y;
        projZ = dz * tangentDx + curves[1]->z;
        *outLateralOffset =
            -((projX * segmentDz) - (projZ * segmentDx)) + (x * segmentDz - z * segmentDx);
        *outVerticalOffset = y - projY;
        *outPhase = tangentDx;
        return 1;
    }
    return 0;
}

#pragma opt_propagation reset
int curves_distFn15(u32 curveId, f32 x, f32 y, f32 z, f32* outDistance)
{
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
    *outDistance = lbl_803E065C;
    do
    {
        nextCurveId = ROMCURVE_LINK_ID_NONE;
        linkIndex = 0;
        nextCurve = curve;
        while ((linkIndex < ROMCURVE_LINK_COUNT) && (nextCurveId == (int)ROMCURVE_LINK_ID_NONE))
        {
            if ((curve->blockedLinkMask & (1 << linkIndex)) == 0)
            {
                nextCurveId = nextCurve->linkIds[0];
            }
            nextCurve = (RomCurveDef*)((u8*)nextCurve + ROMCURVE_LINK_ID_STRIDE);
            linkIndex++;
        }

        nextCurve = curve;
        if (nextCurveId != (int)ROMCURVE_LINK_ID_NONE)
        {
            nextCurve = RomCurve_FindByIdInline(nextCurveId);
            if (RomCurve_segmentIntersectsOriginRayXZ(x, y, z, curve, nextCurve, lbl_803E0660) != 0)
            {
                dx = curve->x - x;
                dy = curve->y - y;
                dz = curve->z - z;
                distance = sqrtf(dx * dx + dy * dy + dz * dz);
                if (distance < *outDistance)
                {
                    *outDistance = distance;
                }
                hitCount++;
            }
            previousCurveId = nextCurveId;
            curve = nextCurve;
        }
    }
    while ((previousCurveId != (int)curveId) && (nextCurveId != (int)ROMCURVE_LINK_ID_NONE));

    return hitCount & 1;
}

int curves_distanceToNearestOfType16(f32 x, f32 y, f32 z, int queryAll)
{
    float dx;
    float dy;
    float dz;
    int* objects;
    int obj;
    int i;
    RomCurveDef* curve;
    float distance;
    float nearestDistance;
    float nearestCurveId;
    int startIndex;
    int objectCount;

    objects = ObjList_GetObjects(&startIndex, &objectCount);
    nearestCurveId = gFloatNegOne;
    nearestDistance = gFloatZero;
    for (i = 0; i < objectCount; i = i + 1)
    {
        obj = objects[i];
        if (((((GameObject*)obj)->anim.classId == 0x2c) &&
                    (((GameObject*)obj)->anim.mapEventSlot != queryAll)) &&
                (curve = (RomCurveDef*)((GameObject*)obj)->anim.placementData, curve != NULL) &&
                curve->type == 0x16)
        {
            dx = ((GameObject*)obj)->anim.worldPosX - x;
            dy = ((GameObject*)obj)->anim.worldPosY - y;
            dz = ((GameObject*)obj)->anim.worldPosZ - z;
            distance = sqrtf(dz * dz + (dx * dx + dy * dy));
            if (gFloatNegOne == nearestCurveId || distance < nearestDistance)
            {
                nearestDistance = distance;
                nearestCurveId = (float)curve->id;
            }
        }
    }
    return nearestCurveId;
}

#define SQ(v) ((v) * (v))

int RomCurve_func13(u32 curveId, int typeFilter, int maxDist, int* outLink)
{
    RomCurveDef* cand;
    u32* idWrite;
    u32 candWalk;
    u32 cur;
    f32* probe;
    u32* idRead;
    RomCurveDef* node;
    f32* qscan;
    f32* distWrite;
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
    int j;
    int best;
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
    if (start == NULL)
    {
        return -1;
    }
    found = 0;
    li = 0;
    cur = (u32)start;
    distRead = bestDists;
    probe = distRead;
    idRead = resultIds;
    qscan = queueDist;
    for (; li < 4; li++, cur += 4)
    {
        if (*(s32*)(cur + 0x1c) <= -1)
        {
            continue;
        }
        for (off = 0; off < ROMCURVE_MAX_CURVES; off++)
        {
            visited[off] = 0;
        }
        visited[startIdx] = 1;
        node = RomCurve_findByIdWithIndex(*(s32*)(cur + 0x1c), &idx);
        if (node == NULL)
        {
            continue;
        }
        queueDist[0] = SQ(node->z - start->z) + (SQ(node->x - start->x) + SQ(node->y - start->y));
        pos = 0;
        count = 1;
        queueIds[pos++] = idx;
        visited[idx] = 1;
        done = 0;
        distWrite = probe;
        idWrite = idRead;
        do
        {
            if (count > 0)
            {
                count--;
                idx = queueIds[count];
                node = romCurves[idx];
                curDist = queueDist[count];
                if ((((int)node->type == typeFilter) || (typeFilter == -1)) &&
                    ((*(u8*)((u8*)node + 0x31) == (int)maxDist ||
                        ((*(u8*)((u8*)node + 0x32) == (int)maxDist || (*(u8*)((u8*)node + 0x33) == (int)maxDist))))))
                {
                    done = 1;
                    *distWrite = curDist;
                    if (found < 4)
                    {
                        *idWrite = node->id;
                        probe++;
                        idRead++;
                        distWrite++;
                        idWrite++;
                        resultLinks[found++] = li;
                    }
                }
                else
                {
                    for (k = 0, candWalk = (u32)node; k < 4; k++, candWalk += 4)
                    {
                        if (((-1 < *(s32*)(candWalk + 0x1c)) &&
                                ((cand = RomCurve_findByIdWithIndex(*(s32*)(candWalk + 0x1c), &idx)) != NULL)) &&
                            (visited[idx] == 0) && (count < ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY))
                        {
                            newDist = SQ(node->z - cand->z) + ((curDist + SQ(node->x - cand->x)) +
                                SQ(node->y - cand->y));
                            pos = 0;
                            pq = qscan;
                            while ((pos < count) && (*pq > newDist))
                            {
                                pq++;
                                pos++;
                            }
                            for (m = count; m > pos; m--)
                            {
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
            }
            else
            {
                done = 1;
            }
        }
        while (!done);
    }
    if (found > 0)
    {
        best = 0;
        for (j = 0; j < found; j++)
        {
            if (*distRead < bestDists[best])
            {
                best = j;
            }
            distRead++;
        }
        if (outLink != NULL)
        {
            *outLink = resultLinks[best];
        }
        return resultIds[best];
    }
    return -1;
}

#pragma fp_contract off
int RomCurve_func11(RomCurveDef* curve, int typeFilter, int actionFilter, int* outCurveId)
{
    f32* distWrite;
    f32* probe;
    f32* qscan;
    f32* distRead;
    u32 cur;
    RomCurveDef* node;
    int li;
    int found;
    int count;
    int done;
    int k;
    RomCurveDef* cand;
    f32 newDist;
    f32* pq;
    int pos;
    int m;
    int j;
    int best;
    int off;
    f32 curDist;
    f32 zd;
    f32 xd;
    f32 yd;
    int linkWord;
    char* pc;
    char* pu;
    int rem;
    char zval;
    char visited[ROMCURVE_MAX_CURVES];
    int queueIds[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
    f32 queueDist[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
    int results[4];
    f32 bestDists[4];
    int idx;
    int startIdx;

    if (curve == NULL)
    {
        return -1;
    }
    if (RomCurve_findByIdWithIndex(curve->id, &startIdx) == NULL)
    {
        return -1;
    }
    found = 0;
    li = 0;
    cur = (u32)curve;
    distRead = bestDists;
    probe = distRead;
    qscan = queueDist;
    for (; li < 4; li++, cur += 4)
    {
        if (*(s32*)(cur + 0x1c) <= -1)
        {
            continue;
        }
        for (off = 0; off < ROMCURVE_MAX_CURVES; off++)
        {
            visited[off] = 0;
        }
        visited[startIdx] = 1;
        node = RomCurve_findByIdWithIndex(*(s32*)(cur + 0x1c), &idx);
        if (node == NULL)
        {
            continue;
        }
        queueDist[0] = SQ(node->z - curve->z) + (SQ(node->x - curve->x) + SQ(node->y - curve->y));
        pos = 0;
        count = 1;
        queueIds[pos++] = idx;
        visited[idx] = 1;
        done = 0;
        distWrite = probe;
        do
        {
            if (count > 0)
            {
                count--;
                idx = queueIds[count];
                node = romCurves[idx];
                curDist = queueDist[count];
                if (((int)node->type == typeFilter) &&
                    ((actionFilter == -1) || (actionFilter == node->action)))
                {
                    done = 1;
                    *distWrite = queueDist[count];
                    probe++;
                    distWrite++;
                    results[found++] = *(s32*)(cur + 0x1c);
                }
                else
                {
                    for (k = 0; k < 4; k++)
                    {
                        if (((-1 < (int)node->linkIds[k]) &&
                                ((cand = RomCurve_findByIdWithIndex(node->linkIds[k], &idx)) != NULL)) &&
                            (visited[idx] == 0) && (count < ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY))
                        {
                            newDist = SQ(node->z - cand->z) +
                                ((curDist + SQ(node->x - cand->x)) +
                                    SQ(node->y - cand->y));
                            pos = 0;
                            pq = qscan;
                            while ((pos < count) && (*pq > newDist))
                            {
                                pq++;
                                pos++;
                            }
                            for (m = count; m > pos; m--)
                            {
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
            }
            else
            {
                done = 1;
            }
        }
        while (!done);
    }
    if (found == 0)
    {
        return -1;
    }
    if (found == 1)
    {
        *outCurveId = curve->id;
        return results[0];
    }
    if (found > 1)
    {
        for (j = 0; j < found; j++)
        {
            if (*outCurveId == results[j])
            {
                for (; j < found - 1; j++)
                {
                    results[j] = results[j + 1];
                    bestDists[j] = bestDists[j + 1];
                }
                found--;
            }
        }
        *outCurveId = curve->id;
        best = 0;
        for (j = best; j < found; j++)
        {
            if (*distRead < bestDists[best])
            {
                best = j;
            }
            distRead++;
        }
        return results[best];
    }
    return -1;
}
#pragma fp_contract reset

int RomCurve_getRandomLinkedOfTypes(RomCurveDef* curve, int* types, int typeCount, int* previousLinkId)
{
    int candidateCount;
    int linkIndex;
    int typeIndex;
    int low;
    int high;
    int mid;
    int j;
    int linkId;
    RomCurveDef* linkedCurve;
    int candidates[4];

    if (curve == NULL)
    {
        return -1;
    }
    candidateCount = 0;
    for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++)
    {
        linkId = curve->linkIds[linkIndex];
        if (linkId > -1)
        {
            linkedCurve = RomCurve_FindByIdInline(linkId);

            for (typeIndex = 0; typeIndex < typeCount; typeIndex++)
            {
                if (linkedCurve->type == types[typeIndex])
                {
                    candidates[candidateCount++] = curve->linkIds[linkIndex];
                    typeIndex = typeCount;
                }
            }
        }
    }
    if (candidateCount == 0)
    {
        return -1;
    }
    if (candidateCount == 1)
    {
        *previousLinkId = curve->id;
        return candidates[0];
    }
    if (candidateCount > 1)
    {
        for (j = 0; j < candidateCount; j++)
        {
            if (*previousLinkId == candidates[j])
            {
                for (; j < candidateCount - 1; j++)
                {
                    candidates[j] = candidates[j + 1];
                }
                candidateCount--;
            }
        }
        *previousLinkId = curve->id;
        return candidates[randomGetRange(0, candidateCount - 1)];
    }
    return -1;
}

f32 curves_distXZ(f32 x, f32 z, u32 curveId)
{
    RomCurveDef* curve;
    f32 dx;
    f32 dz;

    curve = RomCurve_FindByIdInline(curveId);
    if (curve != NULL)
    {
        dx = curve->x - x;
        dz = curve->z - z;
        return sqrtf(dx * dx + dz * dz);
    }

    return gFloatNegOne;
}

f32 curves_distFn0B(int obj, u32 curveId)
{
    RomCurveDef* curve;
    f32 dx;
    f32 dy;
    f32 dz;

    curve = RomCurve_FindByIdInline(curveId);
    if (curve != NULL && (void*)obj != NULL)
    {
        dx = curve->x - ((GameObject*)obj)->anim.localPosX;
        dy = curve->y - ((GameObject*)obj)->anim.localPosY;
        dz = curve->z - ((GameObject*)obj)->anim.localPosZ;
        return sqrtf(dx * dx + dy * dy + dz * dz);
    }

    return gFloatNegOne;
}

int curves_isNotPoint(RomCurveDef* curve)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if ((s32)curve->linkIds[i] != -1 &&
            (curve->blockedLinkMask & (1 << i)) == 0)
        {
            return 0;
        }
    }
    return 1;
}

int curves_isPoint(RomCurveDef* curve)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if ((s32)curve->linkIds[i] != -1 &&
            (curve->blockedLinkMask & (1 << i)) != 0)
        {
            return 0;
        }
    }
    return 1;
}

f32 curves_find(int type, int action, f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ)
{
    RomCurveDef* curve;
    RomCurveDef* linkedCurve;
    int curveIndex;
    int linkIndex;
    int high;
    int low;
    int mid;
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
    zero = gFloatZero;
    *outZ = zero;
    *outY = zero;
    *outX = zero;
    bestDistance = lbl_803E0644;
    for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++)
    {
        curve = romCurves[curveIndex];
        if ((curve->action == action) && (curve->type == type))
        {
            segment.startX = curve->x;
            segment.startY = curve->y;
            segment.startZ = curve->z;
            for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++)
            {
                if (((s32)curve->blockedLinkMask & (1 << linkIndex)) == 0)
                {
                    linkId = curve->linkIds[linkIndex];
                    linkedCurve = RomCurve_FindByIdInline(linkId);

                    if (linkedCurve != NULL)
                    {
                        segment.endX = linkedCurve->x;
                        segment.endY = linkedCurve->y;
                        segment.endZ = linkedCurve->z;
                        distance = RomCurve_distanceToSegment(pointX, pointY, pointZ, &segment);
                        absBestDistance = (bestDistance < *(f32*)&gFloatZero) ? -bestDistance : bestDistance;
                        absDistance = (distance < gFloatZero) ? -distance : distance;
                        if (absDistance < absBestDistance)
                        {
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

RomCurveDef* RomCurve_findByIdWithIndex(u32 curveId, int* outIndex)
{
    int high;
    int low;
    int mid;

    *outIndex = -1;
    if ((int)curveId < 0)
    {
        return NULL;
    }
    high = nRomCurves + -1;
    low = 0;
    while (high >= low)
    {
        mid = high + low >> 1;
        if (curveId > RomCurve_GetId(romCurves[mid]))
        {
            low = mid + 1;
        }
        else if (curveId < RomCurve_GetId(romCurves[mid]))
        {
            high = mid + -1;
        }
        else
        {
            *outIndex = mid;
            return romCurves[mid];
        }
    }
    *outIndex = -1;
    return NULL;
}

#define ROMCURVE_PLACEMENT_ANGLE(v) ((gRomCurveAnglePi2 * (f32)((s32)(v) << 8)) / lbl_803E0618)

static inline int RomCurve_noUnblockedLinks(RomCurvePlacementDef* curve)
{
    int bit;
    u32* lp = curve->base.linkIds;

    for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++)
    {
        if ((s32)*lp++ != -1 && (curve->base.blockedLinkMask & (1 << bit)) == 0)
        {
            return 0;
        }
    }
    return 1;
}

static inline int RomCurve_noBlockedLinks(RomCurvePlacementDef* curve)
{
    int bit;
    u32* lp = curve->base.linkIds;

    for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++)
    {
        if ((s32)*lp++ != -1 && (curve->base.blockedLinkMask & (1 << bit)) != 0)
        {
            return 0;
        }
    }
    return 1;
}

#pragma opt_propagation off
int RomCurve_func20(RomCurvePlacementDef* curve, f32* outX, f32* outY, f32* outZ, s8* outTypes)
{
    extern float mathCosf(float x); /* #57 */
    extern float mathSinf(float x); /* #57 */
    u32 mask;
    u32* lp;
    RomCurvePlacementDef* next;
    int done;
    int n;
    int mA;
    int mB;
    int count;
    int link;
    int id;
    int i;
    int idsB[ROMCURVE_LINK_COUNT];
    int idsA[ROMCURVE_LINK_COUNT];

    done = RomCurve_noUnblockedLinks(curve) ? 1 : 0;
    n = 0;
    mA = 0;
    mB = 0;
    if (!done)
    {
        while (curve != NULL && !RomCurve_noUnblockedLinks(curve))
        {
            count = 0;
            mask = 1;
            lp = curve->base.linkIds;
            for (i = 0; i < ROMCURVE_LINK_COUNT; i++)
            {
                link = *lp++;
                if ((-1 < link) && ((curve->base.blockedLinkMask & mask) == 0) && (link != 0))
                {
                    idsB[count++] = link;
                }
                mask = mask << 1;
            }
            if (count != 0)
            {
                id = idsB[randomGetRange(0, count - 1)];
            }
            else
            {
                id = -1;
            }
            next = (RomCurvePlacementDef*)RomCurve_FindByIdInline(id);
            if (next != NULL)
            {
                if (outTypes != NULL)
                {
                    outTypes[n >> 2] = curve->base.type;
                }
                outX[mB] = curve->base.x;
                outY[mB] = curve->base.y;
                outZ[mB++] = curve->base.z;
                outX[mB] = next->base.x;
                outY[mB] = next->base.y;
                outZ[mB++] = next->base.z;
                n += 2;
                outX[mB] = lbl_803E0610 * ((f32)curve->rotX * mathSinf(ROMCURVE_PLACEMENT_ANGLE(curve->rotZ)));
                outY[mB] = lbl_803E0610 * ((f32)curve->rotX * mathSinf(ROMCURVE_PLACEMENT_ANGLE(curve->rotY)));
                outZ[n++] = lbl_803E0610 * ((f32)curve->rotX * mathCosf(ROMCURVE_PLACEMENT_ANGLE(curve->rotZ)));
                mB++;
                outX[mB] = lbl_803E0610 * ((f32)next->rotX * mathSinf(ROMCURVE_PLACEMENT_ANGLE(next->rotZ)));
                outY[mB] = lbl_803E0610 * ((f32)next->rotX * mathSinf(ROMCURVE_PLACEMENT_ANGLE(next->rotY)));
                outZ[n++] = lbl_803E0610 * ((f32)next->rotX * mathCosf(ROMCURVE_PLACEMENT_ANGLE(next->rotZ)));
                mB++;
            }
            curve = next;
        }
    }
    else
    {
        while (curve != NULL && !RomCurve_noBlockedLinks(curve))
        {
            count = 0;
            mask = 1;
            lp = curve->base.linkIds;
            for (i = 0; i < ROMCURVE_LINK_COUNT; i++)
            {
                link = *lp++;
                if ((-1 < link) && ((curve->base.blockedLinkMask & mask) != 0) && (link != 0))
                {
                    idsA[count++] = link;
                }
                mask = mask << 1;
            }
            if (count != 0)
            {
                id = idsA[randomGetRange(0, count - 1)];
            }
            else
            {
                id = -1;
            }
            next = (RomCurvePlacementDef*)RomCurve_FindByIdInline(id);
            if (next != NULL)
            {
                if (outTypes != NULL)
                {
                    outTypes[n >> 2] = curve->base.type;
                }
                outX[mA] = curve->base.x;
                outY[mA] = curve->base.y;
                outZ[mA++] = curve->base.z;
                outX[mA] = next->base.x;
                outY[mA] = next->base.y;
                outZ[mA++] = next->base.z;
                n += 2;
                outX[mA] = lbl_803E0610 * ((f32)curve->rotX * mathSinf(ROMCURVE_PLACEMENT_ANGLE(curve->rotZ)));
                outY[mA] = lbl_803E0610 * ((f32)curve->rotX * mathSinf(ROMCURVE_PLACEMENT_ANGLE(curve->rotY)));
                outZ[n++] = lbl_803E0610 * ((f32)curve->rotX * mathCosf(ROMCURVE_PLACEMENT_ANGLE(curve->rotZ)));
                mA++;
                outX[mA] = lbl_803E0610 * ((f32)next->rotX * mathSinf(ROMCURVE_PLACEMENT_ANGLE(next->rotZ)));
                outY[mA] = lbl_803E0610 * ((f32)next->rotX * mathSinf(ROMCURVE_PLACEMENT_ANGLE(next->rotY)));
                outZ[n++] = lbl_803E0610 * ((f32)next->rotX * mathCosf(ROMCURVE_PLACEMENT_ANGLE(next->rotZ)));
                mA++;
            }
            curve = next;
        }
    }
    return n;
}

#pragma opt_propagation reset
int RomCurve_countRandomPoints(RomCurveDef* curve)
{
    u32 mask;
    int linkCount;
    int link;
    int count;
    int id;
    int i;
    int ids[ROMCURVE_LINK_COUNT];

    count = 1;
    while (curve != NULL && !RomCurve_noUnblockedLinks((RomCurvePlacementDef*)curve))
    {
        linkCount = RomCurve_CollectUnblockedLinks(curve, ids);
        if (linkCount != 0)
        {
            id = ids[randomGetRange(0, linkCount - 1)];
        }
        else
        {
            id = -1;
        }
        curve = RomCurve_FindByIdInline(id);
        if (curve != NULL)
        {
            count++;
        }
    }
    return count;
}

int RomCurve_func1E(u32* curveIds, float* outX, float* outY, float* outZ)
{
    u32* idCursor;
    RomCurveDef** windowCursor;
    float* outXStart;
    float* outXCursor;
    float* outYCursor;
    float* outZCursor;
    int low;
    int mid;
    int high;
    RomCurveDef* resolvedCurve;
    RomCurveDef** resolveCursor;
    RomCurveDef* reloaded;
    int foundCount;
    u32 curveId;
    int remaining;
    RomCurveDef* windowCurves[4];

    foundCount = 0;
    idCursor = curveIds;
    resolveCursor = windowCurves;
    windowCursor = resolveCursor;
    outXStart = outX;
    outXCursor = outX;
    outYCursor = outY;
    outZCursor = outZ;
    remaining = 4;
    for (remaining = 4; remaining != 0; remaining--)
    {
        curveId = *idCursor;
        resolvedCurve = RomCurve_FindByIdInline(curveId);
        *windowCursor = resolvedCurve;
        reloaded = *windowCursor;
        if (reloaded != NULL)
        {
            *outXCursor = reloaded->x;
            *outYCursor = reloaded->y;
            *outZCursor = reloaded->z;
            foundCount = foundCount + 1;
        }
        idCursor++;
        windowCursor = windowCursor + 1;
        outXCursor++;
        outYCursor = outYCursor + 1;
        outZCursor = outZCursor + 1;
    }

    if (((foundCount < 2) || (windowCurves[1] == NULL)) || (windowCurves[2] == NULL))
    {
        return 0;
    }

    for (foundCount = 0, remaining = 4; remaining != 0; remaining--)
    {
        if (*resolveCursor == NULL)
        {
            if (foundCount == 0)
            {
                *outXStart = windowCurves[1]->x + (windowCurves[1]->x - windowCurves[2]->x);
                *outY = windowCurves[1]->y + (windowCurves[1]->y - windowCurves[2]->y);
                *outZ = windowCurves[1]->z + (windowCurves[1]->z - windowCurves[2]->z);
            }
            else if (foundCount == 3)
            {
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

void RomCurve_getAdjacentWindow(RomCurveDef* curve, int* outIds)
{
    int linkId;
    int adjacentId;
    int low;
    int high;
    int mid;
    int i;
    RomCurveDef* adjacent;

    outIds[0] = ROMCURVE_LINK_ID_NONE;
    outIds[1] = ROMCURVE_LINK_ID_NONE;
    outIds[2] = ROMCURVE_LINK_ID_NONE;
    outIds[3] = ROMCURVE_LINK_ID_NONE;
    if (curve == NULL)
    {
        return;
    }

    outIds[1] = curve->id;
    for (i = 0; i < ROMCURVE_LINK_COUNT; i++)
    {
        linkId = curve->linkIds[i];
        if (linkId != (int)ROMCURVE_LINK_ID_NONE)
        {
            if ((curve->blockedLinkMask & (1 << i)) != 0)
            {
                outIds[0] = linkId;
            }
            else if ((curve->blockedLinkMask & (1 << i)) == 0)
            {
                outIds[2] = linkId;
            }
        }
    }

    adjacentId = outIds[2];
    if (adjacentId <= -1)
    {
        return;
    }
    adjacent = RomCurve_FindByIdInline(adjacentId);

    if (adjacent == NULL)
    {
        return;
    }

    for (i = 0; i < ROMCURVE_LINK_COUNT; i++)
    {
        linkId = adjacent->linkIds[i];
        if (linkId != (int)ROMCURVE_LINK_ID_NONE)
        {
            if ((adjacent->blockedLinkMask & (1 << i)) == 0)
            {
                outIds[3] = linkId;
            }
        }
    }
}

int RomCurve_getNearestAdjacentLink(RomCurveDef* curve, int excludeLinkId, f32 x, f32 y, f32 z)
{
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
    int low;
    int high;
    int mid;
    RomCurveDef* linkedCurve;

    bestLink[1] = ROMCURVE_LINK_ID_NONE;
    bestLink[0] = ROMCURVE_LINK_ID_NONE;
    bestDistance[1] = gFloatZero;
    bestDistance[0] = gFloatZero;
    segment.startX = curve->x;
    segment.startY = curve->y;
    segment.startZ = curve->z;

    for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++)
    {
        linkId = curve->linkIds[linkIndex];
        if ((s32)linkId > -1)
        {
            linkedCurve = RomCurve_FindByIdInline(linkId);

            if (linkedCurve != NULL)
            {
                segment.endX = linkedCurve->x;
                segment.endY = linkedCurve->y;
                segment.endZ = linkedCurve->z;
                RomCurve_distanceToSegment(x, y, z, &segment);
                dx = segment.nearestX - x;
                dy = segment.nearestY - y;
                dz = segment.nearestZ - z;
                distance = dx * dx + dy * dy + dz * dz;
                slot = (u32)__cntlzw(excludeLinkId - linkId) >> 5;
                if (distance > bestDistance[slot])
                {
                    bestDistance[slot] = distance;
                    bestLink[slot] = curve->linkIds[linkIndex];
                }
            }
        }
    }

    if (bestLink[0] != (int)ROMCURVE_LINK_ID_NONE)
    {
        return bestLink[0];
    }
    if (bestLink[1] != (int)ROMCURVE_LINK_ID_NONE)
    {
        return bestLink[1];
    }
    return ROMCURVE_LINK_ID_NONE;
}

f32 RomCurve_distanceToSegment(f32 x, f32 y, f32 z, RomCurveSegmentProjection* segment)
{
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
    if (((gFloatZero == deltaX) && (gFloatZero == deltaY)) && (gFloatZero == deltaZ))
    {
        projection = gFloatZero;
    }
    else
    {
        projection = (deltaX * (x - startX) + deltaY * (y - startY) + deltaZ * (z - startZ)) /
            (deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ);
    }
    if (projection < *(f32 *)&gFloatZero)
    {
        nearestX = startX;
        nearestY = startY;
        nearestZ = startZ;
        distance = -((startZ - z) * (startZ - z) +
            ((startX - x) * (startX - x) + (startY - y) * (startY - y)));
    }
    else if (projection > gFloatOne)
    {
        nearestX = endX;
        nearestY = endY;
        nearestZ = endZ;
        distance = -((endZ - z) * (endZ - z) +
            ((endX - x) * (endX - x) + (endY - y) * (endY - y)));
    }
    else
    {
        nearestX = projection * deltaX + startX;
        nearestY = projection * deltaY + startY;
        nearestZ = projection * deltaZ + startZ;
        distance = (nearestZ - z) * (nearestZ - z) +
            ((nearestX - x) * (nearestX - x) + (nearestY - y) * (nearestY - y));
    }
    segment->nearestX = nearestX;
    segment->nearestY = nearestY;
    segment->nearestZ = nearestZ;
    return distance;
}

int RomCurve_getRandomBlockedLink(RomCurveDef* curve, int excludeLinkId)
{
    int link;
    int count;
    u32 mask;
    int i;
    int result;
    int eligibleLinks[ROMCURVE_LINK_COUNT];

    count = 0;
    mask = 1;

    for (i = 0; i < ROMCURVE_LINK_COUNT; i = i + 1)
    {
        link = curve->linkIds[i];
        if ((-1 < link) && ((curve->blockedLinkMask & mask) != 0) && (link != excludeLinkId))
        {
            eligibleLinks[count++] = link;
        }
        mask = mask << 1;
    }

    if (count != 0)
    {
        result = eligibleLinks[randomGetRange(0, count - 1)];
    }
    else
    {
        result = -1;
    }
    return result;
}

int RomCurve_getLinkIds(RomCurveDef* curve, int excludeLinkId, int* outIds)
{
    int linkId;
    int count;
    int i;

    count = 0;
    for (i = 0; i < 4; i++)
    {
        linkId = curve->linkIds[i];
        if (RomCurve_IsLinkIdValid(linkId) && linkId != excludeLinkId)
        {
            outIds[count++] = linkId;
        }
    }
    return count;
}

int RomCurve_getRandomUnblockedLink(RomCurveDef* curve, int excludeLinkId)
{
    int link;
    int count;
    u32 mask;
    int i;
    int result;
    int eligibleLinks[ROMCURVE_LINK_COUNT];

    count = 0;
    mask = 1;

    for (i = 0; i < ROMCURVE_LINK_COUNT; i = i + 1)
    {
        link = curve->linkIds[i];
        if ((-1 < link) && ((curve->blockedLinkMask & mask) == 0) && (link != excludeLinkId))
        {
            eligibleLinks[count++] = link;
        }
        mask = mask << 1;
    }

    if (count != 0)
    {
        result = eligibleLinks[randomGetRange(0, count - 1)];
    }
    else
    {
        result = -1;
    }
    return result;
}

RomCurveDef* RomCurve_getById(u32 curveId)
{
    int high;
    int low;
    int mid;

    if ((int)curveId < 0)
    {
        return 0;
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
            return (RomCurveDef*)romCurves[mid];
        }
    }
    return 0;
}

int RomCurve_find(int* types, int typeCount, f32 x, f32 y, f32 z, int action)
{
    int curveIndex;
    int typeIndex;
    RomCurveDef* curve;
    RomCurveDef* bestCurve;
    RomCurveDef* bestActionCurve;
    f32 bestDistance;
    f32 bestActionDistance;
    f32 distance;
    f32 point[3];

    bestDistance = gRomCurveFindDistInit;
    bestCurve = NULL;
    bestActionDistance = bestDistance;
    bestActionCurve = NULL;
    point[0] = x;
    point[1] = y;
    point[2] = z;
    for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++)
    {
        curve = romCurves[curveIndex];
        typeIndex = 0;
        do
        {
            if ((typeCount <= 0) || (curve->type == types[typeIndex]))
            {
                distance = vec3f_distanceSquared(point, &curve->x);
                if (distance < bestDistance)
                {
                    bestDistance = distance;
                    bestCurve = curve;
                }
                if ((curve->action == action) && (distance < bestActionDistance))
                {
                    bestActionDistance = distance;
                    bestActionCurve = curve;
                }
                typeIndex = typeCount;
            }
            typeIndex++;
        }
        while (typeIndex < typeCount);
    }
    if (bestActionCurve != NULL)
    {
        bestCurve = bestActionCurve;
    }
    if (bestCurve != NULL)
    {
        return bestCurve->id;
    }
    return -1;
}

void curves_remove(RomCurveDef* curve)
{
    RomCurveDef** tableSlot;
    int sortedCurveCount;
    int removeIndex;

    removeIndex = 0;
    while ((removeIndex < nRomCurves) &&
        (curve->id != romCurves[removeIndex]->id))
    {
        removeIndex = removeIndex + 1;
    }

    sortedCurveCount = nRomCurves;
    if (removeIndex >= sortedCurveCount)
    {
        return;
    }

    nRomCurves = nRomCurves - 1;
    sortedCurveCount = nRomCurves;
    tableSlot = romCurves + removeIndex;
    for (; removeIndex < sortedCurveCount; removeIndex++)
    {
        tableSlot[0] = tableSlot[1];
        tableSlot = tableSlot + 1;
    }
}

/*
 * Retail source-tag string: Hcurves.c: MAX_ROMCURVES exceeded!!
 */
void curves_addCurveDef(RomCurveDef* curve)
{
    int sortedCurveCount;
    RomCurveDef** tailSlot;
    int insertIndex;

    sortedCurveCount = nRomCurves;
    if (sortedCurveCount == ROMCURVE_MAX_CURVES)
    {
        OSReport(sCurvesMaxRomCurvesExceeded);
        return;
    }

    insertIndex = 0;
    while ((insertIndex < sortedCurveCount) && (curve->id > romCurves[insertIndex]->id))
    {
        insertIndex++;
    }

    for (tailSlot = romCurves + sortedCurveCount; insertIndex < sortedCurveCount;
         sortedCurveCount--)
    {
        tailSlot[0] = tailSlot[-1];
        tailSlot--;
    }

    nRomCurves++;
    romCurves[insertIndex] = curve;
}

#pragma dont_inline on
#pragma dont_inline reset

void curves_release(void)
{
}

void RomCurve_initialise(void)
{
}

void curves_initialise(void) { nRomCurves = 0x0; }

void RomCurve_func0D(RomCurveDef** startOut, RomCurveDef** endOut)
{
    *startOut = gRomCurveLastFindStart;
    *endOut = gRomCurveLastFindEnd;
}

void* RomCurve_getCurves(int* outCount)
{
    *outCount = nRomCurves;
    return romCurves;
}

int curves_findByAction(int act)
{
    int i;

    for (i = 0; i < nRomCurves; i++)
    {
        RomCurveDef* c = romCurves[i];
        if (c->type == ROMCURVE_TYPE_ACTION)
        {
            if (c->action == act)
            {
                return c->id;
            }
        }
    }
    return -1;
}

/* RomCurve_segmentIntersectsOriginRayXZ: 2D segment-intersection predicate.
 * Returns 1 if the segment between (x, z) and the origin in the xz-plane
 * crosses the segment between a and b. */
#pragma opt_common_subs off
int RomCurve_segmentIntersectsOriginRayXZ(f32 x, f32 unusedY, f32 z, RomCurveDef* a,
                                          RomCurveDef* b, f32 unusedW)
{
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
    if ((sum1 <= gFloatZero && cross1 >= gFloatZero) ||
        (sum1 >= gFloatZero && cross1 < gFloatZero))
    {
        f32 cross_a = -z * ax + x * az;
        f32 cross_b = -z * bx + x * bz;
        if ((cross_a <= gFloatZero && cross_b >= gFloatZero) ||
            (cross_a >= gFloatZero && cross_b < gFloatZero))
        {
            return 1;
        }
    }
    return 0;
}
#pragma opt_common_subs reset

char sObjfsaMissingPatchExitPoint0[] = "Unable to find exit point 0 on patch between walkgroup %d and %d\n";
char sObjfsaMissingPatchExitPoint1[] = "Unable to find exit point 1 on patch between walkgroup %d and %d\n";

char sObjfsaFoundNewWalkGroupPatch[] = "Found new walk group patch from walkgroup %d\n";
char sObjfsaIsPointWithinPatchGroupError[] = "Error in isPointWithinPatchGroup\n";

void* lbl_803115F8[49] = {
    (void*)0,
    (void*)0,
    (void*)0,
    (void*)0x2C0000,
    (void*)RomCurve_initialise,
    (void*)curves_release,
    (void*)0,
    (void*)curves_initialise,
    (void*)curves_addCurveDef,
    (void*)curves_remove,
    (void*)RomCurve_getCurves,
    (void*)RomCurve_find,
    (void*)curves_findNearObj,
    (void*)RomCurve_getById,
    (void*)curves_find,
    (void*)curves_distFn0B,
    (void*)curves_distXZ,
    (void*)RomCurve_func0D,
    (void*)curves_isPoint,
    (void*)curves_isNotPoint,
    (void*)RomCurve_getRandomLinkedOfTypes,
    (void*)RomCurve_func11,
    (void*)curves_findByAction,
    (void*)RomCurve_func13,
    (void*)curves_distanceToNearestOfType16,
    (void*)curves_distFn15,
    (void*)RomCurve_func16,
    (void*)RomCurve_getRandomUnblockedLink,
    (void*)RomCurve_getLinkIds,
    (void*)RomCurve_getNearestAdjacentLink,
    (void*)RomCurve_getRandomBlockedLink,
    (void*)RomCurve_func1B,
    (void*)RomCurve_func1C,
    (void*)RomCurve_getAdjacentWindow,
    (void*)RomCurve_func1E,
    (void*)RomCurve_countRandomPoints,
    (void*)RomCurve_func20,
    (void*)RomCurve_projectPointToAdjacentWindow,
    (void*)RomCurve_findProjectedCurveFromStart,
    (void*)curves_getPos,
    (void*)curves_lengthFn24,
    (void*)RomCurve_get,
    (void*)RomCurve_goNextPoint,
    (void*)RomCurve_setClosed,
    (void*)RomCurve_setA4,
    (void*)RomCurve_func29,
    (void*)RomCurve_getControlPointId_2A,
    (void*)RomCurve_getControlPointId_2B,
    (void*)RomCurve_func2C
};
char sCurvesMaxRomCurvesExceeded[36] = "curves.c: MAX_ROMCURVES exceeded!!\n\000";
