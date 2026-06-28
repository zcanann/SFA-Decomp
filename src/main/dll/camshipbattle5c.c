/*
 * Path-camera ROM-curve sampling helpers (DLL 0x5B / camshipbattle5C
 * family, sibling of dll_8010a104.c). Operates on the ROM curve-node
 * graph reached through gRomCurveInterface->getById.
 *
 * Each curve node holds a world position (f32 x/y/z at +0x08/+0x0C/+0x10),
 * a packed rotation/fov sample (s16 at +0x34/+0x36/+0x38, s8 at +0x3A),
 * a self id (+0x14), up to five neighbour ids (int[5] at +0x1C), a
 * direction bitmask (+0x1B) splitting neighbours into forward/backward
 * links, and three path-tag bytes (+0x31..+0x33) used to keep a walk on
 * the path picked by `tag`.
 *
 * pathcam_findTaggedNodeWindow resolves the four-node window (prev,
 * cur, next, next-next) around a node along the tagged path.
 * pathcam_buildWindowSamples gathers the per-node samples for that
 * window, extrapolating the missing end nodes and unwrapping angle
 * deltas that cross the +/- bound. fn_8010AC48 returns the normalised
 * position of (px,pz) along the segment between the two midpoint planes
 * of the window.
 */
#include "main/dll/CAM/camshipbattle5C.h"
#include "main/dll/rom_curve_interface.h"
#include "main/engine_shared.h"
extern f32 lbl_803E1890; /* angle delta upper bound */
extern f32 lbl_803E1894; /* angle delta lower bound */
extern f32 lbl_803E1898; /* angle unwrap step */
extern f32 lbl_803E1888; /* angle near/zero threshold */
extern char sPathCamNeedTwoControlPointsError[];


extern f32 lbl_803E18A8; /* midpoint factor (segment normal averaging) */

/* curve-node field offsets (raw walking-pointer accesses below) */
#define NODE_SELF_ID 0x14
#define NODE_DIR_MASK 0x1B
#define NODE_NEIGHBOURS 0x1C
#define NODE_TAG0 0x31
#define NODE_TAG1 0x32
#define NODE_TAG2 0x33

/*
 * A single ROM curve-node as returned by gRomCurveInterface->getById.
 * Single-owner layout for this unit (and its sibling dll_8010a104.c,
 * which still uses raw offsets). Only the fields touched here are named.
 */
typedef struct RomCurveNode {
    /* 0x00 */ u8 pad00[0x08];
    /* 0x08 */ f32 x;
    /* 0x0C */ f32 y;
    /* 0x10 */ f32 z;
    /* 0x14 */ int selfId;
    /* 0x18 */ u8 pad18[0x03];
    /* 0x1B */ u8 dirMask;
    /* 0x1C */ int neighbours[5];
    /* 0x30 */ u8 pad30;
    /* 0x31 */ u8 tag0;
    /* 0x32 */ u8 tag1;
    /* 0x33 */ u8 tag2;
    /* 0x34 */ s16 sampleA;
    /* 0x36 */ s16 sampleB;
    /* 0x38 */ s16 sampleC;
    /* 0x3A */ s8 sampleD;
} RomCurveNode;

STATIC_ASSERT(offsetof(RomCurveNode, x) == 0x08);
STATIC_ASSERT(offsetof(RomCurveNode, y) == 0x0C);
STATIC_ASSERT(offsetof(RomCurveNode, z) == 0x10);
STATIC_ASSERT(offsetof(RomCurveNode, selfId) == 0x14);
STATIC_ASSERT(offsetof(RomCurveNode, dirMask) == 0x1B);
STATIC_ASSERT(offsetof(RomCurveNode, neighbours) == 0x1C);
STATIC_ASSERT(offsetof(RomCurveNode, tag0) == 0x31);
STATIC_ASSERT(offsetof(RomCurveNode, tag1) == 0x32);
STATIC_ASSERT(offsetof(RomCurveNode, tag2) == 0x33);
STATIC_ASSERT(offsetof(RomCurveNode, sampleA) == 0x34);
STATIC_ASSERT(offsetof(RomCurveNode, sampleB) == 0x36);
STATIC_ASSERT(offsetof(RomCurveNode, sampleC) == 0x38);
STATIC_ASSERT(offsetof(RomCurveNode, sampleD) == 0x3A);

#pragma opt_common_subs off
#pragma ppc_unroll_factor_limit 1
void pathcam_buildWindowSamples(int* nodes, f32* o1, f32* o2, f32* o3, f32* o4,
                                f32* o5, f32* o6, f32* o7)
{
    f32* wp;
    int* np;
    f32 *w1, *w2, *w3, *w4, *w5, *w6, *w7;
    RomCurveNode** ppNode;
    f32 *q1, *q2, *q3, *q4, *q5, *q6, *q7;
    RomCurveNode* node;
    int j;
    RomCurveNode** pwNode;
    int i;
    int step;
    f32* axisOut;
    int axis;
    f32 wrap, d, near, lower, upper, v0, v1;
    RomCurveNode* pts[4];

    i = 0;
    np = nodes;
    pwNode = pts;
    ppNode = pwNode;
    q1 = o1;
    q2 = o2;
    q3 = o3;
    q4 = o4;
    q5 = o5;
    q6 = o6;
    q7 = o7;
    for (; i < 4; i++)
    {
        *ppNode = (RomCurveNode*)(*gRomCurveInterface)->getById(*np);
        node = *ppNode;
        if (node != NULL)
        {
            *q1 = node->x;
            *q2 = node->y;
            *q3 = node->z;
            *q4 = (f32)node->sampleA;
            *q5 = (f32)node->sampleB;
            *q6 = (f32)node->sampleC;
            *q7 = (f32)node->sampleD;
        }
        np++;
        ppNode++;
        q1++;
        q2++;
        q3++;
        q4++;
        q5++;
        q6++;
        q7++;
    }

    if (pts[1] == NULL || pts[2] == NULL)
    {
        return;
    }
    {
        j = 0;
        w1 = o1;
        w2 = o2;
        w3 = o3;
        w4 = o4;
        w5 = o5;
        w6 = o6;
        w7 = o7;
        for (; j < 4; j++)
        {
            if (*pwNode == NULL)
            {
                if (j == 0)
                {
                    *w1 = pts[1]->x + (pts[1]->x - pts[2]->x);
                    *w2 = pts[1]->y + (pts[1]->y - pts[2]->y);
                    *w3 = pts[1]->z + (pts[1]->z - pts[2]->z);
                    *w4 = (f32)(pts[1]->sampleA + (pts[1]->sampleA - pts[2]->sampleA));
                    *w5 = (f32)(pts[1]->sampleB + (pts[1]->sampleB - pts[2]->sampleB));
                    *w6 = (f32)(pts[1]->sampleC + (pts[1]->sampleC - pts[2]->sampleC));
                    *w7 = (f32)pts[1]->sampleD +
                        ((f32)pts[1]->sampleD - (f32)pts[2]->sampleD);
                }
                else if (j == 3)
                {
                    *w1 = pts[2]->x + (pts[2]->x - pts[1]->x);
                    *w2 = pts[2]->y + (pts[2]->y - pts[1]->y);
                    *w3 = pts[2]->z + (pts[2]->z - pts[1]->z);
                    *w4 = (f32)(pts[2]->sampleA + (pts[2]->sampleA - pts[1]->sampleA));
                    *w5 = (f32)(pts[2]->sampleB + (pts[2]->sampleB - pts[1]->sampleB));
                    *w6 = (f32)(pts[2]->sampleC + (pts[2]->sampleC - pts[1]->sampleC));
                    *w7 = (f32)pts[2]->sampleD +
                        ((f32)pts[2]->sampleD - (f32)pts[1]->sampleD);
                }
            }
            pwNode++;
            w1++;
            w2++;
            w3++;
            w4++;
            w5++;
            w6++;
            w7++;
        }

        axis = 0;
        do
        {
            if (axis == 0)
            {
                axisOut = o4;
            }
            else if (axis == 1)
            {
                axisOut = o5;
            }
            else
            {
                axisOut = o6;
            }
            if (axisOut != NULL)
            {
                wp = axisOut;
                upper = lbl_803E1890;
                for (step = 0; step < 3; step++)
                {
                    near = lbl_803E1888;
                    lower = lbl_803E1894;
                    wrap = lbl_803E1898;
                    v0 = wp[0];
                    v1 = wp[1];
                    d = v0 - v1;
                    if (d > upper || d < lower)
                    {
                        if (v0 < near)
                        {
                            wp[0] = wp[0] + wrap;
                        }
                        else if (v1 < near)
                        {
                            wp[1] = wp[1] + wrap;
                        }
                    }
                    wp++;
                }
            }
            axis++;
        }
        while (axis < 3);
    }
}
#pragma opt_common_subs on
#pragma ppc_unroll_factor_limit 4

void pathcam_findTaggedNodeWindow(u8* node, int* out, int tag)
{
    int i;
    u8* neighbour;
    int idx;
    int forward;

    out[0] = -1;
    out[1] = -1;
    out[2] = -1;
    out[3] = -1;

    if (node == NULL)
    {
        return;
    }

    out[1] = *(int*)(node + NODE_SELF_ID);

    i = 0;
    for (; i < 5; i++)
    {
        idx = *(int*)(node + i * 4 + NODE_NEIGHBOURS);
        if (idx > -1)
        {
            neighbour = (u8*)(*gRomCurveInterface)->getById(idx);
            if (neighbour != NULL)
            {
                if (neighbour[NODE_TAG0] == tag || neighbour[NODE_TAG1] == tag || neighbour[NODE_TAG2] == tag)
                {
                    forward = (s8)node[NODE_DIR_MASK] & (1 << i);
                    if (forward != 0)
                    {
                        out[0] = *(int*)(node + i * 4 + NODE_NEIGHBOURS);
                    }
                    else if (forward == 0)
                    {
                        out[2] = *(int*)(node + i * 4 + NODE_NEIGHBOURS);
                    }
                }
            }
        }
    }

    idx = out[2];
    if (idx > -1)
    {
        u8* node2 = (u8*)(*gRomCurveInterface)->getById(idx);
        if (node2 != NULL)
        {
            if (node2[NODE_TAG0] == tag || node2[NODE_TAG1] == tag || node2[NODE_TAG2] == tag)
            {
                i = 0;
                for (; i < 5; i++)
                {
                    idx = *(int*)(node2 + i * 4 + NODE_NEIGHBOURS);
                    if (idx > -1)
                    {
                        forward = (s8)node2[NODE_DIR_MASK] & (1 << i);
                        if (forward == 0)
                        {
                            neighbour = (u8*)(*gRomCurveInterface)->getById(idx);
                            if (neighbour != NULL)
                            {
                                if (neighbour[NODE_TAG0] == tag || neighbour[NODE_TAG1] == tag || neighbour[NODE_TAG2] == tag)
                                {
                                    out[3] = *(int*)(node2 + i * 4 + NODE_NEIGHBOURS);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (out[1] < 0 || out[2] < 0)
    {
        debugPrintf(sPathCamNeedTwoControlPointsError);
    }
}

f32 fn_8010AC48(int* obj, f32 px, f32 unused, f32 pz)
{
    RomCurveNode* pts[4];
    int* sp;
    RomCurveNode** dp;
    int i;
    f32 dx1;
    f32 dz1;
    f32 sx;
    f32 sz;
    f32 nsz;
    f32 nsx;
    f32 nx;
    f32 nz;
    f32 len;
    f32 t1;
    f32 t2;
    f32 negdot;
    for (i = 0, sp = obj, dp = pts; i < 4; i++)
    {
        *dp = (RomCurveNode*)(*gRomCurveInterface)->getById(*sp);
        sp++;
        dp++;
    }
    dx1 = pts[2]->x - pts[1]->x;
    dz1 = pts[2]->z - pts[1]->z;
    if (pts[0] != NULL)
    {
        sx = pts[1]->x - pts[0]->x;
        sz = pts[1]->z - pts[0]->z;
    }
    else
    {
        sx = dx1;
        sz = dz1;
    }
    nx = lbl_803E18A8 * (sx + dx1);
    nz = lbl_803E18A8 * (sz + dz1);
    len = sqrtf(nz * nz + nx * nx);
    if (0.0f != len)
    {
        nx = nx / len;
        nz = nz / len;
    }
    negdot = -(nz * pts[1]->z + nx * pts[1]->x);
    t1 = nx * dx1 + nz * dz1;
    if (0.0f != t1)
    {
        t1 = -(negdot + (nx * px + nz * pz)) / t1;
    }
    sx = pts[2]->x - pts[1]->x;
    sz = pts[2]->z - pts[1]->z;
    if (pts[3] != NULL)
    {
        nsx = pts[3]->x - pts[2]->x;
        nsz = pts[3]->z - pts[2]->z;
    }
    else
    {
        nsx = sx;
        nsz = sz;
    }
    nx = lbl_803E18A8 * (nsx + sx);
    nz = lbl_803E18A8 * (nsz + sz);
    len = sqrtf(nx * nx + nz * nz);
    if (0.0f != len)
    {
        nx = nx / len;
        nz = nz / len;
    }
    negdot = -(nx * pts[2]->x + nz * pts[2]->z);
    t2 = nx * dx1 + nz * dz1;
    if (0.0f != t2)
    {
        t2 = -(negdot + (nx * px + nz * pz)) / t2;
    }
    return -t1 / (t2 - t1);
}
