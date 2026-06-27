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

/* curve-node field offsets used below */
#define NODE_POS_X 0x08
#define NODE_POS_Y 0x0C
#define NODE_POS_Z 0x10
#define NODE_SELF_ID 0x14
#define NODE_DIR_MASK 0x1B
#define NODE_NEIGHBOURS 0x1C
#define NODE_SAMPLE_A 0x34
#define NODE_SAMPLE_B 0x36
#define NODE_SAMPLE_C 0x38
#define NODE_SAMPLE_D 0x3A
#define NODE_TAG0 0x31
#define NODE_TAG1 0x32
#define NODE_TAG2 0x33

#pragma opt_common_subs off
#pragma ppc_unroll_factor_limit 1
void pathcam_buildWindowSamples(int* nodes, f32* o1, f32* o2, f32* o3, f32* o4,
                                f32* o5, f32* o6, f32* o7)
{
    f32* wp;
    int* np;
    f32 *w1, *w2, *w3, *w4, *w5, *w6, *w7;
    u8** ppNode;
    f32 *q1, *q2, *q3, *q4, *q5, *q6, *q7;
    u8* node;
    int j;
    u8** pwNode;
    int i;
    int step;
    f32* axisOut;
    int axis;
    f32 wrap, d, near, lower, upper, v0, v1;
    u8* pts[4];

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
        *ppNode = (u8*)(*gRomCurveInterface)->getById(*np);
        node = *ppNode;
        if (node != NULL)
        {
            *q1 = *(f32*)(node + NODE_POS_X);
            *q2 = *(f32*)(node + NODE_POS_Y);
            *q3 = *(f32*)(node + NODE_POS_Z);
            *q4 = (f32) * (s16*)(node + NODE_SAMPLE_A);
            *q5 = (f32) * (s16*)(node + NODE_SAMPLE_B);
            *q6 = (f32) * (s16*)(node + NODE_SAMPLE_C);
            *q7 = (f32) * (s8*)(node + NODE_SAMPLE_D);
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
                    *w1 = *(f32*)(pts[1] + NODE_POS_X) + (*(f32*)(pts[1] + NODE_POS_X) - *(f32*)(pts[2] + NODE_POS_X));
                    *w2 = *(f32*)(pts[1] + NODE_POS_Y) + (*(f32*)(pts[1] + NODE_POS_Y) - *(f32*)(pts[2] + NODE_POS_Y));
                    *w3 = *(f32*)(pts[1] + NODE_POS_Z) + (*(f32*)(pts[1] + NODE_POS_Z) - *(f32*)(pts[2] + NODE_POS_Z));
                    *w4 = (f32)(*(s16*)(pts[1] + NODE_SAMPLE_A) + (*(s16*)(pts[1] + NODE_SAMPLE_A) - *(s16*)(pts[2] + NODE_SAMPLE_A)));
                    *w5 = (f32)(*(s16*)(pts[1] + NODE_SAMPLE_B) + (*(s16*)(pts[1] + NODE_SAMPLE_B) - *(s16*)(pts[2] + NODE_SAMPLE_B)));
                    *w6 = (f32)(*(s16*)(pts[1] + NODE_SAMPLE_C) + (*(s16*)(pts[1] + NODE_SAMPLE_C) - *(s16*)(pts[2] + NODE_SAMPLE_C)));
                    *w7 = (f32) * (s8*)(pts[1] + NODE_SAMPLE_D) +
                        ((f32) * (s8*)(pts[1] + NODE_SAMPLE_D) - (f32) * (s8*)(pts[2] + NODE_SAMPLE_D));
                }
                else if (j == 3)
                {
                    *w1 = *(f32*)(pts[2] + NODE_POS_X) + (*(f32*)(pts[2] + NODE_POS_X) - *(f32*)(pts[1] + NODE_POS_X));
                    *w2 = *(f32*)(pts[2] + NODE_POS_Y) + (*(f32*)(pts[2] + NODE_POS_Y) - *(f32*)(pts[1] + NODE_POS_Y));
                    *w3 = *(f32*)(pts[2] + NODE_POS_Z) + (*(f32*)(pts[2] + NODE_POS_Z) - *(f32*)(pts[1] + NODE_POS_Z));
                    *w4 = (f32)(*(s16*)(pts[2] + NODE_SAMPLE_A) + (*(s16*)(pts[2] + NODE_SAMPLE_A) - *(s16*)(pts[1] + NODE_SAMPLE_A)));
                    *w5 = (f32)(*(s16*)(pts[2] + NODE_SAMPLE_B) + (*(s16*)(pts[2] + NODE_SAMPLE_B) - *(s16*)(pts[1] + NODE_SAMPLE_B)));
                    *w6 = (f32)(*(s16*)(pts[2] + NODE_SAMPLE_C) + (*(s16*)(pts[2] + NODE_SAMPLE_C) - *(s16*)(pts[1] + NODE_SAMPLE_C)));
                    *w7 = (f32) * (s8*)(pts[2] + NODE_SAMPLE_D) +
                        ((f32) * (s8*)(pts[2] + NODE_SAMPLE_D) - (f32) * (s8*)(pts[1] + NODE_SAMPLE_D));
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
    int* pts[4];
    int* sp;
    int** dp;
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
        *dp = (int*)(*gRomCurveInterface)->getById(*sp);
        sp++;
        dp++;
    }
    dx1 = *(f32*)((char*)pts[2] + NODE_POS_X) - *(f32*)((char*)pts[1] + NODE_POS_X);
    dz1 = *(f32*)((char*)pts[2] + NODE_POS_Z) - *(f32*)((char*)pts[1] + NODE_POS_Z);
    if (pts[0] != NULL)
    {
        sx = *(f32*)((char*)pts[1] + NODE_POS_X) - *(f32*)((char*)pts[0] + NODE_POS_X);
        sz = *(f32*)((char*)pts[1] + NODE_POS_Z) - *(f32*)((char*)pts[0] + NODE_POS_Z);
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
    negdot = -(nz * *(f32*)((char*)pts[1] + NODE_POS_Z) + nx * *(f32*)((char*)pts[1] + NODE_POS_X));
    t1 = nx * dx1 + nz * dz1;
    if (0.0f != t1)
    {
        t1 = -(negdot + (nx * px + nz * pz)) / t1;
    }
    sx = *(f32*)((char*)pts[2] + NODE_POS_X) - *(f32*)((char*)pts[1] + NODE_POS_X);
    sz = *(f32*)((char*)pts[2] + NODE_POS_Z) - *(f32*)((char*)pts[1] + NODE_POS_Z);
    if (pts[3] != NULL)
    {
        nsx = *(f32*)((char*)pts[3] + NODE_POS_X) - *(f32*)((char*)pts[2] + NODE_POS_X);
        nsz = *(f32*)((char*)pts[3] + NODE_POS_Z) - *(f32*)((char*)pts[2] + NODE_POS_Z);
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
    negdot = -(nx * *(f32*)((char*)pts[2] + NODE_POS_X) + nz * *(f32*)((char*)pts[2] + NODE_POS_Z));
    t2 = nx * dx1 + nz * dz1;
    if (0.0f != t2)
    {
        t2 = -(negdot + (nx * px + nz * pz)) / t2;
    }
    return -t1 / (t2 - t1);
}
