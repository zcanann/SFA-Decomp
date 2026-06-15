#include "main/dll/CAM/camshipbattle5C.h"
#include "main/dll/rom_curve_interface.h"

extern f32 lbl_803E1890;
extern f32 lbl_803E1894;
extern f32 lbl_803E1898;
extern f32 lbl_803E1888;

extern char sPathCamNeedTwoControlPointsError[];
extern void debugPrintf(const char* fmt, ...);
extern float sqrtf(float x);
extern f32 lbl_803E18A8;

void pathcam_buildWindowSamples(int* nodes, f32* o1, f32* o2, f32* o3, f32* o4,
                                f32* o5, f32* o6, f32* o7)
{
    int i;
    u8** pw;
    u8** pp;
    f32 *q1, *q2, *q3, *q4, *q5, *q6, *q7;
    u8* p;
    int i2;
    f32 *w1, *w2, *w3, *w4, *w5, *w6, *w7;
    int k;
    int m;
    f32* sel;
    f32* wp;
    f32 t0, ta, tb, tc, v0, v1, d;
    u8* pts[4];

    i = 0;
    pw = pts;
    pp = pw;
    q1 = o1;
    q2 = o2;
    q3 = o3;
    q4 = o4;
    q5 = o5;
    q6 = o6;
    q7 = o7;
    for (; i < 4; i++)
    {
        *pp = (u8*)(*gRomCurveInterface)->getById(*nodes);
        p = *pp;
        if (p != NULL)
        {
            *q1 = *(f32*)(p + 8);
            *q2 = *(f32*)(p + 0xc);
            *q3 = *(f32*)(p + 0x10);
            *q4 = (f32) * (s16*)(p + 0x34);
            *q5 = (f32) * (s16*)(p + 0x36);
            *q6 = (f32) * (s16*)(p + 0x38);
            *q7 = (f32) * (s8*)(p + 0x3a);
        }
        nodes++;
        pp++;
        q1++;
        q2++;
        q3++;
        q4++;
        q5++;
        q6++;
        q7++;
    }

    if (pts[1] != NULL && pts[2] != NULL)
    {
        i2 = 0;
        w1 = o1;
        w2 = o2;
        w3 = o3;
        w4 = o4;
        w5 = o5;
        w6 = o6;
        w7 = o7;
        for (; i2 < 4; i2++)
        {
            if (*pw == NULL)
            {
                if (i2 == 0)
                {
                    *w1 = *(f32*)(pts[1] + 8) + (*(f32*)(pts[1] + 8) - *(f32*)(pts[2] + 8));
                    *w2 = *(f32*)(pts[1] + 0xc) + (*(f32*)(pts[1] + 0xc) - *(f32*)(pts[2] + 0xc));
                    *w3 = *(f32*)(pts[1] + 0x10) + (*(f32*)(pts[1] + 0x10) - *(f32*)(pts[2] + 0x10));
                    *w4 = (f32)(*(s16*)(pts[1] + 0x34) + (*(s16*)(pts[1] + 0x34) - *(s16*)(pts[2] + 0x34)));
                    *w5 = (f32)(*(s16*)(pts[1] + 0x36) + (*(s16*)(pts[1] + 0x36) - *(s16*)(pts[2] + 0x36)));
                    *w6 = (f32)(*(s16*)(pts[1] + 0x38) + (*(s16*)(pts[1] + 0x38) - *(s16*)(pts[2] + 0x38)));
                    *w7 = (f32) * (s8*)(pts[1] + 0x3a) +
                        ((f32) * (s8*)(pts[1] + 0x3a) - (f32) * (s8*)(pts[2] + 0x3a));
                }
                else if (i2 == 3)
                {
                    *w1 = *(f32*)(pts[2] + 8) + (*(f32*)(pts[2] + 8) - *(f32*)(pts[1] + 8));
                    *w2 = *(f32*)(pts[2] + 0xc) + (*(f32*)(pts[2] + 0xc) - *(f32*)(pts[1] + 0xc));
                    *w3 = *(f32*)(pts[2] + 0x10) + (*(f32*)(pts[2] + 0x10) - *(f32*)(pts[1] + 0x10));
                    *w4 = (f32)(*(s16*)(pts[2] + 0x34) + (*(s16*)(pts[2] + 0x34) - *(s16*)(pts[1] + 0x34)));
                    *w5 = (f32)(*(s16*)(pts[2] + 0x36) + (*(s16*)(pts[2] + 0x36) - *(s16*)(pts[1] + 0x36)));
                    *w6 = (f32)(*(s16*)(pts[2] + 0x38) + (*(s16*)(pts[2] + 0x38) - *(s16*)(pts[1] + 0x38)));
                    *w7 = (f32) * (s8*)(pts[2] + 0x3a) +
                        ((f32) * (s8*)(pts[2] + 0x3a) - (f32) * (s8*)(pts[1] + 0x3a));
                }
            }
            pw++;
            w1++;
            w2++;
            w3++;
            w4++;
            w5++;
            w6++;
            w7++;
        }

        k = 0;
        do
        {
            if (k == 0)
            {
                sel = o4;
            }
            else if (k == 1)
            {
                sel = o5;
            }
            else
            {
                sel = o6;
            }
            if (sel != NULL)
            {
                wp = sel;
                t0 = lbl_803E1890;
                m = 3;
                do
                {
                    ta = lbl_803E1888;
                    tb = lbl_803E1894;
                    tc = lbl_803E1898;
                    v0 = wp[0];
                    v1 = wp[1];
                    d = v0 - v1;
                    if (d > t0 || d < tb)
                    {
                        if (v0 < ta)
                        {
                            wp[0] = wp[0] + tc;
                        }
                        else if (v1 < ta)
                        {
                            wp[1] = wp[1] + tc;
                        }
                    }
                    wp++;
                    m--;
                }
                while (m != 0);
            }
            k++;
        }
        while (k < 3);
    }
}

void pathcam_findTaggedNodeWindow(u8* node, int* out, int tag)
{
    int i;
    u8* cur;
    u8* p;
    int idx;
    int m;

    out[0] = -1;
    out[1] = -1;
    out[2] = -1;
    out[3] = -1;

    if (node == NULL)
    {
        return;
    }

    out[1] = *(int*)(node + 0x14);

    i = 0;
    cur = node;
    for (; i < 5; i++)
    {
        idx = *(int*)(cur + 0x1c);
        if (idx > -1)
        {
            p = (u8*)(*gRomCurveInterface)->getById(idx);
            if (p != NULL)
            {
                if (p[0x31] == tag || p[0x32] == tag || p[0x33] == tag)
                {
                    m = (s8)node[0x1b] & (1 << i);
                    if (m != 0)
                    {
                        out[0] = *(int*)(cur + 0x1c);
                    }
                    else if (m == 0)
                    {
                        out[2] = *(int*)(cur + 0x1c);
                    }
                }
            }
        }
        cur += 4;
    }

    idx = out[2];
    if (idx > -1)
    {
        u8* node2 = (u8*)(*gRomCurveInterface)->getById(idx);
        if (node2 != NULL)
        {
            if (node2[0x31] == tag || node2[0x32] == tag || node2[0x33] == tag)
            {
                i = 0;
                cur = node2;
                for (; i < 5; i++)
                {
                    idx = *(int*)(cur + 0x1c);
                    if (idx > -1)
                    {
                        m = (s8)node2[0x1b] & (1 << i);
                        if (m == 0)
                        {
                            p = (u8*)(*gRomCurveInterface)->getById(idx);
                            if (p != NULL)
                            {
                                if (p[0x31] == tag || p[0x32] == tag || p[0x33] == tag)
                                {
                                    out[3] = *(int*)(cur + 0x1c);
                                }
                            }
                        }
                    }
                    cur += 4;
                }
            }
        }
    }

    if (out[1] < 0 || out[2] < 0)
    {
        debugPrintf(sPathCamNeedTwoControlPointsError);
    }
}

f32 fn_8010AC48(int* obj, f32 px, f32 py, f32 pz)
{
    int* pts[4];
    int** dp;
    int* sp;
    int i;
    f32 dx1;
    f32 dz1;
    f32 sx;
    f32 sz;
    f32 nsx;
    f32 nsz;
    f32 nx;
    f32 nz;
    f32 len;
    f32 t1;
    f32 t2;
    f32 negdot;
    dp = pts;
    sp = obj;
    for (i = 0; i < 4; i++)
    {
        *dp = (int*)(*gRomCurveInterface)->getById(*sp);
        sp++;
        dp++;
    }
    dx1 = *(f32*)((char*)pts[2] + 8) - *(f32*)((char*)pts[1] + 8);
    dz1 = *(f32*)((char*)pts[2] + 0x10) - *(f32*)((char*)pts[1] + 0x10);
    if (pts[0] != NULL)
    {
        sx = *(f32*)((char*)pts[1] + 8) - *(f32*)((char*)pts[0] + 8);
        sz = *(f32*)((char*)pts[1] + 0x10) - *(f32*)((char*)pts[0] + 0x10);
    }
    else
    {
        sx = dx1;
        sz = dz1;
    }
    nx = lbl_803E18A8 * (sx + dx1);
    nz = lbl_803E18A8 * (sz + dz1);
    len = sqrtf(nx * nx + nz * nz);
    if (lbl_803E1888 != len)
    {
        nx = nx / len;
        nz = nz / len;
    }
    negdot = -(nx * *(f32*)((char*)pts[1] + 8) + nz * *(f32*)((char*)pts[1] + 0x10));
    t1 = nx * dx1 + nz * dz1;
    if (lbl_803E1888 != t1)
    {
        t1 = -(negdot + (nx * px + nz * pz)) / t1;
    }
    sx = *(f32*)((char*)pts[2] + 8) - *(f32*)((char*)pts[1] + 8);
    sz = *(f32*)((char*)pts[2] + 0x10) - *(f32*)((char*)pts[1] + 0x10);
    if (pts[3] != NULL)
    {
        nsx = *(f32*)((char*)pts[3] + 8) - *(f32*)((char*)pts[2] + 8);
        nsz = *(f32*)((char*)pts[3] + 0x10) - *(f32*)((char*)pts[2] + 0x10);
    }
    else
    {
        nsx = sx;
        nsz = sz;
    }
    nx = lbl_803E18A8 * (nsx + sx);
    nz = lbl_803E18A8 * (nsz + sz);
    len = sqrtf(nx * nx + nz * nz);
    if (lbl_803E1888 != len)
    {
        nx = nx / len;
        nz = nz / len;
    }
    negdot = -(nx * *(f32*)((char*)pts[2] + 8) + nz * *(f32*)((char*)pts[2] + 0x10));
    t2 = nx * dx1 + nz * dz1;
    if (lbl_803E1888 != t2)
    {
        t2 = -(negdot + (nx * px + nz * pz)) / t2;
    }
    return -t1 / (t2 - t1);
}
