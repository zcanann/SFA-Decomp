#include "global.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"
#include "track/intersect_internal.h"


static const f32 gGxPi = 3.1415927f;



/* Queues a GXPeekZ read at (x,y) tagged by an opaque requestKey (callers pass
 * any unique value - object ptrs, loop indices, even a function address) and
 * returns the previously completed result for that key, 0 until ready. */
int depthReadRequestPoll(int x, int y, void* requestKey)
{
    bool ok;
    int i;
    int key = (int)requestKey;
    u16 n;

    ok = false;
    if (x >= 0 && x < 0x280 && y >= 0 && y < 0x1E0)
    {
        ok = true;
    }
    if (ok)
    {
        if (x < 0x10)
            x = 0x10;
        if (y < 6)
            y = 6;
        n = gDepthReadPendingCount;
        if (n < 0x14)
        {
            gDepthReadPendingQueue[n].x = x;
            gDepthReadPendingQueue[n].y = y;
            gDepthReadPendingQueue[n].key = key;
            gDepthReadPendingCount++;
        }
        i = 0;
        n = gDepthReadResultCount;
        for (; (u32)i < n; i++)
        {
            if (key == gDepthReadResults[i].key)
            {
                return gDepthReadResults[i].value;
            }
        }
        return 0;
    }
    return 0;
}

u32 getScreenResolution(void)
{
    u32 v = screenWidth;
    if (v != 0)
    {
        return v | (v << 16);
    }
    return 0x01E00280;
}

void setScreenWidth(u32 width)
{
    screenWidth = width;
}

void clearScreenWidth(void)
{
    screenWidth = 0;
}

void mtx44Perspective(f32* matrix, u16* perspectiveNorm, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane,
                      f32 scale) {
    f32 angle;
    f32 tan;
    int i;

    mtx44Identity(matrix);

    angle = (f32)(s32)(91.022f * fovY) * gGxPi / 32768.0f;
    tan = mathCosf(angle) / mathSinf(angle);
    matrix[0] = tan / aspect;
    matrix[5] = tan;
    matrix[10] = -nearPlane / (farPlane - nearPlane);
    matrix[11] = -1.0f;
    matrix[14] = -nearPlane * farPlane / (farPlane - nearPlane);
    matrix[15] = 0.0f;

    for (i = 0; i < 16; i++) {
        matrix[i] *= scale;
    }

    if (perspectiveNorm != NULL) {
        if (nearPlane + farPlane <= 2.0f) {
            *perspectiveNorm = 0xFFFF;
        } else {
            *perspectiveNorm = (u16)(131072.0f / (nearPlane + farPlane));
            if (*perspectiveNorm == 0) {
                *perspectiveNorm = 1;
            }
        }
    }
    gFogNearZ = __fabs(nearPlane);
    gFogFarZ = __fabs(farPlane);
    C_MTXPerspective((void*)gPerspectiveMtx, fovY, aspect, gFogNearZ, gFogFarZ);
    lbl_803DD03C = 0;
}

void normalize(f32* x, f32* y, f32* z)
{
    f32 scale;
    f32 len;

    len = sqrtf(*z * *z + (*x * *x + *y * *y));
    scale = 1.0f / len;
    *x = *x * scale;
    *y = *y * scale;
    *z = *z * scale;
}
