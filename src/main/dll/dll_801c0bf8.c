/* DLL 0x801C0BF8 - DIM level control [801C0BF8-...) */
#include "main/dll_000A_expgfx.h"

extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */

#include "main/game_object.h"

extern void* memcpy(void* dst, const void* src, u32 size);

extern f32 lbl_803E4DE0;
extern f32 lbl_803E4DE4;
extern f32 lbl_803E4DE8;

#pragma peephole on
void fn_801C0BF8(void* templateData, int angle, float* startNode, float* endNode, short* out)
{
    int startX;
    int startY;
    int startZ;
    int endX;
    int endY;
    int endZ;
    short* vertex;
    int i;
    float angleRadians;
    f32 vertexX;

    startX = (int)(lbl_803E4DE0 * startNode[0]);
    startY = (int)(lbl_803E4DE0 * startNode[1]);
    startZ = (int)(lbl_803E4DE0 * startNode[2]);
    endX = (int)(lbl_803E4DE0 * endNode[0]);
    endY = (int)(lbl_803E4DE0 * endNode[1]);
    endZ = (int)(lbl_803E4DE0 * endNode[2]);
    memcpy(out, templateData, 0x60);

    i = 0;
    vertex = out;
    angleRadians = (lbl_803E4DE4 * (float)(short)angle) / lbl_803E4DE8;
    for (; i < 6; i++)
    {
        vertexX = (float)(int)*vertex;
        *vertex = (int)(vertexX * mathCosf(angleRadians));
        vertex[2] = (int)(-vertexX * mathSinf(angleRadians));
        vertex += 8;
    }

    out[0] += startX;
    out[1] += startY;
    out[2] += startZ;
    out[0x18] += endX;
    out[0x19] += endY;
    out[0x1a] += endZ;
    out[8] += startX;
    out[9] += startY;
    out[10] += startZ;
    out[0x20] += endX;
    out[0x21] += endY;
    out[0x22] += endZ;
    out[0x10] += startX;
    out[0x11] += startY;
    out[0x12] += startZ;
    out[0x28] += endX;
    out[0x29] += endY;
    out[0x2a] += endZ;
    return;
}
#pragma peephole reset
