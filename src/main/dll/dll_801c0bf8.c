/*
 * Rope-segment mesh builder (DLL 0x801C0BF8), used by the DragonRock rope node
 * (dll_0175_dfropenode.c). For one rope link it takes a 6-vertex template mesh,
 * rotates it about the Y axis by the rope's yaw angle, then translates the two
 * ends of the mesh onto the link's start and end node positions.
 *
 * The output buffer holds 6 vertices of 8 shorts (16 bytes) each = 0x60 bytes.
 * The template is copied in first, then vertex X/Z are spun by the angle and the
 * two three-vertex end-caps are offset by the (scaled) start / end node coords.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "string.h"
#include "main/dll/dll_80220608_shared.h"

/* .sdata2 shared constants. */
extern f32 lbl_803E4DE0; /* 100.0f  - world-units -> fixed-point vertex scale   */
extern f32 lbl_803E4DE4; /* PI                                                  */
extern f32 lbl_803E4DE8; /* 32768.0f - half-turn in binary-angle (BAMS) units   */

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

    /* Scale the node world positions into the mesh's fixed-point vertex space. */
    startX = (int)(lbl_803E4DE0 * startNode[0]);
    startY = (int)(lbl_803E4DE0 * startNode[1]);
    startZ = (int)(lbl_803E4DE0 * startNode[2]);
    endX = (int)(lbl_803E4DE0 * endNode[0]);
    endY = (int)(lbl_803E4DE0 * endNode[1]);
    endZ = (int)(lbl_803E4DE0 * endNode[2]);
    memcpy(out, templateData, 0x60);

    /* BAMS -> radians: angle * PI / 32768. */
    i = 0;
    vertex = out;
    angleRadians = (lbl_803E4DE4 * (float)(short)angle) / lbl_803E4DE8;
    for (; i < 6; i++)
    {
        /* Rotate each vertex about Y: x' = x*cos, z' = -x*sin. */
        vertexX = (float)(int)vertex[0];
        vertex[0] = (int)(vertexX * mathCosf(angleRadians));
        vertex[2] = (int)(-vertexX * mathSinf(angleRadians));
        vertex += 8;
    }

    /* Translate the near end-cap (vertices 0,1,2) onto the start node ... */
    out[0] += startX;
    out[1] += startY;
    out[2] += startZ;
    /* ... and the far end-cap (vertices 3,4,5) onto the end node. */
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
