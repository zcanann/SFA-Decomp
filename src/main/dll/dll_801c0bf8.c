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
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "string.h"
#include "main/dll/dll_801c0bf8.h"

/* .sdata2 shared constants. */
extern f32 lbl_803E4DE0; /* 100.0f  - world-units -> fixed-point vertex scale   */
extern f32 lbl_803E4DE4; /* PI                                                  */
extern f32 lbl_803E4DE8; /* 32768.0f - half-turn in binary-angle (BAMS) units   */

void fn_801C0BF8(void* templateData, int angle, float* startNode, float* endNode, LightmapVertex* out)
{
    s16 startX;
    s16 startY;
    s16 startZ;
    s16 endX;
    s16 endY;
    s16 endZ;
    LightmapVertex* vertex;
    int i;
    float angleRadians;
    f32 vertexX;

    /* Scale the node world positions into the mesh's fixed-point vertex space. */
    startX = lbl_803E4DE0 * startNode[0];
    startY = lbl_803E4DE0 * startNode[1];
    startZ = lbl_803E4DE0 * startNode[2];
    endX = lbl_803E4DE0 * endNode[0];
    endY = lbl_803E4DE0 * endNode[1];
    endZ = lbl_803E4DE0 * endNode[2];
    memcpy(out, templateData, 0x60);

    /* BAMS -> radians: angle * PI / 32768. */
    i = 0;
    vertex = out;
    angleRadians = (lbl_803E4DE4 * (float)(short)angle) / lbl_803E4DE8;
    for (; i < 6; i++)
    {
        /* Rotate each vertex about Y: x' = x*cos, z' = -x*sin. */
        vertexX = (float)(int)vertex->x;
        vertex->x = vertexX * mathCosf(angleRadians);
        vertex->z = -vertexX * mathSinf(angleRadians);
        vertex++;
    }

    /* Translate the near end-cap (vertices 0,1,2) onto the start node ... */
    out[0].x += startX;
    out[0].y += startY;
    out[0].z += startZ;
    /* ... and the far end-cap (vertices 3,4,5) onto the end node. */
    out[3].x += endX;
    out[3].y += endY;
    out[3].z += endZ;
    out[1].x += startX;
    out[1].y += startY;
    out[1].z += startZ;
    out[4].x += endX;
    out[4].y += endY;
    out[4].z += endZ;
    out[2].x += startX;
    out[2].y += startY;
    out[2].z += startZ;
    out[5].x += endX;
    out[5].y += endY;
    out[5].z += endZ;
    return;
}
