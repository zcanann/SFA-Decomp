#include "ghidra_import.h"
#include "main/dll/DF/DFbarrel.h"
#include "main/dll/DF/dll_194.h"
#include "main/dll/DF/DFbarrelanim.h"
#include "main/dll/DF/dfropenode.h"

extern f32 sqrtf(f32 x);

extern f64 lbl_803E4DF0;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E18;
extern f32 lbl_803E4E1C;

#pragma peephole off
#pragma scheduling off

static inline f32 DFRope_S32AsFloat(s32 value) {
  u64 bits = CONCAT44(0x43300000, (u32)value ^ 0x80000000);
  return (f32)(*(f64 *)&bits - lbl_803E4DF0);
}

static inline f32 DFRope_S32AsFloat_SubAsFloat(s32 value) {
  u64 bits = CONCAT44(0x43300000, (u32)value ^ 0x80000000);
  return (f32)*(f64 *)&bits - (f32)lbl_803E4DF0;
}

/*
 * --INFO--
 *
 * Function: dfropenode_func0E
 * EN v1.0 Address: 0x801C1740
 * EN v1.0 Size: 560b
 * EN v1.1 Address: 0x801C17EC
 * EN v1.1 Size: 992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int dfropenode_func0E(int obj, f32 worldX, f32 worldY, f32 worldZ, float *distanceOut,
                      float *phaseOut, u8 *sideOut)
{
  DFropenodeExtra *extra;
  int result;
  int offset;
  int i;
  f32 localZ;
  f32 localY;
  f32 localX;
  f32 best;
  f32 phase;
  f32 x;
  f32 y;
  f32 z;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 distance;

  extra = *(DFropenodeExtra **)(obj + 0xb8);
  if ((*(u8 *)(*(int *)(obj + 0x4c) + 0x18) & 1) == 0) {
    return 0;
  }
  if (extra->linkedObj == NULL) {
    return 0;
  }
  if (worldX < extra->minX || worldX > extra->maxX || worldZ < extra->minZ ||
      worldZ > extra->maxZ) {
    return 0;
  }
  *distanceOut = lbl_803E4E1C;
  localX = worldX - *(f32 *)(obj + 0xc);
  localY = worldY - *(f32 *)(obj + 0x10);
  localZ = worldZ - *(f32 *)(obj + 0x14);
  {
    i = 0;
    result = 0;
    offset = 0;
    best = lbl_803E4DFC;
    for (; i < extra->rope->count - 1; i++) {
      int node;

      x = localX;
      y = localY;
      z = localZ;
      node = (int)extra->rope->nodes + offset;
      phase = fn_801C1698(*(f32 *)(node + 0), *(f32 *)(node + 4), *(f32 *)(node + 8),
                          *(f32 *)(node + 0x34), *(f32 *)(node + 0x38), *(f32 *)(node + 0x3c),
                          &x, &y, &z);
      if (phase >= best && phase < lbl_803E4E18) {
        dx = x - localX;
        dy = y - localY;
        dz = z - localZ;
        distance = sqrtf(dx * dx + dy * dy + dz * dz);
        if (distance < *distanceOut) {
          result = i + 1;
          *distanceOut = distance;
          *phaseOut = (f32)i + phase;
        }
      }
      offset += 0x34;
    }
  }
  if (result != 0) {
    if (result - 1 <= ((int)extra->rope->count >> 1)) {
      *sideOut = 0;
    } else {
      *sideOut = 1;
    }
  }
  return result;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfropenode_render2
 * EN v1.0 Address: 0x801C1970
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dfropenode_render2(f32 phase, f32 force, int obj)
{
  int extra;
  s8 idx;
  f32 fraction;
  int node;

  extra = *(int *)(obj + 0xb8);
  phase = phase - (f32)(s8)phase;
  idx = (s8)phase;
  fraction = phase - (f32)idx;
  node = **(int **)(extra + 0x2c) + idx * 0x34;
  *(f32 *)(node + 0x1c) = force * fraction + *(f32 *)(node + 0x1c);
  fraction = lbl_803E4E18 - fraction;
  node = **(int **)(extra + 0x2c) + idx * 0x34;
  *(f32 *)(node + 0x1c) = force * fraction + *(f32 *)(node + 0x1c);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfropenode_modelMtxFn
 * EN v1.0 Address: 0x801C1A14
 * EN v1.0 Size: 240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dfropenode_modelMtxFn(f32 distance, int obj, float *phase)
{
  int extra;
  s32 raw;
  s8 idx;
  int node;
  f32 ph;
  f32 x0;
  f32 dx;
  f32 dz;
  f32 len;

  extra = *(int *)(obj + 0xb8);
  ph = *phase;
  raw = (s32)ph;
  idx = (s8)raw;
  *phase = ph - (f32)idx;
  x0 = *((f32 *)**(int **)(extra + 0x2c) + idx * 13);
  node = **(int **)(extra + 0x2c) + idx * 0x34;
  dx = x0 - *(f32 *)(node + 0x34);
  dz = *(f32 *)(node + 8) - *(f32 *)(node + 0x3c);
  len = sqrtf(dx * dx + dz * dz);
  distance = distance / len;
  *phase = *phase + distance;
  *phase = *phase + (f32)(s8)raw;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfropenode_func0B
 * EN v1.0 Address: 0x801C1B04
 * EN v1.0 Size: 196b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dfropenode_func0B(f32 phase, int obj, float *xOut, float *yOut, float *zOut)
{
  DFropenodeExtra *extra;
  s8 idx;
  f32 x0;
  f32 dy;
  f32 dz;
  f32 fraction;
  DFRopeNode *node;
  int nodes;

  extra = *(DFropenodeExtra **)(obj + 0xb8);
  idx = (s8)phase;
  fraction = phase - (f32)idx;
  nodes = (int)extra->rope->nodes;
  node = (DFRopeNode *)(nodes + idx * 0x34);
  dy = node[1].pos[1] - node->pos[1];
  dz = node[1].pos[2] - node->pos[2];
  x0 = *(f32 *)(nodes + idx * 0x34);
  *xOut = (node[1].pos[0] - x0) * fraction + (*(f32 *)(obj + 0xc) + x0);
  *yOut = dy * fraction + (*(f32 *)(obj + 0x10) + extra->rope->nodes[idx].pos[1]);
  *zOut = dz * fraction + (*(f32 *)(obj + 0x14) + extra->rope->nodes[idx].pos[2]);
}
#pragma scheduling reset
