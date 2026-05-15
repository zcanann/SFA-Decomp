#include "ghidra_import.h"
#include "main/dll/DF/dll_194.h"
#include "main/dll/DF/DFbarrelanim.h"

typedef struct DFropenodeExtra {
  int linkedObj;
  f32 minX;
  f32 maxX;
  f32 minZ;
  f32 maxZ;
  f32 minY;
  s16 angle;
  u8 pad1A[2];
  f32 planeNormalX;
  f32 planeNormalY;
  f32 planeNormalZ;
  f32 planeDistance;
  void *rope;
} DFropenodeExtra;

typedef struct DFRope {
  void *nodes;
  void *links;
  u8 count;
} DFRope;

extern undefined8 FUN_802860d4(void);
extern void FUN_80286120(int value);
extern f32 sqrtf(f32 x);

extern f64 lbl_803E4DF0;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E18;
extern f32 lbl_803E4E1C;

static inline f32 DFRope_S32AsFloat(s32 value) {
  u64 bits = CONCAT44(0x43300000, (u32)value ^ 0x80000000);
  return (f32)(*(f64 *)&bits - lbl_803E4DF0);
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
void dfropenode_func0E(undefined8 param_1, double y, double z, undefined4 param_4,
                       undefined4 param_5, float *phaseOut, u8 *sideOut)
{
  int obj;
  float *distanceOut;
  DFropenodeExtra *extra;
  DFRope *rope;
  f32 localX;
  f32 localY;
  f32 localZ;
  f32 distance;
  f32 segmentPhase;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 x;
  f32 bestDistance;
  f32 *node;
  int segmentIndex;
  int nodeOffset;
  u32 i;
  undefined8 current;

  current = FUN_802860d4();
  obj = (int)((u64)current >> 0x20);
  distanceOut = (float *)current;
  extra = *(DFropenodeExtra **)(obj + 0xb8);
  segmentIndex = 0;
  if ((*(u8 *)(*(int *)(obj + 0x4c) + 0x18) & 1) == 0) {
    segmentIndex = 0;
  } else if (extra->linkedObj == 0) {
    segmentIndex = 0;
  } else if ((((double)extra->minX > (double)(float)param_1) ||
              ((double)extra->maxX < (double)(float)param_1)) ||
             (z < (double)extra->minZ) || ((double)extra->maxZ < z)) {
    segmentIndex = 0;
  } else {
    *distanceOut = lbl_803E4E1C;
    localX = (f32)((double)(float)param_1 - (double)*(f32 *)(obj + 0xc));
    localY = (f32)(y - (double)*(f32 *)(obj + 0x10));
    localZ = (f32)(z - (double)*(f32 *)(obj + 0x14));
    rope = (DFRope *)extra->rope;
    nodeOffset = 0;
    bestDistance = lbl_803E4DFC;
    for (i = 0; (int)i < (int)(rope->count - 1); i++) {
      x = localX;
      dy = localY;
      dz = localZ;
      node = (float *)((int)rope->nodes + nodeOffset);
      segmentPhase = fn_801C1698(node[0], node[1], node[2], node[13], node[14], node[15], &x, &dy,
                                 &dz);
      if ((bestDistance <= segmentPhase) && (segmentPhase < lbl_803E4E18)) {
        dx = dz - localZ;
        dz = x - localX;
        dy = localY - dy;
        distance = sqrtf(dx * dx + dz * dz + dy * dy);
        if (distance < *distanceOut) {
          segmentIndex = i + 1;
          *distanceOut = distance;
          *phaseOut = DFRope_S32AsFloat(i) + segmentPhase;
        }
      }
      nodeOffset += 0x34;
    }
    if (segmentIndex != 0) {
      if (((int)(u32)rope->count >> 1) < segmentIndex - 1) {
        *sideOut = 1;
      } else {
        *sideOut = 0;
      }
    }
  }
  FUN_80286120(segmentIndex);
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
void dfropenode_render2(double phase, double force, int obj)
{
  DFropenodeExtra *extra;
  int segmentOffset;
  int node;
  s8 segmentIndex;
  f32 fraction;

  extra = *(DFropenodeExtra **)(obj + 0xb8);
  phase = phase - (double)DFRope_S32AsFloat((s32)(s8)(s32)phase);
  segmentIndex = (s8)(s32)phase;
  fraction = (f32)phase - DFRope_S32AsFloat(segmentIndex);
  segmentOffset = segmentIndex * 0x34;
  node = **(int **)&extra->rope + segmentOffset;
  *(f32 *)(node + 0x1c) = (f32)(force * (double)fraction + (double)*(f32 *)(node + 0x1c));
  node = **(int **)&extra->rope + segmentOffset;
  *(f32 *)(node + 0x1c) =
      (f32)(force * (double)(lbl_803E4E18 - fraction) + (double)*(f32 *)(node + 0x1c));
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
void dfropenode_modelMtxFn(double distance, int obj, float *phase)
{
  DFropenodeExtra *extra;
  int nodeBase;
  int segmentOffset;
  s8 segmentIndex;
  f32 dx;
  f32 dz;
  f32 segmentLength;

  extra = *(DFropenodeExtra **)(obj + 0xb8);
  segmentIndex = (s8)(s32)*phase;
  *phase = *phase - DFRope_S32AsFloat(segmentIndex);
  nodeBase = **(int **)&extra->rope;
  segmentOffset = segmentIndex * 0x34;
  dx = *(f32 *)(nodeBase + segmentOffset) - *(f32 *)(nodeBase + segmentOffset + 0x34);
  dz = *(f32 *)(nodeBase + segmentOffset + 8) - *(f32 *)(nodeBase + segmentOffset + 0x3c);
  segmentLength = sqrtf(dx * dx + dz * dz);
  *phase = *phase + (f32)(distance / (double)segmentLength);
  *phase = *phase + DFRope_S32AsFloat(segmentIndex);
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
void dfropenode_func0B(double phase, int obj, float *xOut, float *yOut, float *zOut)
{
  DFropenodeExtra *extra;
  int segmentOffset;
  int node;
  f32 fraction;
  f32 x0;
  f32 y0;
  f32 y1;
  f32 z0;
  f32 z1;

  extra = *(DFropenodeExtra **)(obj + 0xb8);
  fraction = (f32)(phase - (double)DFRope_S32AsFloat((s8)(s32)phase));
  segmentOffset = (s8)(s32)phase * 0x34;
  node = **(int **)&extra->rope + segmentOffset;
  y0 = *(f32 *)(node + 0x38);
  y1 = *(f32 *)(node + 4);
  z0 = *(f32 *)(node + 0x3c);
  z1 = *(f32 *)(node + 8);
  x0 = *(f32 *)(**(int **)&extra->rope + segmentOffset);
  *xOut = (*(f32 *)(node + 0x34) - x0) * fraction + *(f32 *)(obj + 0xc) + x0;
  *yOut = (y0 - y1) * fraction + *(f32 *)(obj + 0x10) +
          *(f32 *)(**(int **)&extra->rope + segmentOffset + 4);
  *zOut = (z0 - z1) * fraction + *(f32 *)(obj + 0x14) +
          *(f32 *)(**(int **)&extra->rope + segmentOffset + 8);
}
#pragma scheduling reset
