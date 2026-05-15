#include "ghidra_import.h"
#include "main/dll/DF/dll_196.h"

typedef struct DFRopeNode {
  f32 pos[3];
  f32 velocity[3];
  f32 force[3];
  u8 linkCount;
  u8 pad25[3];
  struct DFRopeLink *links[2];
  u8 locked;
  u8 pad31[3];
} DFRopeNode;

typedef struct DFRopeLink {
  f32 length;
  DFRopeNode *a;
  DFRopeNode *b;
  f32 restLength;
  f32 stiffness;
  f32 maxLength;
  f32 force[3];
} DFRopeLink;

typedef struct DFRope {
  DFRopeNode *nodes;
  DFRopeLink *links;
  u8 count;
  u8 pad09[3];
  f32 start[3];
  f32 end[3];
  f32 totalLength;
  s32 enabled;
  f32 maxSlack;
  f32 step;
  u8 sway;
  u8 direction;
  u8 pad36[2];
  f32 damping;
  f32 inverseTicks;
  f32 stepPerTick;
} DFRope;

typedef struct DFropenodeExtra {
  int linkedObj;
  f32 minX;
  f32 maxX;
  f32 minZ;
  f32 maxZ;
  f32 minY;
  s16 angle;
  u8 pad1A[0x12];
  DFRope *rope;
  u8 flags;
  u8 pad31[3];
} DFropenodeExtra;

extern int getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);

extern f64 lbl_803E4DF0;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E20;
extern f32 lbl_803E4E24;

/*
 * --INFO--
 *
 * Function: fn_801C1BF0
 * EN v1.0 Address: 0x801C1BF0
 * EN v1.0 Size: 684b
 * EN v1.1 Address: 0x801C1C4C
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int fn_801C1BF0(int obj)
{
  DFropenodeExtra *extra;
  DFRopeLink *link;
  int endObj;
  int baseObj;
  int i;
  int flag;
  s16 angle;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 length;
  f32 clampY;
  f32 temp;
  f32 margin;

  baseObj = obj;
  flag = *(u8 *)(*(int *)(baseObj + 0x4c) + 0x18) & 1;
  if (flag != 0) {
    extra = *(DFropenodeExtra **)(baseObj + 0xb8);
    endObj = extra->linkedObj;
  } else {
    endObj = baseObj;
    baseObj = *(int *)*(int *)(baseObj + 0xb8);
    if (baseObj == 0) {
      return 0;
    }
    extra = *(DFropenodeExtra **)(baseObj + 0xb8);
  }

  if ((extra->rope == NULL) || (endObj == 0)) {
    return 0;
  }

  dx = *(f32 *)(endObj + 0xc) - *(f32 *)(baseObj + 0xc);
  dy = *(f32 *)(endObj + 0x10) - *(f32 *)(baseObj + 0x10);
  dz = *(f32 *)(endObj + 0x14) - *(f32 *)(baseObj + 0x14);

  angle = getAngle(dx, dz);
  if (angle > 0x8000) {
    angle = angle - 0xffff;
  }
  if (angle < -0x8000) {
    angle = angle + 0xffff;
  }
  extra->angle = angle;

  length = sqrtf(dx * dx + dy * dy + dz * dz);
  length = length / (f32)(extra->rope->count - 1);
  link = extra->rope->links;
  extra->rope->damping = lbl_803E4E20;
  for (i = 0; i < extra->rope->count - 1; i++, link++) {
    link->restLength = length;
  }

  i = extra->rope->count - 1;
  extra->rope->nodes[i].pos[0] = dx;
  extra->rope->nodes[i].pos[1] = dy;
  extra->rope->nodes[i].pos[2] = dz;

  extra->minX = *(f32 *)(baseObj + 0xc);
  extra->minZ = *(f32 *)(baseObj + 0x14);
  extra->maxX = *(f32 *)(endObj + 0xc);
  extra->maxZ = *(f32 *)(endObj + 0x14);
  if (extra->minX > extra->maxX) {
    temp = extra->minX;
    extra->minX = extra->maxX;
    extra->maxX = temp;
  }
  if (extra->minZ > extra->maxZ) {
    temp = extra->minZ;
    extra->minZ = extra->maxZ;
    extra->maxZ = temp;
  }

  if (extra->minY != lbl_803E4DFC) {
    clampY = extra->minY - *(f32 *)(baseObj + 0x10);
    for (i = 0; i < extra->rope->count - 1; i++) {
      if (extra->rope->nodes[i].pos[1] < clampY) {
        extra->rope->nodes[i].pos[1] = clampY;
      }
    }
  }

  margin = lbl_803E4E24;
  extra->minX -= margin;
  extra->minZ -= margin;
  extra->maxX += margin;
  extra->maxZ += margin;
  return 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfropenode_getExtraSize
 * EN v1.0 Address: 0x801C1E9C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfropenode_getExtraSize(void)
{
  return 0x34;
}

/*
 * --INFO--
 *
 * Function: dfropenode_func08
 * EN v1.0 Address: 0x801C1EA4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfropenode_func08(void)
{
  return 0;
}
