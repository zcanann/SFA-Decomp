#include "ghidra_import.h"
#include "main/dll/DF/DFbarrel.h"
#include "main/dll/DF/dll_196.h"
#include "main/dll/DF/dfropenode.h"

extern int getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);

extern f64 lbl_803E4DF0;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E20;
extern f32 lbl_803E4E24;

/*
 * --INFO--
 *
 * Function: dfropenode_syncRopeToEndpoints
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
#pragma peephole off
int dfropenode_syncRopeToEndpoints(DFropenodeObject *obj)
{
  DFropenodeExtra *extra;
  DFropenodeObject *endObj;
  DFropenodeObject *baseObj;
  int i;
  DFRopeLink *link;
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
  flag = baseObj->definition[0x18] & 1;
  if (flag != 0) {
    extra = baseObj->extra;
    endObj = extra->linkedObj;
  } else {
    endObj = baseObj;
    baseObj = baseObj->extra->linkedObj;
    if (baseObj == NULL) {
      return 0;
    }
    extra = baseObj->extra;
  }

  if ((extra->rope == NULL) || (endObj == NULL)) {
    return 0;
  }

  dx = endObj->posX - baseObj->posX;
  dy = endObj->posY - baseObj->posY;
  dz = endObj->posZ - baseObj->posZ;

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

  extra->minX = baseObj->posX;
  extra->minZ = baseObj->posZ;
  extra->maxX = endObj->posX;
  extra->maxZ = endObj->posZ;
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
    clampY = extra->minY - baseObj->posY;
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
 * Function: dfropenode_getObjectTypeId
 * EN v1.0 Address: 0x801C1EA4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfropenode_getObjectTypeId(void)
{
  return 0;
}
