#include "ghidra_import.h"
#include "main/dll/DF/DFbarrel.h"
#include "main/dll/DF/DFbarrelanim.h"
#include "main/dll/DF/dll_196.h"
#include "main/dll/DF/dll_198.h"
#include "main/dll/DF/dfropenode.h"

typedef struct DFDoorSpeciExtra {
  u16 phase;
  u8 pad02;
  u8 state;
  u8 pad04[2];
} DFDoorSpeciExtra;

extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern void ObjGroup_AddObject(int obj, int group);
extern int GameBit_Get(int eventId);
extern int *objFindTexture(int obj, int a, int b);
extern void textureFree(void *resource);
extern void *textureLoadAsset(int assetId);
extern s32 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 x);
extern f64 sin(f64 x);
extern u8 framesThisStep;
extern int lbl_803DBF40;
extern void *lbl_803DBF48;
extern f32 lbl_803DBF50;
extern u8 lbl_803DBF58;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E24;
extern f32 lbl_803E4E28;
extern f32 lbl_803E4E30;
extern f32 lbl_803E4E34;
extern f32 lbl_803E4E38;
extern f32 lbl_803E4E3C;
extern f32 lbl_803E4E40;
extern f64 lbl_803E4E48;

/*
 * --INFO--
 *
 * Function: dfropenode_update
 * EN v1.0 Address: 0x801C2278
 * EN v1.0 Size: 824b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void dfropenode_update(DFropenodeObject *obj)
{
  DFropenodeExtra *extra;
  u8 *objDef;
  DFropenodeObject *linkedObj;
  DFropenodeObject **objects;
  int objectCount;
  int objectIndex;
  DFropenodeObject *candidateObj;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 length;
  s16 angle;
  f32 temp;
  f32 baseX;
  f32 baseY;
  f32 baseZ;
  f32 linkedX;
  f32 linkedY;
  f32 linkedZ;
  f32 liftedY;
  f32 normalX;
  f32 normalY;
  f32 normalZ;
  f32 normalLength;

  objDef = obj->definition;
  extra = obj->extra;
  if ((objDef[0x18] & 1) == 0) {
    return;
  }

  linkedObj = extra->linkedObj;
  if (linkedObj == NULL) {
    objects = (DFropenodeObject **)ObjList_GetObjects(&objectIndex, &objectCount);
    objectIndex = 0;
    while ((objectIndex < objectCount) && (linkedObj == NULL)) {
      candidateObj = *objects;
      if ((candidateObj->objType == 0x36) &&
          ((u32)objDef[0x18] == candidateObj->definition[0x18] - 1)) {
        linkedObj = candidateObj;
      }
      objects++;
      objectIndex++;
    }
    if (linkedObj == NULL) {
      return;
    }

    linkedObj->extra->linkedObj = obj;
    extra = obj->extra;
    extra->linkedObj = linkedObj;

    dx = linkedObj->posX - obj->posX;
    dy = linkedObj->posY - obj->posY;
    dz = linkedObj->posZ - obj->posZ;
    length = sqrtf(dz * dz + (dx * dx + dy * dy));
    angle = getAngle(dx, dz);
    if (angle > 0x8000) {
      angle -= 0xFFFF;
    }
    if (angle < -0x8000) {
      angle += 0xFFFF;
    }
    extra->angle = angle;

    extra->rope =
        DFRope_Create(0x10, lbl_803E4DFC, lbl_803E4DFC, lbl_803E4DFC, dx, dy, dz, length,
                      (&lbl_803DBF50)[*(u8 *)(objDef + 0x1b)]);

    extra->minX = obj->posX;
    extra->minZ = obj->posZ;
    extra->maxX = linkedObj->posX;
    extra->maxZ = linkedObj->posZ;
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
    extra->minX -= lbl_803E4E24;
    extra->minZ -= lbl_803E4E24;
    extra->maxX += lbl_803E4E24;
    extra->maxZ += lbl_803E4E24;

    baseX = obj->posX;
    baseY = obj->posY;
    baseZ = obj->posZ;
    linkedX = linkedObj->posX;
    linkedY = linkedObj->posY;
    linkedZ = linkedObj->posZ;
    liftedY = lbl_803E4E28 + baseY;

    normalX = liftedY * (baseZ - linkedZ) +
              (baseY * (linkedZ - baseZ) + (linkedY * (baseZ - baseZ)));
    normalY = baseZ * (baseX - linkedX) +
              (baseZ * (linkedX - baseX) + (linkedZ * (baseX - baseX)));
    normalZ = baseX * (baseY - linkedY) +
              (baseX * (linkedY - liftedY) + (linkedX * (liftedY - baseY)));
    normalLength = sqrtf(normalZ * normalZ + (normalX * normalX + normalY * normalY));
    if (normalLength > lbl_803E4DFC) {
      normalX /= normalLength;
      normalY /= normalLength;
      normalZ /= normalLength;
    }
    extra->planeNormalX = normalX;
    extra->planeNormalY = normalY;
    extra->planeNormalZ = normalZ;
    extra->planeDistance = -(baseZ * normalZ + (baseX * normalX + baseY * normalY));
  }

  DFRope_UpdateSimulation((u8 *)extra->rope);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dfropenode_init
 * EN v1.0 Address: 0x801C25B0
 * EN v1.0 Size: 132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void dfropenode_init(DFropenodeObject *obj, u8 *objDef)
{
  DFropenodeExtra *extra;

  extra = obj->extra;
  if ((&lbl_803DBF58)[*(u8 *)(objDef + 0x1b)] == 0) {
    *(s16 *)((u8 *)obj + 6) = *(s16 *)((u8 *)obj + 6) & ~0x80;
  }
  ObjGroup_AddObject((int)obj, 0x17);
  *(void **)((u8 *)obj + 0xbc) = dfropenode_syncRopeToEndpoints;
  extra->rope = NULL;
  extra->linkedObj = NULL;
  *(u8 *)((u8 *)obj + 0x36) = 0x46;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dfropenode_release
 * EN v1.0 Address: 0x801C2634
 * EN v1.0 Size: 76b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void dfropenode_release(void)
{
  int i;

  for (i = 0; i < 2; i++) {
    textureFree((&lbl_803DBF48)[i]);
  }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dfropenode_initialise
 * EN v1.0 Address: 0x801C2680
 * EN v1.0 Size: 96b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
void dfropenode_initialise(void)
{
  int i;

  for (i = 0; i < 2; i++) {
    (&lbl_803DBF48)[i] = textureLoadAsset((&lbl_803DBF40)[i]);
  }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: DFSH_Door2Speci_SeqFn
 * EN v1.0 Address: 0x801C26E0
 * EN v1.0 Size: 316b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
#pragma scheduling off
int DFSH_Door2Speci_SeqFn(int obj)
{
  int *texture;
  DFDoorSpeciExtra *extra;
  int objDef;
  int alpha;
  u32 phaseStep;
  f64 phase;
  f64 phaseBits;
  u64 phaseBitsRaw;

  extra = *(DFDoorSpeciExtra **)(obj + 0xb8);
  objDef = *(int *)(obj + 0x4c);
  switch (extra->state) {
  case 0:
    if (GameBit_Get(*(s16 *)(objDef + 0x22)) != 0) {
      extra->state = 1;
    }
    break;
  case 1:
    texture = objFindTexture(obj, 0, 0);
    if (texture != NULL) {
      alpha = *texture + framesThisStep * 0x10;
      if (alpha > 0x100) {
        alpha = 0x100;
        extra->state = 2;
      }
      *texture = alpha;
    }
    break;
  default:
    texture = objFindTexture(obj, 0, 0);
    if (texture != NULL) {
      phaseStep = (extra->phase + framesThisStep * 800) & 0xffff;
      extra->phase = phaseStep;
      phaseBitsRaw = CONCAT44(0x43300000, (u32)extra->phase);
      phaseBits = *(f64 *)&phaseBitsRaw;
      phase = (lbl_803E4E3C * (f32)(phaseBits - lbl_803E4E48)) / lbl_803E4E40;
      *texture = (s32)-(lbl_803E4E34 * (lbl_803E4E38 - sin(phase)) - lbl_803E4E30);
    }
    break;
  }
  return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dfsh_door2speci_getExtraSize
 * EN v1.0 Address: 0x801C281C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801C29EC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfsh_door2speci_getExtraSize(void)
{
  return sizeof(DFDoorSpeciExtra);
}
