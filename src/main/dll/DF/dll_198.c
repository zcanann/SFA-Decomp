#include "ghidra_import.h"
#include "main/dll/DF/dll_198.h"

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
extern void fn_801C0FD8(void *rope);
extern void *fn_801C1238(s32 count, f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY,
                         f32 endZ, f32 unused, f32 tickScale);
extern int fn_801C1BF0(int obj);

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
#pragma scheduling off
void dfropenode_update(int obj)
{
  DFropenodeExtra *extra;
  int objDef;
  int linkedObj;
  int *objects;
  int objectIndex;
  int objectCount;
  int candidateObj;
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

  objDef = *(int *)(obj + 0x4c);
  extra = *(DFropenodeExtra **)(obj + 0xb8);
  if ((*(u8 *)(objDef + 0x18) & 1) == 0) {
    return;
  }

  linkedObj = extra->linkedObj;
  if (linkedObj == 0) {
    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    objectIndex = 0;
    while ((objectIndex < objectCount) && (linkedObj == 0)) {
      candidateObj = *objects;
      if ((*(s16 *)(candidateObj + 0x44) == 0x36) &&
          ((u32)*(u8 *)(objDef + 0x18) == *(u8 *)(*(int *)(candidateObj + 0x4c) + 0x18) - 1)) {
        linkedObj = candidateObj;
      }
      objects++;
      objectIndex++;
    }
    if (linkedObj == 0) {
      return;
    }

    **(int **)(linkedObj + 0xb8) = obj;
    extra = *(DFropenodeExtra **)(obj + 0xb8);
    extra->linkedObj = linkedObj;

    dx = *(f32 *)(linkedObj + 0xc) - *(f32 *)(obj + 0xc);
    dy = *(f32 *)(linkedObj + 0x10) - *(f32 *)(obj + 0x10);
    dz = *(f32 *)(linkedObj + 0x14) - *(f32 *)(obj + 0x14);
    length = sqrtf(dz * dz + (dx * dx + dy * dy));
    angle = getAngle(dx, dz);
    if (angle > 0x8000) {
      angle += 1;
    }
    if (angle < -0x8000) {
      angle -= 1;
    }
    extra->angle = angle;

    extra->rope =
        fn_801C1238(0x10, lbl_803E4DFC, lbl_803E4DFC, lbl_803E4DFC, dx, dy, dz, length,
                    (&lbl_803DBF50)[*(u8 *)(objDef + 0x1b)]);

    extra->minX = *(f32 *)(obj + 0xc);
    extra->minZ = *(f32 *)(obj + 0x14);
    extra->maxX = *(f32 *)(linkedObj + 0xc);
    extra->maxZ = *(f32 *)(linkedObj + 0x14);
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

    baseX = *(f32 *)(obj + 0xc);
    baseY = *(f32 *)(obj + 0x10);
    baseZ = *(f32 *)(obj + 0x14);
    linkedX = *(f32 *)(linkedObj + 0xc);
    linkedY = *(f32 *)(linkedObj + 0x10);
    linkedZ = *(f32 *)(linkedObj + 0x14);
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

  fn_801C0FD8(extra->rope);
}
#pragma scheduling reset

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
void dfropenode_init(int obj, int objDef)
{
  DFropenodeExtra *extra;

  extra = *(DFropenodeExtra **)(obj + 0xb8);
  if ((&lbl_803DBF58)[*(u8 *)(objDef + 0x1b)] == 0) {
    *(s16 *)(obj + 6) = *(u16 *)(obj + 6) & 0xff7f;
  }
  ObjGroup_AddObject(obj, 0x17);
  *(void **)(obj + 0xbc) = fn_801C1BF0;
  extra->rope = NULL;
  extra->linkedObj = 0;
  *(u8 *)(obj + 0x36) = 0x46;
}

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
void dfropenode_release(void)
{
  int i;

  for (i = 0; i < 2; i++) {
    textureFree((&lbl_803DBF48)[i]);
  }
}

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
void dfropenode_initialise(void)
{
  int i;

  for (i = 0; i < 2; i++) {
    (&lbl_803DBF48)[i] = textureLoadAsset((&lbl_803DBF40)[i]);
  }
}

/*
 * --INFO--
 *
 * Function: fn_801C26E0
 * EN v1.0 Address: 0x801C26E0
 * EN v1.0 Size: 316b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int fn_801C26E0(int obj)
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
