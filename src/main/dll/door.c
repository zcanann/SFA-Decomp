#include "ghidra_import.h"
#include "main/dll/door.h"

extern undefined4 FUN_80006b4c();
extern uint FUN_80017690();
extern int fn_800640CC(f32 radius,f32 *from,f32 *to,int mode,void *hit,
                       DfpTargetBlockObject *obj,int flags,int mask,int arg9,int arg10);
extern void Sfx_PlayFromObject(DfpTargetBlockObject *obj,u16 sfxId);
extern void fn_8003B8F4(int obj,float param_2);
extern undefined4 sfxplayer_updateState();

extern undefined4 DAT_803add98;
extern undefined4 DAT_803add9c;
extern undefined4 DAT_803adda0;
extern undefined4 DAT_803adda4;
extern undefined4 DAT_803adda8;
extern undefined4 DAT_803addac;
extern undefined4 DAT_803addb0;
extern undefined4 DAT_803addb4;
extern f32 lbl_803E6488;
extern f32 lbl_803E648C;
extern f32 lbl_803E6490;

struct DfpTargetBlockObject {
  u8 pad00[0x0C];
  f32 x;
  f32 y;
  f32 z;
  u8 pad18[0x0C];
  f32 velX;
  f32 velY;
  f32 velZ;
};

typedef struct DfpTargetBlockCollisionPoints {
  u8 pointData[0x64];
  u8 pad64[0x68 - 0x64];
  s8 count;
} DfpTargetBlockCollisionPoints;

#define DFPTARGETBLOCK_POINT_OFFSET_X 0x04
#define DFPTARGETBLOCK_POINT_OFFSET_Y 0x08
#define DFPTARGETBLOCK_POINT_OFFSET_Z 0x0C
#define DFPTARGETBLOCK_POINT_STRIDE 0x0C

/*
 * --INFO--
 *
 * Function: dfptargetblock_resolveCollisionPoints
 * EN v1.0 Address: 0x80208508
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802085F4
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dfptargetblock_resolveCollisionPoints(DfpTargetBlockObject *obj,
                                           DfpTargetBlockCollisionPoints *collisionPoints)
{
  u8 *point;
  f32 probe[3];
  u8 hit[0x54];
  f32 originalX;
  f32 originalZ;
  f32 deltaX;
  f32 deltaZ;
  int i;

  i = 0;
  point = collisionPoints->pointData;
  while (i < collisionPoints->count) {
    probe[0] = *(f32 *)(point + DFPTARGETBLOCK_POINT_OFFSET_X) + obj->x;
    originalX = probe[0];
    probe[1] = *(f32 *)(point + DFPTARGETBLOCK_POINT_OFFSET_Y) + obj->y;
    probe[2] = *(f32 *)(point + DFPTARGETBLOCK_POINT_OFFSET_Z) + obj->z;
    originalZ = probe[2];
    if (fn_800640CC(lbl_803E6488,&obj->x,probe,1,hit,obj,8,-1,0,0) != 0) {
      deltaX = probe[0] - originalX;
      deltaZ = probe[2] - originalZ;
      if (lbl_803E648C != obj->velX) {
        obj->x = obj->x + deltaX;
      }
      if (lbl_803E648C != obj->velZ) {
        obj->z = obj->z + deltaZ;
      }
      {
        f32 zero = lbl_803E648C;
        obj->velX = zero;
        obj->velY = zero;
        obj->velZ = zero;
      }
      Sfx_PlayFromObject(obj,0x1d0);
      return;
    }
    point += DFPTARGETBLOCK_POINT_STRIDE;
    i++;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfptargetblock_getExtraSize
 * EN v1.0 Address: 0x80208660
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8020874C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfptargetblock_getExtraSize(void)
{
  return 0x6c;
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_func08
 * EN v1.0 Address: 0x80208668
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80208754
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dfptargetblock_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_free
 * EN v1.0 Address: 0x80208670
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020875C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfptargetblock_free(void)
{
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_render
 * EN v1.0 Address: 0x80208674
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x80208760
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void dfptargetblock_render(int obj)
{
  int state;

  state = *(int *)(obj + 0xb8);
  if (((*(u8 *)(state + 0x6b) == 0) && (*(u8 *)(state + 0x6a) != 0)) &&
      (*(u8 *)(state + 0x69) != 4)) {
    fn_8003B8F4(obj,lbl_803E6490);
  }
}
#pragma peephole reset
#pragma scheduling reset
