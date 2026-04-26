#include "main/dll/SC/SClantern.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern undefined4 fn_8000BAE0();
extern undefined4 Sfx_PlayFromObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 fn_80296554();
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 fn_8002B9EC();

extern undefined lbl_803AD048[];
extern undefined4* lbl_803DCAAC;
extern f32 FLOAT_803db414;
extern f32 lbl_803E5498;

/*
 * --INFO--
 *
 * Function: SHthorntail_init
 * EN v1.0 Address: 0x801D6C04
 * EN v1.0 Size: 340b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void SHthorntail_init(void)
{
  short *obj;
  undefined4 advanceResult;
  undefined *event;
  int pointIndex;
  int i;
  float local_28;
  float local_24;
  float local_20[8];

  obj = (short *)FUN_8028683c();
  pointIndex = 0;
  lbl_803AD048[0x1b] = 0;
  lbl_803AD048[0x12] = 0;
  advanceResult = ObjAnim_AdvanceCurrentMove((double)FLOAT_803db414,(double)FLOAT_803db414,(int)obj,
                                             (ObjAnimEventList *)lbl_803AD048);
  if (lbl_803AD048[0x12] != 0) {
    *obj = *obj + *(short *)(lbl_803AD048 + 0xe);
  }
  event = lbl_803AD048;
  for (i = 0; i < lbl_803AD048[0x1b]; i++) {
    switch(event[0x13]) {
    case 1:
    case 3:
      pointIndex = 1;
      break;
    case 2:
    case 4:
      pointIndex = 2;
      break;
    case 9:
      Sfx_PlayFromObject((int)obj,0x2f4);
    }
    event++;
  }
  if ((pointIndex != 0) &&
      (ObjPath_GetPointWorldPosition((int)obj,pointIndex - 1,&local_28,&local_24,local_20,0),
       ((obj[0x50] != 0x1b || (lbl_803E5498 <= *(float *)(obj + 0x4c)))))) {
    fn_8000BAE0((double)local_28,(double)local_24,(double)local_20[0],obj,0x415);
  }
  FUN_80286888(advanceResult);
}

/*
 * --INFO--
 *
 * Function: fn_801D6D58
 * EN v1.0 Address: 0x801D6D58
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_801D6D58(void)
{
  undefined4 playerObj;

  (**(code **)(*lbl_803DCAAC + 0x74))();
  playerObj = fn_8002B9EC();
  fn_80296554(playerObj,0xff);
  return 2;
}
