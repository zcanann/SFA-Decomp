#include "main/dll/cloudprisoncontrol.h"
#include "main/game_object.h"

extern void ObjHitbox_SetSphereRadius(int obj, int radius);
extern int GameBit_Get(int bitId);

extern f32 lbl_803E3750;

/*
 * --INFO--
 *
 * Function: InvisibleHitSwitch_init
 * EN v1.0 Address: 0x8017AB20
 * EN v1.0 Size: 268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void InvisibleHitSwitch_init(int param_1, u8 *param_2)
{
  u8 *info;

  info = (u8 *)*(int *)&((GameObject *)param_1)->extra;
  ((GameObject *)param_1)->objectFlags = (u16)(((GameObject *)param_1)->objectFlags | 0x6000);
  if (param_2[0x1d] == 0) {
    ((GameObject *)param_1)->anim.rootMotionScale = *(f32 *)(*(int *)&((GameObject *)param_1)->anim.modelInstance + 4);
  } else {
    {
      f32 v = (f32)(u32)param_2[0x1d] * *(f32 *)(*(int *)&((GameObject *)param_1)->anim.modelInstance + 4);
      ((GameObject *)param_1)->anim.rootMotionScale = v * lbl_803E3750;
    }
  }
  ObjHitbox_SetSphereRadius(
      param_1,
      (s16)((param_2[0x1d] * (int)*(u8 *)(*(int *)&((GameObject *)param_1)->anim.modelInstance + 0x62)) / 64));
  info[0] = (u8)GameBit_Get(*(s16 *)(param_2 + 0x18));
  switch ((param_2[0x23] & 0xe) >> 1) {
  case 0:
  default:
    info[1] = 5;
    break;
  case 1:
    info[1] = 0x10;
    break;
  case 2:
    info[1] = 0x15;
    break;
  }
}
