#include "ghidra_import.h"
#include "main/dll/texScroll.h"

extern void GameBit_Set(int eventId,int value);
extern undefined8 ObjGroup_RemoveObject();

/*
 * --INFO--
 *
 * Function: fn_8017AC2C
 * EN v1.0 Address: 0x8017AC2C
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x8017AC40
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_8017AC2C(int obj,undefined4 param_2,int stateParam)
{
  s16 objType;
  int config;
  int handle;
  u8 i;
  int runtime;
  int particleObj;

  runtime = *(int *)(obj + 0xb8);
  config = *(int *)(obj + 0x4c);
  if (*(u8 *)(stateParam + 0x80) == 1) {
    for (i = 0; i < 10; i++) {
      handle = *(int *)(runtime + (u32)i * 4 + 4);
      if (handle != 0) {
        *(f32 *)(runtime + (u32)i * 8 + 0x2c) = *(f32 *)(handle + 0xc);
        *(f32 *)(runtime + (u32)i * 8 + 0x30) =
            *(f32 *)(*(int *)(runtime + (u32)i * 4 + 4) + 0x14);
      }
    }
    *(u8 *)(stateParam + 0x80) = 0;
  }
  else if (*(u8 *)(stateParam + 0x80) == 2) {
    for (i = 0; i < 10; i += 5) {
      particleObj = runtime + (u32)i * 4 + 4;
      *(undefined4 *)(particleObj + 0x0) = 0;
      *(undefined4 *)(particleObj + 0x4) = 0;
      *(undefined4 *)(particleObj + 0x8) = 0;
      *(undefined4 *)(particleObj + 0xc) = 0;
      *(undefined4 *)(particleObj + 0x10) = 0;
    }
    *(f32 *)(obj + 0x14) = *(f32 *)(config + 8);
    *(f32 *)(obj + 0x10) = *(f32 *)(runtime + 0x7c);
    *(f32 *)(obj + 0x14) = *(f32 *)(config + 0x10);
    GameBit_Set(*(s16 *)(config + 0x1a),0);
    *(u8 *)(stateParam + 0x80) = 0;
  }
  objType = *(s16 *)(obj + 0x46);
  if ((((objType != 0x19f) && (objType != 0x26c)) && (objType != 0x274)) &&
      (objType != 0x545)) {
    *(f32 *)(runtime + 0x7c) = *(f32 *)(obj + 0x10);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: pressureswitchfb_getExtraSize
 * EN v1.0 Address: 0x8017AD88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8017ADC4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int pressureswitchfb_getExtraSize(void)
{
  return 0x88;
}

/*
 * --INFO--
 *
 * Function: pressureswitchfb_free
 * EN v1.0 Address: 0x8017AD90
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017ADCC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void pressureswitchfb_free(int obj)
{
  ObjGroup_RemoveObject(obj,0x53);
}
#pragma scheduling reset
