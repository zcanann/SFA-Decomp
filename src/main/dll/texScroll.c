#include "ghidra_import.h"
#include "main/dll/texScroll.h"

extern void GameBit_Set(int eventId,int value);
extern undefined8 ObjGroup_RemoveObject();

#define PRESSURESWITCHFB_STATE_IDLE 0
#define PRESSURESWITCHFB_STATE_CAPTURE_POSITIONS 1
#define PRESSURESWITCHFB_STATE_RESET 2

#define PRESSURESWITCHFB_TRACKED_OBJECT_COUNT 10
#define PRESSURESWITCHFB_TRACKED_OBJECT_BATCH 5

#define PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET 0x04
#define PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET 0x2c
#define PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET 0x7c
#define PRESSURESWITCHFB_EXTRA_SIZE 0x88

#define PRESSURESWITCHFB_CONFIG_BASE_COORD_OFFSET 0x08
#define PRESSURESWITCHFB_CONFIG_RESET_COORD_OFFSET 0x10
#define PRESSURESWITCHFB_CONFIG_RAISED_GAMEBIT_OFFSET 0x1a

#define PRESSURESWITCHFB_STATE_MODE_OFFSET 0x80
#define PRESSURESWITCHFB_REMOVE_GROUP_ID 0x53

#define PRESSURESWITCHFB_OBJ_LINK_SNOWPR 0x019f
#define PRESSURESWITCHFB_OBJ_SH_PRESSURE 0x026c
#define PRESSURESWITCHFB_OBJ_LINK_UNDERW 0x0274
#define PRESSURESWITCHFB_OBJ_CC_PRESSURE 0x0545

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
#pragma scheduling off
#pragma peephole off
undefined4 fn_8017AC2C(int obj,undefined4 param_2,int stateParam)
{
  s16 objType;
  int config;
  u32 handle;
  u32 offset;
  u8 i;
  int runtime;
  int particleObj;

  runtime = *(int *)(obj + 0xb8);
  config = *(int *)(obj + 0x4c);
  if (*(u8 *)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) ==
      PRESSURESWITCHFB_STATE_CAPTURE_POSITIONS) {
    for (i = 0; i < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT; i++) {
      offset = (u32)i * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET;
      handle = *(u32 *)(runtime + offset);
      if (handle != 0) {
        *(f32 *)(runtime + (u32)i * 8 + PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET) =
            *(f32 *)(handle + 0xc);
        *(f32 *)(runtime + (u32)i * 8 + (PRESSURESWITCHFB_RUNTIME_TRACKED_POSITIONS_OFFSET + 4)) =
            *(f32 *)(*(int *)(runtime + offset) + 0x14);
      }
    }
    *(u8 *)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) =
        PRESSURESWITCHFB_STATE_IDLE;
  }
  else if (*(u8 *)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) ==
           PRESSURESWITCHFB_STATE_RESET) {
    for (i = 0; i < PRESSURESWITCHFB_TRACKED_OBJECT_COUNT;
         i += PRESSURESWITCHFB_TRACKED_OBJECT_BATCH) {
      particleObj = runtime + (u32)i * 4 + PRESSURESWITCHFB_RUNTIME_TRACKED_OBJECTS_OFFSET;
      *(undefined4 *)(particleObj + 0x0) = 0;
      *(undefined4 *)(particleObj + 0x4) = 0;
      *(undefined4 *)(particleObj + 0x8) = 0;
      *(undefined4 *)(particleObj + 0xc) = 0;
      *(undefined4 *)(particleObj + 0x10) = 0;
    }
    *(f32 *)(obj + 0x14) = *(f32 *)(config + PRESSURESWITCHFB_CONFIG_BASE_COORD_OFFSET);
    *(f32 *)(obj + 0x10) = *(f32 *)(runtime + PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET);
    *(f32 *)(obj + 0x14) = *(f32 *)(config + PRESSURESWITCHFB_CONFIG_RESET_COORD_OFFSET);
    GameBit_Set(*(s16 *)(config + PRESSURESWITCHFB_CONFIG_RAISED_GAMEBIT_OFFSET),0);
    *(u8 *)(stateParam + PRESSURESWITCHFB_STATE_MODE_OFFSET) =
        PRESSURESWITCHFB_STATE_IDLE;
  }
  objType = *(s16 *)(obj + 0x46);
  if ((((objType != PRESSURESWITCHFB_OBJ_LINK_SNOWPR) &&
        (objType != PRESSURESWITCHFB_OBJ_SH_PRESSURE)) &&
       (objType != PRESSURESWITCHFB_OBJ_LINK_UNDERW)) &&
      (objType != PRESSURESWITCHFB_OBJ_CC_PRESSURE)) {
    *(f32 *)(runtime + PRESSURESWITCHFB_RUNTIME_BASE_COORD_OFFSET) = *(f32 *)(obj + 0x10);
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

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
  return PRESSURESWITCHFB_EXTRA_SIZE;
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
#pragma peephole off
void pressureswitchfb_free(int obj)
{
  ObjGroup_RemoveObject(obj,PRESSURESWITCHFB_REMOVE_GROUP_ID);
}
#pragma peephole reset
#pragma scheduling reset
