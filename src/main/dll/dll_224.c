#include "ghidra_import.h"
#include "main/dll/dll_224.h"

extern undefined4 FUN_800305f8();

extern f32 lbl_803E5928;
extern f32 lbl_803E5930;

/*
 * --INFO--
 *
 * Function: dll_DIM_BossGutSpik_update
 * EN v1.0 Address: 0x801BE44C
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x801BE4D4
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
dll_DIM_BossGutSpik_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                           undefined8 param_5,undefined8 param_6,undefined8 param_7,
                           undefined8 param_8,undefined4 param_9,int param_10,
                           undefined4 param_11,undefined4 param_12,undefined4 param_13,
                           undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E5928,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = lbl_803E5930;
  return 0;
}
