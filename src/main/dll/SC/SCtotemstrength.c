#include "ghidra_import.h"
#include "main/dll/SC/SCtotemstrength.h"

extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_80080f14();
extern undefined4 FUN_801d80f4();
extern undefined4 FUN_801d8524();

extern undefined4* DAT_803dd6e8;

/*
 * --INFO--
 *
 * Function: FUN_801d80f4
 * EN v1.0 Address: 0x801D80F4
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801D81A0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d80f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  
  FUN_80080f14(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
  uVar1 = FUN_80017690(0x13f);
  if (uVar1 == 0) {
    (**(code **)(*DAT_803dd6e8 + 100))();
  }
  uVar1 = FUN_80017690(0x193);
  if (uVar1 != 0) {
    FUN_80017698(0x194,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d8180
 * EN v1.0 Address: 0x801D8180
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801D8204
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801d8180(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            undefined4 param_10,int param_11)
{
  int iVar1;
  
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar1 = iVar1 + 1) {
    if (*(char *)(param_11 + iVar1 + 0x81) == '\0') {
      param_1 = FUN_801d8524(*(uint **)(param_9 + 0xb8));
    }
  }
  FUN_801d80f4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               *(int *)(param_9 + 0xb8));
  return 0;
}
