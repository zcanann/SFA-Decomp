#include "ghidra_import.h"
#include "main/dll/NW/NWtricky.h"

extern uint FUN_80022264();
extern undefined4 FUN_80036018();
extern undefined4 FUN_8003613c();
extern undefined4 FUN_8003709c();

extern undefined4* DAT_803dd6f8;
extern f64 DOUBLE_803e5fa0;
extern f32 FLOAT_803e5f90;
extern f32 FLOAT_803e5f94;
extern f32 FLOAT_803e5f98;
extern f32 FLOAT_803e5f9c;

/*
 * --INFO--
 *
 * Function: FUN_801d21ec
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D21EC
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d21ec(undefined2 *param_1,undefined4 *param_2,int param_3)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x26);
  uVar1 = FUN_80022264(0xfffffa24,0x5dc);
  param_1[2] = (short)uVar1;
  uVar1 = FUN_80022264(0xfffffa24,0x5dc);
  param_1[1] = (short)uVar1;
  uVar1 = FUN_80022264(0xfffffa24,0x5dc);
  *param_1 = (short)uVar1;
  *(undefined *)(param_1 + 0x1b) = 0xff;
  param_1[3] = param_1[3] & 0xbfff;
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar2 + 8);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar2 + 0xc);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar2 + 0x10);
  if (param_3 != 0) {
    *(float *)(param_1 + 4) = FLOAT_803e5f90;
    *param_2 = FLOAT_803e5f94;
    uVar1 = FUN_80022264(0,100);
    param_2[2] = FLOAT_803e5f98 +
                 (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5fa0);
    uVar1 = FUN_80022264(0xffffff9c,100);
    param_2[1] = FLOAT_803e5f9c *
                 (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e5fa0) +
                 (float)param_2[3];
    param_2[4] = (float)param_2[1] / (float)param_2[2];
  }
  FUN_80036018((int)param_1);
  FUN_8003613c((int)param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d2364
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D2364
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d2364(int param_1)
{
  (**(code **)(*DAT_803dd6f8 + 0x14))();
  FUN_8003709c(param_1,3);
  return;
}
