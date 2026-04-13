// Function: FUN_80295d6c
// Entry: 80295d6c
// Size: 104 bytes

void FUN_80295d6c(undefined4 param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  
  uVar1 = *param_2;
  if (DAT_803df0a0 != (int *)0x0) {
    FUN_80026cfc((double)FLOAT_803dd2d8,(double)FLOAT_803dd2dc,(double)FLOAT_803dd2e0,
                 (int)DAT_803df0a0);
    FUN_80026c00(param_2,uVar1,DAT_803df0a0,FUN_80295a94);
  }
  return;
}

