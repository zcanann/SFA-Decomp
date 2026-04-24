// Function: FUN_8025105c
// Entry: 8025105c
// Size: 112 bytes

undefined4 * FUN_8025105c(undefined4 *param_1)

{
  undefined4 uVar1;
  
  uVar1 = FUN_8024377c();
  FUN_8025186c(param_1);
  *param_1 = 0;
  param_1[2] = 1;
  FUN_802437a4(uVar1);
  if (param_1 == DAT_803de078) {
    FUN_802516e0(param_1);
  }
  return param_1;
}

