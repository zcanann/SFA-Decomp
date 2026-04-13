// Function: FUN_8001ff38
// Entry: 8001ff38
// Size: 28 bytes

void FUN_8001ff38(undefined4 param_1)

{
  uint uVar1;
  
  uVar1 = (uint)DAT_803dd6c8;
  DAT_803dd6c8 = DAT_803dd6c8 + 1;
  *(undefined4 *)(&DAT_803dd768 + uVar1 * 4) = param_1;
  return;
}

