// Function: FUN_801e69b0
// Entry: 801e69b0
// Size: 84 bytes

void FUN_801e69b0(int param_1,int param_2,undefined4 param_3)

{
  **(undefined **)(param_1 + 0xb8) = (char)param_2;
  if (param_2 != 0) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(param_3,param_1,0xffffffff);
  }
  return;
}

