// Function: FUN_800d8830
// Entry: 800d8830
// Size: 264 bytes

void FUN_800d8830(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  while ((param_4 != 0 && (param_1 != 0))) {
    if (param_5 == 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,param_3,0,2,0xffffffff,0);
    }
    else if (param_5 == 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,param_3,0,2,0xffffffff,0);
    }
    else if (param_5 == 2) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,param_3,0,4,0xffffffff,0);
    }
    param_4 = param_4 + -1;
  }
  return;
}

