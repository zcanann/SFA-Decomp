// Function: FUN_800d85a4
// Entry: 800d85a4
// Size: 264 bytes

void FUN_800d85a4(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  while ((param_4 != 0 && (param_1 != 0))) {
    if (param_5 == 0) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,param_3,0,2,0xffffffff,0);
    }
    else if (param_5 == 1) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,param_3,0,2,0xffffffff,0);
    }
    else if (param_5 == 2) {
      (**(code **)(*DAT_803dca88 + 8))(param_1,param_3,0,4,0xffffffff,0);
    }
    param_4 = param_4 + -1;
  }
  return;
}

