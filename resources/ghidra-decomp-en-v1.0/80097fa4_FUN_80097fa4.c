// Function: FUN_80097fa4
// Entry: 80097fa4
// Size: 716 bytes

void FUN_80097fa4(double param_1,undefined4 param_2,byte param_3)

{
  int iVar1;
  undefined auStack40 [6];
  undefined2 local_22;
  float local_20;
  
  local_20 = (float)param_1;
  if (param_3 != 0) {
    if (param_3 == 3) {
      local_22 = 0xc8e;
      iVar1 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_2,0x7c8,auStack40,1,0xffffffff,0);
        iVar1 = iVar1 + 1;
      } while (iVar1 < 0x28);
      local_22 = 2;
      (**(code **)(*DAT_803dca88 + 8))(param_2,0x7f3,auStack40,1,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_2,0x7f3,auStack40,1,0xffffffff,0);
    }
    else if (param_3 < 3) {
      if (param_3 == 1) {
        local_22 = 0xc8c;
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(param_2,0x7c8,auStack40,1,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 0x28);
        local_22 = 1;
        (**(code **)(*DAT_803dca88 + 8))(param_2,0x7f3,auStack40,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_2,0x7f3,auStack40,1,0xffffffff,0);
      }
      else if (param_3 != 0) {
        local_22 = 0xc8d;
        iVar1 = 0;
        do {
          (**(code **)(*DAT_803dca88 + 8))(param_2,0x7c8,auStack40,1,0xffffffff,0);
          iVar1 = iVar1 + 1;
        } while (iVar1 < 0x28);
        local_22 = 0;
        (**(code **)(*DAT_803dca88 + 8))(param_2,0x7f3,auStack40,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_2,0x7f3,auStack40,1,0xffffffff,0);
        (**(code **)(*DAT_803dca88 + 8))(param_2,0x7f3,auStack40,1,0xffffffff,0);
      }
    }
    else if (param_3 < 5) {
      iVar1 = 0;
      local_22 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_2,0x7f2,auStack40,1,0xffffffff,0);
        iVar1 = iVar1 + 1;
      } while (iVar1 < 0x14);
    }
  }
  return;
}

