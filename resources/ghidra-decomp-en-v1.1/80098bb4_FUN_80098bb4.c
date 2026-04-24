// Function: FUN_80098bb4
// Entry: 80098bb4
// Size: 496 bytes

void FUN_80098bb4(double param_1,undefined4 param_2,byte param_3,undefined2 param_4,
                 undefined2 param_5,undefined4 param_6)

{
  uint uVar1;
  int iVar2;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  undefined2 local_22;
  float local_20;
  
  uVar1 = (uint)DAT_803dc070;
  if (3 < uVar1) {
    uVar1 = 3;
  }
  local_20 = (float)param_1;
  if (param_3 != 0) {
    local_24 = param_5;
    local_22 = param_4;
    if (param_3 == 3) {
      local_28 = 0;
      local_26 = 1;
      for (iVar2 = 0; iVar2 < (int)uVar1; iVar2 = iVar2 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(param_2,0x7b7,&local_28,1,0xffffffff,param_6);
      }
    }
    else if (param_3 < 3) {
      if (param_3 == 1) {
        local_28 = 0;
        local_26 = 0;
        for (iVar2 = 0; iVar2 < (int)uVar1; iVar2 = iVar2 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(param_2,0x7b7,&local_28,1,0xffffffff,param_6);
        }
      }
      else if (param_3 != 0) {
        local_28 = 1;
        local_26 = 0;
        for (iVar2 = 0; iVar2 < (int)uVar1; iVar2 = iVar2 + 1) {
          (**(code **)(*DAT_803dd708 + 8))(param_2,0x7b7,&local_28,1,0xffffffff,param_6);
        }
      }
    }
    else if (param_3 < 5) {
      local_28 = 1;
      local_26 = 1;
      for (iVar2 = 0; iVar2 < (int)uVar1; iVar2 = iVar2 + 1) {
        (**(code **)(*DAT_803dd708 + 8))(param_2,0x7b7,&local_28,1,0xffffffff,param_6);
      }
    }
  }
  return;
}

