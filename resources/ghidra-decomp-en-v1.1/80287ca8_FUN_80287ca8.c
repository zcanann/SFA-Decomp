// Function: FUN_80287ca8
// Entry: 80287ca8
// Size: 84 bytes

void FUN_80287ca8(int param_1,undefined2 param_2)

{
  undefined2 *puVar1;
  undefined2 local_8;
  undefined local_4;
  undefined local_3;
  
  if (DAT_803d7578 == 0) {
    local_8._1_1_ = (undefined)param_2;
    puVar1 = (undefined2 *)&local_4;
    local_8._0_1_ = (undefined)((ushort)param_2 >> 8);
    local_4 = (undefined)local_8;
    local_3 = local_8._0_1_;
  }
  else {
    puVar1 = &local_8;
  }
  local_8 = param_2;
  FUN_80287d88(param_1,(undefined *)puVar1,2);
  return;
}

