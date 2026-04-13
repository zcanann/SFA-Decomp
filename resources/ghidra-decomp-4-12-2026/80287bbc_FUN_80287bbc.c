// Function: FUN_80287bbc
// Entry: 80287bbc
// Size: 136 bytes

void FUN_80287bbc(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 local_18;
  undefined4 local_14;
  undefined local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  undefined local_c;
  undefined local_b;
  undefined local_a;
  undefined local_9;
  
  if (DAT_803d7578 == 0) {
    local_14._3_1_ = (undefined)param_4;
    puVar1 = (undefined4 *)&local_10;
    local_14._2_1_ = (undefined)((uint)param_4 >> 8);
    local_14._1_1_ = (undefined)((uint)param_4 >> 0x10);
    local_14._0_1_ = (undefined)((uint)param_4 >> 0x18);
    local_18._3_1_ = (undefined)param_3;
    local_18._2_1_ = (undefined)((uint)param_3 >> 8);
    local_18._1_1_ = (undefined)((uint)param_3 >> 0x10);
    local_18._0_1_ = (undefined)((uint)param_3 >> 0x18);
    local_10 = (undefined)local_14;
    local_f = local_14._2_1_;
    local_e = local_14._1_1_;
    local_d = local_14._0_1_;
    local_c = (undefined)local_18;
    local_b = local_18._2_1_;
    local_a = local_18._1_1_;
    local_9 = local_18._0_1_;
  }
  else {
    puVar1 = &local_18;
  }
  local_18 = param_3;
  local_14 = param_4;
  FUN_80287d88(param_1,(undefined *)puVar1,8);
  return;
}

