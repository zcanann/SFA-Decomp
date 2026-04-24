// Function: FUN_802874e0
// Entry: 802874e0
// Size: 100 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_802874e0(undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  undefined4 local_8;
  undefined local_4;
  undefined local_3;
  undefined local_2;
  undefined local_1;
  
  if (DAT_803d6918 == 0) {
    local_8._3_1_ = (undefined)param_2;
    puVar1 = (undefined4 *)&local_4;
    local_8._2_1_ = (undefined)((uint)param_2 >> 8);
    local_8._1_1_ = (undefined)((uint)param_2 >> 0x10);
    local_8._0_1_ = (undefined)((uint)param_2 >> 0x18);
    local_4 = (undefined)local_8;
    local_3 = local_8._2_1_;
    local_2 = local_8._1_1_;
    local_1 = local_8._0_1_;
  }
  else {
    puVar1 = &local_8;
  }
  local_8 = param_2;
  FUN_80287624(param_1,puVar1,4);
  return;
}

