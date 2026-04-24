// Function: FUN_80287348
// Entry: 80287348
// Size: 168 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_80287348(undefined4 param_1,undefined4 *param_2,int param_3)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 local_28;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  
  iVar1 = 0;
  for (iVar3 = 0; (iVar1 == 0 && (iVar3 < param_3)); iVar3 = iVar3 + 1) {
    local_28 = *param_2;
    if (DAT_803d6918 == 0) {
      puVar2 = (undefined4 *)&local_24;
      local_28._2_1_ = (undefined)((uint)local_28 >> 8);
      local_28._1_1_ = (undefined)((uint)local_28 >> 0x10);
      local_28._0_1_ = (undefined)((uint)local_28 >> 0x18);
      local_24 = (undefined)local_28;
      local_23 = local_28._2_1_;
      local_22 = local_28._1_1_;
      local_21 = local_28._0_1_;
    }
    else {
      puVar2 = &local_28;
    }
    iVar1 = FUN_80287624(param_1,puVar2,4);
    param_2 = param_2 + 1;
  }
  return;
}

