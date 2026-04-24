// Function: FUN_80287544
// Entry: 80287544
// Size: 84 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_80287544(undefined4 param_1,undefined2 param_2)

{
  undefined2 *puVar1;
  undefined2 local_8;
  undefined local_4;
  undefined local_3;
  
  if (DAT_803d6918 == 0) {
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
  FUN_80287624(param_1,puVar1,2);
  return;
}

