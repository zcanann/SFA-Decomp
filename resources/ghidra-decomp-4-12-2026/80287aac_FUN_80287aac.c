// Function: FUN_80287aac
// Entry: 80287aac
// Size: 168 bytes

void FUN_80287aac(int param_1,undefined4 *param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 local_28;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  
  iVar1 = 0;
  for (iVar4 = 0; (iVar1 == 0 && (iVar4 < param_3)); iVar4 = iVar4 + 1) {
    uVar2 = *param_2;
    if (DAT_803d7578 == 0) {
      local_28._3_1_ = (undefined)uVar2;
      puVar3 = (undefined4 *)&local_24;
      local_28._2_1_ = (undefined)((uint)uVar2 >> 8);
      local_28._1_1_ = (undefined)((uint)uVar2 >> 0x10);
      local_28._0_1_ = (undefined)((uint)uVar2 >> 0x18);
      local_24 = (undefined)local_28;
      local_23 = local_28._2_1_;
      local_22 = local_28._1_1_;
      local_21 = local_28._0_1_;
    }
    else {
      puVar3 = &local_28;
    }
    local_28 = uVar2;
    iVar1 = FUN_80287d88(param_1,(undefined *)puVar3,4);
    param_2 = param_2 + 1;
  }
  return;
}

