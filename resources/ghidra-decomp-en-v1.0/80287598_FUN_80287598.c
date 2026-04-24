// Function: FUN_80287598
// Entry: 80287598
// Size: 140 bytes

undefined4 FUN_80287598(int param_1,undefined4 param_2,uint param_3)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  if (param_3 == 0) {
    uVar2 = 0;
  }
  else {
    uVar1 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
    if (uVar1 < param_3) {
      uVar2 = 0x302;
      param_3 = uVar1;
    }
    FUN_80003514(param_2,param_1 + *(int *)(param_1 + 0xc) + 0x10,param_3);
    *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + param_3;
  }
  return uVar2;
}

