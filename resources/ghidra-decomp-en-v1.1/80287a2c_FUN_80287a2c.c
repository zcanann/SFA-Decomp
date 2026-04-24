// Function: FUN_80287a2c
// Entry: 80287a2c
// Size: 128 bytes

undefined4 FUN_80287a2c(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  
  uVar4 = 0;
  iVar2 = *(int *)(param_1 + 0xc);
  bVar1 = *(int *)(param_1 + 8) == iVar2;
  if (bVar1) {
    uVar4 = 0x302;
  }
  uVar3 = (uint)!bVar1;
  FUN_80003514(param_2,param_1 + iVar2 + 0x10,uVar3);
  *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar3;
  return uVar4;
}

