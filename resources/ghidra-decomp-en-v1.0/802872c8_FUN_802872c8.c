// Function: FUN_802872c8
// Entry: 802872c8
// Size: 128 bytes

undefined4 FUN_802872c8(int param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar3 = 0;
  iVar1 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
  iVar2 = 1;
  if (iVar1 == 0) {
    uVar3 = 0x302;
    iVar2 = iVar1;
  }
  FUN_80003514(param_2,param_1 + *(int *)(param_1 + 0xc) + 0x10,iVar2);
  *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + iVar2;
  return uVar3;
}

