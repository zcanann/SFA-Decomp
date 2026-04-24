// Function: FUN_8028772c
// Entry: 8028772c
// Size: 152 bytes

void FUN_8028772c(int param_1,int param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  iVar2 = 0;
  for (iVar4 = 0; (iVar2 == 0 && (iVar4 < param_3)); iVar4 = iVar4 + 1) {
    iVar3 = *(int *)(param_1 + 0xc);
    iVar2 = 0;
    bVar1 = *(int *)(param_1 + 8) == iVar3;
    if (bVar1) {
      iVar2 = 0x302;
    }
    uVar5 = (uint)!bVar1;
    FUN_80003514(param_2 + iVar4,param_1 + iVar3 + 0x10,uVar5);
    *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + uVar5;
  }
  return;
}

