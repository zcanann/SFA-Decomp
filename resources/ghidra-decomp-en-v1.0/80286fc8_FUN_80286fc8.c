// Function: FUN_80286fc8
// Entry: 80286fc8
// Size: 152 bytes

void FUN_80286fc8(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar2 = 0;
  for (iVar3 = 0; (iVar2 == 0 && (iVar3 < param_3)); iVar3 = iVar3 + 1) {
    iVar2 = 0;
    iVar1 = *(int *)(param_1 + 8) - *(int *)(param_1 + 0xc);
    iVar4 = 1;
    if (iVar1 == 0) {
      iVar2 = 0x302;
      iVar4 = iVar1;
    }
    FUN_80003514(param_2 + iVar3,param_1 + *(int *)(param_1 + 0xc) + 0x10,iVar4);
    *(int *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + iVar4;
  }
  return;
}

