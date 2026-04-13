// Function: FUN_801ed478
// Entry: 801ed478
// Size: 132 bytes

void FUN_801ed478(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003709c(param_1,10);
  iVar2 = 0;
  iVar3 = iVar1;
  do {
    FUN_800238c4(*(uint *)(iVar3 + 0x4c8));
    iVar3 = iVar3 + 8;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 9);
  if ((*(byte *)(iVar1 + 0x428) >> 5 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
  }
  return;
}

