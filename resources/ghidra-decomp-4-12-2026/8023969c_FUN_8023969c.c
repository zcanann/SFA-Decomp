// Function: FUN_8023969c
// Entry: 8023969c
// Size: 160 bytes

void FUN_8023969c(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar3 + 0x1e));
  if (uVar1 == 0) {
    iVar2 = FUN_8003811c(param_1);
    if (iVar2 == 0) {
      FUN_80041110();
    }
    else {
      FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

