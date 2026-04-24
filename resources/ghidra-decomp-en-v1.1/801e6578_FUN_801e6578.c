// Function: FUN_801e6578
// Entry: 801e6578
// Size: 112 bytes

void FUN_801e6578(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_80286840();
  uVar2 = FUN_80020078((int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x1e));
  if (uVar2 != 0) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

