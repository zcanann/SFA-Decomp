// Function: FUN_80179480
// Entry: 80179480
// Size: 100 bytes

void FUN_80179480(int param_1)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  sVar1 = *(short *)(iVar3 + 0x1c);
  if ((sVar1 != 0) && (bVar2 = FUN_8000b5f0(param_1,sVar1), bVar2)) {
    FUN_8000b844(param_1,*(short *)(iVar3 + 0x1c));
  }
  FUN_8003709c(param_1,0xe);
  return;
}

