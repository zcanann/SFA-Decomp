// Function: FUN_80196a30
// Entry: 80196a30
// Size: 100 bytes

void FUN_80196a30(int param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x32));
  *(bool *)(iVar2 + 2) = uVar1 != 0;
  FUN_800372f8(param_1,0x1a);
  return;
}

