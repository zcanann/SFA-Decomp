// Function: FUN_801d5ed4
// Entry: 801d5ed4
// Size: 132 bytes

void FUN_801d5ed4(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8003b8f4((double)FLOAT_803e5448);
  FUN_80114dec(param_1,iVar2,0);
  iVar1 = 0;
  do {
    FUN_8003842c(param_1,iVar1,iVar2 + 0x8e0,iVar2 + 0x8e4,iVar2 + 0x8e8,0);
    iVar2 = iVar2 + 0xc;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  return;
}

