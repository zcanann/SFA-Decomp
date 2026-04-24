// Function: FUN_801cf010
// Entry: 801cf010
// Size: 156 bytes

void FUN_801cf010(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003b8f4((double)FLOAT_803e5210);
  iVar2 = 0;
  iVar3 = iVar1;
  do {
    FUN_8003842c(param_1,iVar2,iVar3 + 0x45c,iVar3 + 0x460,iVar3 + 0x464,0);
    iVar3 = iVar3 + 0xc;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  FUN_8003842c(param_1,4,iVar1 + 0xc,iVar1 + 0x10,iVar1 + 0x14,0);
  return;
}

