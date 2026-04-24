// Function: FUN_801b0dfc
// Entry: 801b0dfc
// Size: 220 bytes

void FUN_801b0dfc(void)

{
  int iVar1;
  char in_r8;
  int iVar2;
  int *piVar3;
  
  iVar1 = FUN_8028683c();
  if (in_r8 != '\0') {
    piVar3 = *(int **)(iVar1 + 0xb8);
    iVar2 = piVar3[1];
    if (iVar2 != 0) {
      iVar2 = *(int *)(*(int *)(iVar2 + 0x7c) + *(char *)(iVar2 + 0xad) * 4);
      *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
      *(undefined *)(piVar3[1] + 0x37) = *(undefined *)(iVar1 + 0x37);
      FUN_8003b9ec(piVar3[1]);
    }
    FUN_8003b9ec(iVar1);
    iVar1 = *piVar3;
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_80060630(iVar1);
    }
  }
  FUN_80286888();
  return;
}

