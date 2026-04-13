// Function: FUN_8021adbc
// Entry: 8021adbc
// Size: 248 bytes

void FUN_8021adbc(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  int *piVar3;
  
  iVar1 = FUN_8028683c();
  piVar3 = *(int **)(iVar1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(iVar1);
    iVar2 = *piVar3;
    if (iVar2 != 0) {
      FUN_80038524(iVar1,0,(float *)(iVar2 + 0xc),(undefined4 *)(iVar2 + 0x10),
                   (float *)(iVar2 + 0x14),0);
      FUN_8003b9ec(*piVar3);
      iVar1 = piVar3[1];
      if (iVar1 != 0) {
        *(undefined2 *)(iVar1 + 2) = *(undefined2 *)(*piVar3 + 2);
        *(undefined2 *)(iVar1 + 4) = *(undefined2 *)(*piVar3 + 4);
        FUN_80038524(*piVar3,0,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),
                     (float *)(iVar1 + 0x14),0);
        FUN_8003b9ec(iVar1);
      }
    }
  }
  FUN_80286888();
  return;
}

