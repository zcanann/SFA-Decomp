// Function: FUN_8005405c
// Entry: 8005405c
// Size: 76 bytes

int FUN_8005405c(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  piVar1 = DAT_803dda44;
  iVar3 = DAT_803dda3c;
  if (0 < DAT_803dda3c) {
    do {
      if (param_1 == *piVar1) {
        return DAT_803dda44[iVar2 * 4 + 1];
      }
      piVar1 = piVar1 + 4;
      iVar2 = iVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return 0;
}

