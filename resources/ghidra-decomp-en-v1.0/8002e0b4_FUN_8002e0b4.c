// Function: FUN_8002e0b4
// Entry: 8002e0b4
// Size: 72 bytes

int FUN_8002e0b4(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  piVar1 = DAT_803dcb88;
  iVar3 = DAT_803dcb84;
  if (0 < DAT_803dcb84) {
    do {
      iVar2 = *(int *)(*piVar1 + 0x4c);
      if ((iVar2 != 0) && (*(int *)(iVar2 + 0x14) == param_1)) {
        return *piVar1;
      }
      piVar1 = piVar1 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return 0;
}

