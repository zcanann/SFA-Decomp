// Function: FUN_80125d04
// Entry: 80125d04
// Size: 136 bytes

void FUN_80125d04(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = 0;
  piVar3 = &DAT_803a93f8;
  do {
    iVar1 = *piVar3;
    if (iVar1 != 0) {
      if (0x90000000 < *(uint *)(iVar1 + 0x4c)) {
        *(undefined4 *)(iVar1 + 0x4c) = 0;
      }
      FUN_8002cbc4(*piVar3);
      *piVar3 = 0;
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  return;
}

