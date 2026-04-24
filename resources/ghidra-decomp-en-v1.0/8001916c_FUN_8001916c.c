// Function: FUN_8001916c
// Entry: 8001916c
// Size: 88 bytes

int FUN_8001916c(int param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = &DAT_802c86f0;
  iVar2 = 0x17;
  while( true ) {
    if (*piVar1 == param_1) {
      return piVar1[1];
    }
    if (piVar1[2] == param_1) break;
    piVar1 = piVar1 + 4;
    iVar2 = iVar2 + -1;
    if (iVar2 == 0) {
      return 0;
    }
  }
  return piVar1[3];
}

