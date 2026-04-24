// Function: FUN_800191a4
// Entry: 800191a4
// Size: 88 bytes

int FUN_800191a4(int param_1)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = &DAT_802c8e70;
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

