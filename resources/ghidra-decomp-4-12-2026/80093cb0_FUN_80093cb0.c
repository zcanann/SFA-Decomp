// Function: FUN_80093cb0
// Entry: 80093cb0
// Size: 176 bytes

void FUN_80093cb0(void)

{
  int iVar1;
  int *piVar2;
  
  if (DAT_803dde48 != 0) {
    FUN_80054484();
    DAT_803dde48 = 0;
  }
  iVar1 = 0;
  piVar2 = &DAT_8039b478;
  do {
    if (*piVar2 != 0) {
      FUN_80054484();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  if (DAT_803dde44 != 0) {
    FUN_80054484();
    DAT_803dde44 = 0;
  }
  if (DAT_803dde20 != 0) {
    FUN_8001f448(DAT_803dde20);
  }
  DAT_803dde40 = 0;
  return;
}

