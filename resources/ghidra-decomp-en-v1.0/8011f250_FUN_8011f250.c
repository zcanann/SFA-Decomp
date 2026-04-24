// Function: FUN_8011f250
// Entry: 8011f250
// Size: 244 bytes

void FUN_8011f250(void)

{
  int *piVar1;
  int iVar2;
  
  DAT_803dd793 = 0;
  DAT_803dba70 = 0xffff;
  DAT_803dd8d0 = 0;
  DAT_803dd7a8 = 0;
  FUN_8011f72c();
  DAT_803dd780 = 0;
  DAT_803dd778 = 0;
  DAT_803dd730 = 0;
  DAT_803dd770 = 0;
  FLOAT_803dd760 = FLOAT_803e1e3c;
  iVar2 = 0;
  piVar1 = &DAT_803a9410;
  do {
    if (*piVar1 != 0) {
      *(undefined4 *)(*(int *)(*piVar1 + 100) + 4) = 0;
      *(undefined4 *)(*(int *)(*piVar1 + 100) + 8) = 0;
      if (0x90000000 < *(uint *)(*piVar1 + 0x4c)) {
        *(undefined4 *)(*piVar1 + 0x4c) = 0;
      }
      FUN_8002cbc4(*piVar1);
      *piVar1 = 0;
    }
    piVar1 = piVar1 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  DAT_803dd75a = 0;
  DAT_803dd75b = 0;
  DAT_803dd772 = 0;
  DAT_803dd788 = 0x3c;
  DAT_803dd792 = 0;
  return;
}

