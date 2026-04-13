// Function: FUN_80271afc
// Entry: 80271afc
// Size: 148 bytes

void FUN_80271afc(int *param_1,undefined *param_2)

{
  byte *pbVar1;
  int *piVar2;
  int *piVar3;
  
  piVar2 = (int *)*param_1;
  while (piVar2 != (int *)0x0) {
    piVar3 = (int *)*piVar2;
    *(undefined *)((int)piVar2 + 9) = 0xff;
    pbVar1 = (byte *)(piVar2 + 2);
    piVar2 = piVar3;
    if (*(char *)(DAT_803deee8 + (uint)*pbVar1 * 0x404 + 0x11c) == '\0') {
      (*(code *)param_2)();
    }
  }
  *param_1 = 0;
  return;
}

