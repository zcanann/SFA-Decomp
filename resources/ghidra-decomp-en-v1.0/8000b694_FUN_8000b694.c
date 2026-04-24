// Function: FUN_8000b694
// Entry: 8000b694
// Size: 128 bytes

void FUN_8000b694(char param_1)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  
  piVar2 = &DAT_80336000;
  DAT_803dc838 = param_1 * '\x05';
  iVar3 = 0x37;
  do {
    if ((*piVar2 != -1) && (*(char *)(piVar2 + 10) == '\0')) {
      FUN_802727a8(*piVar2,0x5b,DAT_803dc838);
    }
    piVar2 = piVar2 + 0xe;
    bVar1 = iVar3 != 0;
    iVar3 = iVar3 + -1;
  } while (bVar1);
  return;
}

