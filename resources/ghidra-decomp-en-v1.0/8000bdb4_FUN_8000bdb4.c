// Function: FUN_8000bdb4
// Entry: 8000bdb4
// Size: 172 bytes

void FUN_8000bdb4(void)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  int *piVar4;
  
  iVar3 = 0x38;
  puVar2 = (undefined4 *)&DAT_80336c40;
  while( true ) {
    puVar2 = puVar2 + -0xe;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *puVar2 = 0xffffffff;
  }
  DAT_803dc844 = 0;
  DAT_803dc840 = 0;
  piVar4 = &DAT_80336000;
  DAT_803dc838 = 0;
  iVar3 = 0x37;
  do {
    if ((*piVar4 != -1) && (*(char *)(piVar4 + 10) == '\0')) {
      FUN_802727a8(*piVar4,0x5b,DAT_803dc838);
    }
    piVar4 = piVar4 + 0xe;
    bVar1 = iVar3 != 0;
    iVar3 = iVar3 + -1;
  } while (bVar1);
  return;
}

