// Function: FUN_8000bdd4
// Entry: 8000bdd4
// Size: 172 bytes

void FUN_8000bdd4(void)

{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  uint *puVar4;
  
  iVar3 = 0x38;
  puVar2 = (undefined4 *)&DAT_803378a0;
  while( true ) {
    puVar2 = puVar2 + -0xe;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *puVar2 = 0xffffffff;
  }
  DAT_803dd4c4 = 0;
  DAT_803dd4c0 = 0;
  puVar4 = &DAT_80336c60;
  DAT_803dd4b8 = 0;
  iVar3 = 0x37;
  do {
    if ((*puVar4 != 0xffffffff) && (*(char *)(puVar4 + 10) == '\0')) {
      FUN_80272f0c(*puVar4,0x5b,DAT_803dd4b8);
    }
    puVar4 = puVar4 + 0xe;
    bVar1 = iVar3 != 0;
    iVar3 = iVar3 + -1;
  } while (bVar1);
  return;
}

