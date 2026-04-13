// Function: FUN_8000b6b4
// Entry: 8000b6b4
// Size: 128 bytes

void FUN_8000b6b4(char param_1)

{
  bool bVar1;
  uint *puVar2;
  int iVar3;
  
  puVar2 = &DAT_80336c60;
  DAT_803dd4b8 = param_1 * '\x05';
  iVar3 = 0x37;
  do {
    if ((*puVar2 != 0xffffffff) && (*(char *)(puVar2 + 10) == '\0')) {
      FUN_80272f0c(*puVar2,0x5b,DAT_803dd4b8);
    }
    puVar2 = puVar2 + 0xe;
    bVar1 = iVar3 != 0;
    iVar3 = iVar3 + -1;
  } while (bVar1);
  return;
}

