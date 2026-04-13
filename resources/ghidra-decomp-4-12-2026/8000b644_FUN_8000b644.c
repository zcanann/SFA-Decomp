// Function: FUN_8000b644
// Entry: 8000b644
// Size: 112 bytes

void FUN_8000b644(void)

{
  bool bVar1;
  uint *puVar2;
  int iVar3;
  
  puVar2 = &DAT_80336c60;
  iVar3 = 0x37;
  do {
    if (*puVar2 != 0xffffffff) {
      FUN_80272fcc(*puVar2);
      *puVar2 = 0xffffffff;
    }
    puVar2 = puVar2 + 0xe;
    bVar1 = iVar3 != 0;
    iVar3 = iVar3 + -1;
  } while (bVar1);
  return;
}

