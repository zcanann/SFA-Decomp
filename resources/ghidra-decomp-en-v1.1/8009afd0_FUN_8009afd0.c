// Function: FUN_8009afd0
// Entry: 8009afd0
// Size: 168 bytes

void FUN_8009afd0(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 0;
  puVar2 = &DAT_8039b7b8;
  do {
    if ((puVar2[2] != 0) && (puVar2[1] = puVar2[1] - (uint)DAT_803dc070, (int)puVar2[1] < 1)) {
      puVar2[2] = 0;
      puVar2[1] = 0;
      puVar2[3] = 0;
      DAT_803dded8 = 1;
      FUN_80054484();
      DAT_803dded8 = 0;
      *puVar2 = 0;
    }
    puVar2 = puVar2 + 4;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x20);
  return;
}

