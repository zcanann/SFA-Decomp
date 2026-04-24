// Function: FUN_8009ad44
// Entry: 8009ad44
// Size: 168 bytes

void FUN_8009ad44(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 0;
  puVar2 = &DAT_8039ab58;
  do {
    if ((puVar2[2] != 0) && (puVar2[1] = puVar2[1] - (uint)DAT_803db410, (int)puVar2[1] < 1)) {
      puVar2[2] = 0;
      puVar2[1] = 0;
      puVar2[3] = 0;
      DAT_803dd258 = 1;
      FUN_80054308(*puVar2);
      DAT_803dd258 = 0;
      *puVar2 = 0;
    }
    puVar2 = puVar2 + 4;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x20);
  return;
}

