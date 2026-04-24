// Function: FUN_8027bde0
// Entry: 8027bde0
// Size: 220 bytes

undefined4 FUN_8027bde0(void)

{
  byte bVar1;
  int iVar2;
  undefined4 *puVar3;
  
  FUN_80284b94(DAT_803de338);
  iVar2 = 0;
  for (bVar1 = 0; bVar1 < DAT_803de37d; bVar1 = bVar1 + 1) {
    FUN_80284b94(*(undefined4 *)(DAT_803de344 + iVar2));
    FUN_80284b94(*(undefined4 *)(DAT_803de344 + iVar2 + 4));
    iVar2 = iVar2 + 0xf4;
  }
  puVar3 = &DAT_803cc1e0;
  for (bVar1 = 0; bVar1 < DAT_803de37c; bVar1 = bVar1 + 1) {
    FUN_80284b94(*puVar3);
    FUN_80284b94(puVar3[10]);
    puVar3 = puVar3 + 0x2f;
  }
  FUN_80284b94(DAT_803de340);
  FUN_80284b94(DAT_803de344);
  FUN_80284b94(DAT_803de33c);
  FUN_80284b94(DAT_803de330);
  return 1;
}

