// Function: FUN_800234ec
// Entry: 800234ec
// Size: 788 bytes

void FUN_800234ec(void)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  
  puVar3 = &DAT_8033c7a0;
  DAT_803dcb1c = DAT_803dcb1c + 1;
  DAT_803dcb14 = DAT_803dcb14 + 1;
  iVar2 = 0;
  puVar1 = &DAT_8033c820;
  while (iVar2 < DAT_803dcb40) {
    *(char *)(puVar1 + 1) = *(char *)(puVar1 + 1) + -1;
    if (*(char *)(puVar1 + 1) == '\0') {
      FUN_800233e8(*puVar1);
      *puVar1 = *(undefined4 *)(&DAT_8033c818 + DAT_803dcb40 * 8);
      *(undefined *)(puVar1 + 1) = (&DAT_8033c81c)[DAT_803dcb40 * 8];
      DAT_803dcb40 = DAT_803dcb40 + -1;
    }
    else {
      puVar1 = puVar1 + 2;
      iVar2 = iVar2 + 1;
    }
  }
  iVar2 = 0;
  iVar4 = 4;
  do {
    puVar1 = (undefined4 *)*puVar3;
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = *puVar1;
    }
    puVar1 = (undefined4 *)puVar3[1];
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = *puVar1;
    }
    puVar1 = (undefined4 *)puVar3[2];
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = *puVar1;
    }
    puVar1 = (undefined4 *)puVar3[3];
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = *puVar1;
    }
    puVar1 = (undefined4 *)puVar3[4];
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = *puVar1;
    }
    puVar1 = (undefined4 *)puVar3[5];
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = *puVar1;
    }
    puVar1 = (undefined4 *)puVar3[6];
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = *puVar1;
    }
    puVar1 = (undefined4 *)puVar3[7];
    if (puVar1 != (undefined4 *)0x0) {
      puVar1[1] = *puVar1;
    }
    puVar3 = puVar3 + 8;
    iVar2 = iVar2 + 7;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  FUN_800e9418(iVar2);
  DAT_803dcb20 = 0;
  DAT_803dcb28 = 0;
  DAT_803dcb24 = 0;
  DAT_803dcb2c = 0;
  iVar2 = DAT_803406bc;
  if (1 < DAT_803dcb42) {
    while( true ) {
      if (*(short *)(iVar2 + 8) != 0) {
        DAT_803dcb24 = DAT_803dcb24 + *(int *)(iVar2 + 4);
      }
      iVar4 = DAT_803406d0;
      if (*(short *)(iVar2 + 0xc) == -1) break;
      iVar2 = DAT_803406bc + *(short *)(iVar2 + 0xc) * 0x1c;
    }
    while( true ) {
      if (*(short *)(iVar4 + 8) != 0) {
        DAT_803dcb28 = DAT_803dcb28 + *(int *)(iVar4 + 4);
      }
      iVar2 = DAT_803406e4;
      if (*(short *)(iVar4 + 0xc) == -1) break;
      iVar4 = DAT_803406d0 + *(short *)(iVar4 + 0xc) * 0x1c;
    }
    while( true ) {
      if (*(short *)(iVar2 + 8) != 0) {
        DAT_803dcb2c = DAT_803dcb2c + *(int *)(iVar2 + 4);
      }
      if (*(short *)(iVar2 + 0xc) == -1) break;
      iVar2 = DAT_803406e4 + *(short *)(iVar2 + 0xc) * 0x1c;
    }
  }
  iVar2 = DAT_803dcb30 + 1;
  iVar4 = DAT_803dcb30 / 500 + (DAT_803dcb30 >> 0x1f);
  iVar4 = DAT_803dcb30 + (iVar4 - (iVar4 >> 0x1f)) * -500;
  DAT_803dcb30 = iVar2;
  if (iVar4 == 0) {
    FUN_8007d6dc(s_mem__dk__dk__dk__dk__dk__dk__dk__802ca934,0,DAT_803406ac,DAT_803dcb24,
                 DAT_803406c0,DAT_803dcb28,DAT_803406d4,DAT_803dcb2c,DAT_803406e8,DAT_803406a4,
                 DAT_803406a0,DAT_803406b8,DAT_803406b4,DAT_803406cc,DAT_803406c8,DAT_803406e0,
                 DAT_803406dc);
  }
  return;
}

