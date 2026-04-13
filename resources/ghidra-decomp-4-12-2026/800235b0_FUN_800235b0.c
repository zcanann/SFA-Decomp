// Function: FUN_800235b0
// Entry: 800235b0
// Size: 788 bytes

void FUN_800235b0(void)

{
  int iVar1;
  undefined4 *puVar2;
  uint *puVar3;
  int iVar4;
  undefined4 *puVar5;
  
  puVar5 = &DAT_8033d400;
  DAT_803dd79c = DAT_803dd79c + 1;
  DAT_803dd794 = DAT_803dd794 + 1;
  iVar4 = 0;
  puVar3 = &DAT_8033d480;
  while (iVar4 < DAT_803dd7c0) {
    *(char *)(puVar3 + 1) = *(char *)(puVar3 + 1) + -1;
    if (*(char *)(puVar3 + 1) == '\0') {
      FUN_800234ac(*puVar3);
      *puVar3 = *(uint *)(&DAT_8033d478 + DAT_803dd7c0 * 8);
      *(undefined *)(puVar3 + 1) = (&DAT_8033d47c)[DAT_803dd7c0 * 8];
      DAT_803dd7c0 = DAT_803dd7c0 + -1;
    }
    else {
      puVar3 = puVar3 + 2;
      iVar4 = iVar4 + 1;
    }
  }
  iVar4 = 4;
  do {
    puVar2 = (undefined4 *)*puVar5;
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = *puVar2;
    }
    puVar2 = (undefined4 *)puVar5[1];
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = *puVar2;
    }
    puVar2 = (undefined4 *)puVar5[2];
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = *puVar2;
    }
    puVar2 = (undefined4 *)puVar5[3];
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = *puVar2;
    }
    puVar2 = (undefined4 *)puVar5[4];
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = *puVar2;
    }
    puVar2 = (undefined4 *)puVar5[5];
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = *puVar2;
    }
    puVar2 = (undefined4 *)puVar5[6];
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = *puVar2;
    }
    puVar2 = (undefined4 *)puVar5[7];
    if (puVar2 != (undefined4 *)0x0) {
      puVar2[1] = *puVar2;
    }
    puVar5 = puVar5 + 8;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  FUN_800e969c();
  DAT_803dd7a0 = 0;
  DAT_803dd7a8 = 0;
  DAT_803dd7a4 = 0;
  DAT_803dd7ac = 0;
  iVar4 = DAT_8034131c;
  if (1 < DAT_803dd7c2) {
    while( true ) {
      if (*(short *)(iVar4 + 8) != 0) {
        DAT_803dd7a4 = DAT_803dd7a4 + *(int *)(iVar4 + 4);
      }
      iVar1 = DAT_80341330;
      if (*(short *)(iVar4 + 0xc) == -1) break;
      iVar4 = DAT_8034131c + *(short *)(iVar4 + 0xc) * 0x1c;
    }
    while( true ) {
      if (*(short *)(iVar1 + 8) != 0) {
        DAT_803dd7a8 = DAT_803dd7a8 + *(int *)(iVar1 + 4);
      }
      iVar4 = DAT_80341344;
      if (*(short *)(iVar1 + 0xc) == -1) break;
      iVar1 = DAT_80341330 + *(short *)(iVar1 + 0xc) * 0x1c;
    }
    while( true ) {
      if (*(short *)(iVar4 + 8) != 0) {
        DAT_803dd7ac = DAT_803dd7ac + *(int *)(iVar4 + 4);
      }
      if (*(short *)(iVar4 + 0xc) == -1) break;
      iVar4 = DAT_80341344 + *(short *)(iVar4 + 0xc) * 0x1c;
    }
  }
  iVar4 = DAT_803dd7b0 + 1;
  iVar1 = DAT_803dd7b0 / 500 + (DAT_803dd7b0 >> 0x1f);
  iVar1 = DAT_803dd7b0 + (iVar1 - (iVar1 >> 0x1f)) * -500;
  DAT_803dd7b0 = iVar4;
  if (iVar1 == 0) {
    FUN_8007d858();
  }
  return;
}

