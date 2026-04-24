// Function: FUN_80014f40
// Entry: 80014f40
// Size: 1380 bytes

void FUN_80014f40(void)

{
  char cVar1;
  char cVar2;
  bool bVar3;
  uint uVar4;
  int iVar5;
  undefined *puVar6;
  ushort *puVar7;
  undefined4 *puVar8;
  ushort *puVar9;
  ushort *puVar10;
  ushort *puVar11;
  ushort *puVar12;
  uint *puVar13;
  uint *puVar14;
  uint *puVar15;
  uint *puVar16;
  undefined *puVar17;
  undefined *puVar18;
  char *pcVar19;
  char *pcVar20;
  char *pcVar21;
  char *pcVar22;
  undefined *local_54;
  
  FUN_802860a8();
  puVar6 = &DAT_803398f0 + (uint)DAT_803dc94c * 0x30;
  uVar4 = DAT_803dc94c ^ 1;
  DAT_803dc94c = (byte)uVar4;
  puVar7 = (ushort *)(&DAT_803398f0 + uVar4 * 0x30);
  iVar5 = FUN_8024e864(puVar7);
  if (iVar5 != -3) {
    FUN_8024dae8(puVar7);
    if (DAT_803dc909 != '\0') {
      if (((FLOAT_803de6e8 < FLOAT_803dc90c) &&
          (FLOAT_803dc90c = FLOAT_803dc90c - FLOAT_803db414, FLOAT_803dc90c <= FLOAT_803de6e8)) &&
         (DAT_803dc909 != '\0')) {
        FUN_8024ec10(0,0);
        FLOAT_803dc90c = FLOAT_803de6e8;
      }
    }
    bVar3 = false;
    DAT_803dc908 = 0;
    iVar5 = 0;
    pcVar22 = &DAT_803dc944;
    pcVar21 = &DAT_803dc948;
    pcVar20 = &DAT_803dc93c;
    pcVar19 = &DAT_803dc940;
    puVar18 = &DAT_803dc934;
    puVar17 = &DAT_803dc938;
    puVar16 = &DAT_803398b0;
    puVar15 = &DAT_803398c0;
    puVar14 = &DAT_803398d0;
    puVar13 = &DAT_803398e0;
    puVar12 = (ushort *)&DAT_803dc914;
    puVar11 = (ushort *)&DAT_803dc91c;
    puVar10 = (ushort *)&DAT_803dc924;
    puVar9 = (ushort *)&DAT_803dc92c;
    local_54 = &DAT_803398f0;
    puVar8 = &DAT_802c6e50;
    do {
      if (*(char *)(puVar7 + 5) == -1) {
        *pcVar22 = '\0';
        *pcVar21 = '\0';
        *pcVar20 = '\0';
        *pcVar19 = '\0';
        *puVar18 = 0;
        *puVar17 = 0;
        *puVar16 = 0;
        *puVar15 = 0;
        *puVar14 = 0;
        *puVar13 = 0;
        *puVar12 = 0;
        *puVar11 = 0;
        *puVar10 = 0;
        *puVar9 = 0;
        FUN_800033a8(local_54,0,0xc);
        FUN_800033a8(&DAT_803398f0 + (iVar5 + 4) * 0xc,0,0xc);
        DAT_803dc910 = DAT_803dc910 | 0x80000000U >> iVar5;
        *(undefined *)(puVar7 + 5) = 0xff;
      }
      else if (((byte)(*(char *)(puVar7 + 5) + 3U) < 2) || (DAT_803dcca5 == '\0')) {
        FUN_80003494(puVar7,puVar6,0xc);
        bVar3 = true;
      }
      else {
        *puVar15 = (uint)*puVar7;
        if (*(char *)((int)puVar7 + 5) < -0x28) {
          *puVar15 = *puVar15 | 0x20000;
        }
        if ('(' < *(char *)((int)puVar7 + 5)) {
          *puVar15 = *puVar15 | 0x10000;
        }
        if (*(char *)(puVar7 + 2) < -0x28) {
          *puVar15 = *puVar15 | 0x40000;
        }
        if ('(' < *(char *)(puVar7 + 2)) {
          *puVar15 = *puVar15 | 0x80000;
        }
        *puVar13 = *puVar15 & (*puVar15 ^ *puVar16);
        *puVar14 = *puVar16 & (*puVar15 ^ *puVar16);
        *puVar16 = *puVar15;
        *puVar11 = 0;
        if (10 < *(byte *)((int)puVar7 + 7)) {
          *puVar11 = *puVar11 | 0x20;
        }
        if (10 < *(byte *)(puVar7 + 3)) {
          *puVar11 = *puVar11 | 0x40;
        }
        *puVar9 = *puVar11 & (*puVar11 ^ *puVar12);
        *puVar10 = *puVar12 & (*puVar11 ^ *puVar12);
        *puVar12 = *puVar11;
        cVar1 = *(char *)(puVar7 + 1);
        cVar2 = *(char *)((int)puVar7 + 3);
        *puVar17 = 0;
        *puVar18 = 0;
        if ((cVar1 < -0x23) && (-0x24 < *pcVar21)) {
          *puVar17 = 0xff;
          *pcVar19 = '\0';
        }
        if (('#' < cVar1) && (*pcVar21 < '$')) {
          *puVar17 = 1;
          *pcVar19 = '\0';
        }
        if ((cVar2 < -0x23) && (-0x24 < *pcVar22)) {
          *puVar18 = 0xff;
          *pcVar20 = '\0';
        }
        if (('#' < cVar2) && (*pcVar22 < '$')) {
          *puVar18 = 1;
          *pcVar20 = '\0';
        }
        *pcVar22 = cVar2;
        if (*pcVar22 < -0x23) {
          *pcVar20 = *pcVar20 + '\x01';
        }
        else if (*pcVar22 < '$') {
          *pcVar20 = '\0';
        }
        else {
          *pcVar20 = *pcVar20 + '\x01';
        }
        if ((int)(uint)DAT_803db2a8 < (int)*pcVar20) {
          *pcVar22 = '\0';
          *pcVar20 = '\0';
        }
        *pcVar21 = cVar1;
        if (*pcVar21 < -0x23) {
          *pcVar19 = *pcVar19 + '\x01';
        }
        else if (*pcVar21 < '$') {
          *pcVar19 = '\0';
        }
        else {
          *pcVar19 = *pcVar19 + '\x01';
        }
        if ((int)(uint)DAT_803db2a8 < (int)*pcVar19) {
          *pcVar21 = '\0';
          *pcVar19 = '\0';
        }
        *puVar8 = 0xffffffff;
      }
      puVar7 = puVar7 + 6;
      pcVar22 = pcVar22 + 1;
      pcVar21 = pcVar21 + 1;
      pcVar20 = pcVar20 + 1;
      pcVar19 = pcVar19 + 1;
      puVar18 = puVar18 + 1;
      puVar17 = puVar17 + 1;
      puVar16 = puVar16 + 1;
      puVar15 = puVar15 + 1;
      puVar14 = puVar14 + 1;
      puVar13 = puVar13 + 1;
      puVar12 = puVar12 + 1;
      puVar11 = puVar11 + 1;
      puVar10 = puVar10 + 1;
      puVar9 = puVar9 + 1;
      local_54 = local_54 + 0xc;
      puVar6 = puVar6 + 0xc;
      puVar8 = puVar8 + 1;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 4);
    if ((DAT_803dc910 != 0) && (iVar5 = FUN_8024e450(), iVar5 != 0)) {
      DAT_803dc910 = 0;
    }
    if (bVar3) {
      DAT_803dc94c = DAT_803dc94c ^ 1;
    }
    DAT_803dcca5 = '\0';
  }
  FUN_802860f4();
  return;
}

