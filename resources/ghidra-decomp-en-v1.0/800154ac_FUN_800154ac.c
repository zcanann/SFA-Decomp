// Function: FUN_800154ac
// Entry: 800154ac
// Size: 376 bytes

void FUN_800154ac(void)

{
  int iVar1;
  undefined *puVar2;
  undefined2 *puVar3;
  undefined2 *puVar4;
  undefined2 *puVar5;
  undefined2 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  undefined *puVar10;
  undefined *puVar11;
  undefined *puVar12;
  undefined *puVar13;
  undefined *puVar14;
  undefined *puVar15;
  undefined4 *puVar16;
  
  FUN_802860ac();
  puVar16 = &DAT_803398b0;
  DAT_803dc910 = 0xf0000000;
  FUN_8024e654();
  FUN_8024e550(DAT_803dc910);
  iVar1 = FUN_8024e450(DAT_803dc910);
  if (iVar1 != 0) {
    DAT_803dc910 = 0;
  }
  iVar1 = 0;
  puVar15 = &DAT_803dc944;
  puVar14 = &DAT_803dc948;
  puVar13 = &DAT_803dc93c;
  puVar12 = &DAT_803dc940;
  puVar11 = &DAT_803dc934;
  puVar10 = &DAT_803dc938;
  puVar9 = &DAT_803398c0;
  puVar8 = &DAT_803398d0;
  puVar7 = &DAT_803398e0;
  puVar6 = (undefined2 *)&DAT_803dc914;
  puVar5 = (undefined2 *)&DAT_803dc91c;
  puVar4 = (undefined2 *)&DAT_803dc924;
  puVar3 = (undefined2 *)&DAT_803dc92c;
  puVar2 = &DAT_803398f0;
  do {
    *puVar15 = 0;
    *puVar14 = 0;
    *puVar13 = 0;
    *puVar12 = 0;
    *puVar11 = 0;
    *puVar10 = 0;
    *puVar16 = 0;
    *puVar9 = 0;
    *puVar8 = 0;
    *puVar7 = 0;
    *puVar6 = 0;
    *puVar5 = 0;
    *puVar4 = 0;
    *puVar3 = 0;
    FUN_800033a8(puVar2,0,0xc);
    FUN_800033a8(&DAT_803398f0 + (iVar1 + 4) * 0xc,0,0xc);
    puVar15 = puVar15 + 1;
    puVar14 = puVar14 + 1;
    puVar13 = puVar13 + 1;
    puVar12 = puVar12 + 1;
    puVar11 = puVar11 + 1;
    puVar10 = puVar10 + 1;
    puVar16 = puVar16 + 1;
    puVar9 = puVar9 + 1;
    puVar8 = puVar8 + 1;
    puVar7 = puVar7 + 1;
    puVar6 = puVar6 + 1;
    puVar5 = puVar5 + 1;
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
    puVar2 = puVar2 + 0xc;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 4);
  DAT_803dc94c = 0;
  DAT_803dc909 = 1;
  FUN_8024ec10(0,2);
  FLOAT_803dc90c = FLOAT_803de6e8;
  FUN_802860f8(0);
  return;
}

