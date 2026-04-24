// Function: FUN_800154d8
// Entry: 800154d8
// Size: 376 bytes

void FUN_800154d8(void)

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
  
  FUN_80286810();
  puVar16 = &DAT_8033a510;
  DAT_803dd590 = 0xf0000000;
  FUN_8024edb8();
  FUN_8024ecb4(DAT_803dd590);
  iVar1 = FUN_8024ebb4(DAT_803dd590);
  if (iVar1 != 0) {
    DAT_803dd590 = 0;
  }
  iVar1 = 0;
  puVar15 = &DAT_803dd5c4;
  puVar14 = &DAT_803dd5c8;
  puVar13 = &DAT_803dd5bc;
  puVar12 = &DAT_803dd5c0;
  puVar11 = &DAT_803dd5b4;
  puVar10 = &DAT_803dd5b8;
  puVar9 = &DAT_8033a520;
  puVar8 = &DAT_8033a530;
  puVar7 = &DAT_8033a540;
  puVar6 = (undefined2 *)&DAT_803dd594;
  puVar5 = (undefined2 *)&DAT_803dd59c;
  puVar4 = (undefined2 *)&DAT_803dd5a4;
  puVar3 = (undefined2 *)&DAT_803dd5ac;
  puVar2 = &DAT_8033a550;
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
    FUN_800033a8((int)puVar2,0,0xc);
    FUN_800033a8((int)(&DAT_8033a550 + (iVar1 + 4) * 0xc),0,0xc);
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
  DAT_803dd5cc = 0;
  DAT_803dd589 = 1;
  FUN_8024f374(0,2);
  FLOAT_803dd58c = FLOAT_803df368;
  FUN_8028685c();
  return;
}

