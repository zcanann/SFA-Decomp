// Function: FUN_8026498c
// Entry: 8026498c
// Size: 956 bytes

undefined4 FUN_8026498c(void)

{
  byte bVar1;
  int iVar2;
  double dVar3;
  short sVar4;
  ushort uVar5;
  uint uVar6;
  byte *pbVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  byte *pbVar15;
  double *pdVar16;
  int iVar17;
  double dVar18;
  float local_174 [65];
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  
  sVar4 = **(short **)(DAT_803de210 + 0x69c);
  *(short **)(DAT_803de210 + 0x69c) = *(short **)(DAT_803de210 + 0x69c) + 1;
  dVar3 = DOUBLE_803e7760;
  sVar4 = sVar4 + -2;
  do {
    pbVar7 = *(byte **)(DAT_803de210 + 0x69c);
    *(byte **)(DAT_803de210 + 0x69c) = pbVar7 + 1;
    bVar1 = *pbVar7;
    pbVar7 = &DAT_802c2628;
    for (uVar6 = 0; iVar2 = DAT_803de210, (uVar6 & 0xffff) < 0x40; uVar6 = uVar6 + 8) {
      pbVar15 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar15 + 1;
      uStack52 = (uint)*pbVar15;
      local_38 = 0x43300000;
      local_174[*pbVar7] = (float)((double)CONCAT44(0x43300000,uStack52) - dVar3);
      pbVar15 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar15 + 1;
      uStack60 = (uint)*pbVar15;
      local_40 = 0x43300000;
      local_174[(byte)(&DAT_802c2628)[uVar6 + 1 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack60) - dVar3);
      pbVar15 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar15 + 1;
      uStack68 = (uint)*pbVar15;
      local_48 = 0x43300000;
      local_174[(byte)(&DAT_802c2628)[uVar6 + 2 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack68) - dVar3);
      pbVar15 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar15 + 1;
      uStack76 = (uint)*pbVar15;
      local_50 = 0x43300000;
      local_174[(byte)(&DAT_802c2628)[uVar6 + 3 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack76) - dVar3);
      pbVar15 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar15 + 1;
      uStack84 = (uint)*pbVar15;
      local_58 = 0x43300000;
      local_174[(byte)(&DAT_802c2628)[uVar6 + 4 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack84) - dVar3);
      pbVar15 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar15 + 1;
      uStack92 = (uint)*pbVar15;
      local_60 = 0x43300000;
      local_174[(byte)(&DAT_802c2628)[uVar6 + 5 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack92) - dVar3);
      pbVar15 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar15 + 1;
      pbVar7 = pbVar7 + 8;
      uStack100 = (uint)*pbVar15;
      local_68 = 0x43300000;
      local_174[(byte)(&DAT_802c2628)[uVar6 + 6 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack100) - dVar3);
      pbVar15 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar15 + 1;
      uStack108 = (uint)*pbVar15;
      local_70 = 0x43300000;
      local_174[(byte)(&DAT_802c2628)[uVar6 + 7 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack108) - dVar3);
    }
    iVar17 = (uint)bVar1 * 0x100;
    uVar6 = 0;
    uVar5 = 0;
    pdVar16 = &DAT_802c2678;
    while( true ) {
      if (7 < uVar5) break;
      uVar8 = (uVar6 + 1) * 4 & 0x3fffc;
      uVar14 = (uVar6 + 2) * 4 & 0x3fffc;
      uVar13 = (uVar6 + 3) * 4 & 0x3fffc;
      uVar12 = (uVar6 + 4) * 4 & 0x3fffc;
      *(float *)(iVar17 + iVar2 + (uVar6 & 0xffff) * 4) =
           (float)(DAT_802c2678 * (double)local_174[uVar6 & 0xffff] * *pdVar16);
      uVar11 = (uVar6 + 5) * 4 & 0x3fffc;
      uVar10 = (uVar6 + 6) * 4 & 0x3fffc;
      uVar9 = (uVar6 + 7) * 4 & 0x3fffc;
      uVar6 = uVar6 + 8;
      uVar5 = uVar5 + 1;
      *(float *)(iVar17 + iVar2 + uVar8) =
           (float)(DAT_802c2680 * (double)*(float *)((int)local_174 + uVar8) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar14) =
           (float)(DAT_802c2688 * (double)*(float *)((int)local_174 + uVar14) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar13) =
           (float)(DAT_802c2690 * (double)*(float *)((int)local_174 + uVar13) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar12) =
           (float)(DAT_802c2698 * (double)*(float *)((int)local_174 + uVar12) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar11) =
           (float)(DAT_802c26a0 * (double)*(float *)((int)local_174 + uVar11) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar10) =
           (float)(DAT_802c26a8 * (double)*(float *)((int)local_174 + uVar10) * *pdVar16);
      dVar18 = *pdVar16;
      pdVar16 = pdVar16 + 1;
      *(float *)(iVar17 + iVar2 + uVar9) =
           (float)(DAT_802c26b0 * (double)*(float *)((int)local_174 + uVar9) * dVar18);
    }
    sVar4 = sVar4 + -0x41;
  } while (sVar4 != 0);
  return 0;
}

