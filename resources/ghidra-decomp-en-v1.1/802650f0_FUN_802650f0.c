// Function: FUN_802650f0
// Entry: 802650f0
// Size: 956 bytes

undefined4 FUN_802650f0(void)

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
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  sVar4 = **(short **)(DAT_803dee90 + 0x69c);
  *(short **)(DAT_803dee90 + 0x69c) = *(short **)(DAT_803dee90 + 0x69c) + 1;
  dVar3 = DOUBLE_803e83f8;
  sVar4 = sVar4 + -2;
  do {
    pbVar7 = *(byte **)(DAT_803dee90 + 0x69c);
    *(byte **)(DAT_803dee90 + 0x69c) = pbVar7 + 1;
    bVar1 = *pbVar7;
    pbVar7 = &DAT_802c2da8;
    for (uVar6 = 0; iVar2 = DAT_803dee90, (uVar6 & 0xffff) < 0x40; uVar6 = uVar6 + 8) {
      pbVar15 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar15 + 1;
      uStack_34 = (uint)*pbVar15;
      local_38 = 0x43300000;
      local_174[*pbVar7] = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar3);
      pbVar15 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar15 + 1;
      uStack_3c = (uint)*pbVar15;
      local_40 = 0x43300000;
      local_174[(byte)(&DAT_802c2da8)[uVar6 + 1 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar3);
      pbVar15 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar15 + 1;
      uStack_44 = (uint)*pbVar15;
      local_48 = 0x43300000;
      local_174[(byte)(&DAT_802c2da8)[uVar6 + 2 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack_44) - dVar3);
      pbVar15 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar15 + 1;
      uStack_4c = (uint)*pbVar15;
      local_50 = 0x43300000;
      local_174[(byte)(&DAT_802c2da8)[uVar6 + 3 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack_4c) - dVar3);
      pbVar15 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar15 + 1;
      uStack_54 = (uint)*pbVar15;
      local_58 = 0x43300000;
      local_174[(byte)(&DAT_802c2da8)[uVar6 + 4 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack_54) - dVar3);
      pbVar15 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar15 + 1;
      uStack_5c = (uint)*pbVar15;
      local_60 = 0x43300000;
      local_174[(byte)(&DAT_802c2da8)[uVar6 + 5 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack_5c) - dVar3);
      pbVar15 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar15 + 1;
      pbVar7 = pbVar7 + 8;
      uStack_64 = (uint)*pbVar15;
      local_68 = 0x43300000;
      local_174[(byte)(&DAT_802c2da8)[uVar6 + 6 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack_64) - dVar3);
      pbVar15 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar15 + 1;
      uStack_6c = (uint)*pbVar15;
      local_70 = 0x43300000;
      local_174[(byte)(&DAT_802c2da8)[uVar6 + 7 & 0xffff]] =
           (float)((double)CONCAT44(0x43300000,uStack_6c) - dVar3);
    }
    iVar17 = (uint)bVar1 * 0x100;
    uVar6 = 0;
    uVar5 = 0;
    pdVar16 = &DAT_802c2df8;
    while( true ) {
      if (7 < uVar5) break;
      uVar8 = (uVar6 + 1) * 4 & 0x3fffc;
      uVar14 = (uVar6 + 2) * 4 & 0x3fffc;
      uVar13 = (uVar6 + 3) * 4 & 0x3fffc;
      uVar12 = (uVar6 + 4) * 4 & 0x3fffc;
      *(float *)(iVar17 + iVar2 + (uVar6 & 0xffff) * 4) =
           (float)(DAT_802c2df8 * (double)local_174[uVar6 & 0xffff] * *pdVar16);
      uVar11 = (uVar6 + 5) * 4 & 0x3fffc;
      uVar10 = (uVar6 + 6) * 4 & 0x3fffc;
      uVar9 = (uVar6 + 7) * 4 & 0x3fffc;
      uVar6 = uVar6 + 8;
      uVar5 = uVar5 + 1;
      *(float *)(iVar17 + iVar2 + uVar8) =
           (float)(DAT_802c2e00 * (double)*(float *)((int)local_174 + uVar8) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar14) =
           (float)(DAT_802c2e08 * (double)*(float *)((int)local_174 + uVar14) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar13) =
           (float)(DAT_802c2e10 * (double)*(float *)((int)local_174 + uVar13) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar12) =
           (float)(DAT_802c2e18 * (double)*(float *)((int)local_174 + uVar12) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar11) =
           (float)(DAT_802c2e20 * (double)*(float *)((int)local_174 + uVar11) * *pdVar16);
      *(float *)(iVar17 + iVar2 + uVar10) =
           (float)(DAT_802c2e28 * (double)*(float *)((int)local_174 + uVar10) * *pdVar16);
      dVar18 = *pdVar16;
      pdVar16 = pdVar16 + 1;
      *(float *)(iVar17 + iVar2 + uVar9) =
           (float)(DAT_802c2e30 * (double)*(float *)((int)local_174 + uVar9) * dVar18);
    }
    sVar4 = sVar4 + -0x41;
  } while (sVar4 != 0);
  return 0;
}

