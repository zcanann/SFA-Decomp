// Function: FUN_80264d48
// Entry: 80264d48
// Size: 480 bytes

undefined4 FUN_80264d48(void)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  int iVar8;
  byte bVar9;
  byte *pbVar10;
  uint uVar11;
  ushort uVar12;
  short sVar13;
  
  DAT_803de1ac = DAT_803de20c + 0x101;
  DAT_803de1a8 = DAT_803de20c;
  sVar13 = **(short **)(DAT_803de210 + 0x69c);
  *(short **)(DAT_803de210 + 0x69c) = *(short **)(DAT_803de210 + 0x69c) + 1;
  sVar13 = sVar13 + -2;
  do {
    uVar12 = 0;
    bVar9 = 0;
    pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
    *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
    uVar11 = (uint)*pbVar10;
    DAT_803de1a4 = *(undefined4 *)(DAT_803de210 + 0x69c);
    iVar8 = (uVar11 & 0xf) * 2 + ((int)uVar11 >> 4);
    while( true ) {
      if (0xf < bVar9) break;
      bVar9 = bVar9 + 8;
      pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
      bVar1 = *pbVar10;
      pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
      bVar2 = *pbVar10;
      pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
      bVar3 = *pbVar10;
      pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
      bVar4 = *pbVar10;
      pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
      bVar5 = *pbVar10;
      pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
      bVar6 = *pbVar10;
      pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
      bVar7 = *pbVar10;
      pbVar10 = *(byte **)(DAT_803de210 + 0x69c);
      *(byte **)(DAT_803de210 + 0x69c) = pbVar10 + 1;
      uVar12 = uVar12 + bVar1 + (ushort)bVar2 + (ushort)bVar3 + (ushort)bVar4 + (ushort)bVar5 +
               (ushort)bVar6 + (ushort)bVar7 + (ushort)*pbVar10;
    }
    *(undefined4 *)(DAT_803de210 + iVar8 * 0xe0 + 0x340) = *(undefined4 *)(DAT_803de210 + 0x69c);
    *(uint *)(DAT_803de210 + 0x69c) = *(int *)(DAT_803de210 + 0x69c) + (uint)uVar12;
    FUN_80264f28();
    FUN_80265018();
    FUN_80265080(iVar8);
    sVar13 = sVar13 - (uVar12 + 0x11);
    *(byte *)(DAT_803de210 + 0x6a8) = *(byte *)(DAT_803de210 + 0x6a8) | (byte)(1 << iVar8);
  } while (sVar13 != 0);
  return 0;
}

