// Function: FUN_802654ac
// Entry: 802654ac
// Size: 480 bytes

undefined4 FUN_802654ac(void)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  byte *pbVar9;
  uint uVar10;
  ushort uVar11;
  short sVar12;
  
  DAT_803dee2c = DAT_803dee8c + 0x101;
  DAT_803dee28 = DAT_803dee8c;
  sVar12 = **(short **)(DAT_803dee90 + 0x69c);
  *(short **)(DAT_803dee90 + 0x69c) = *(short **)(DAT_803dee90 + 0x69c) + 1;
  sVar12 = sVar12 + -2;
  do {
    uVar11 = 0;
    bVar8 = 0;
    pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
    *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
    uVar10 = (uint)*pbVar9;
    DAT_803dee24 = *(undefined4 *)(DAT_803dee90 + 0x69c);
    uVar10 = (uVar10 & 0xf) * 2 + ((int)uVar10 >> 4);
    while( true ) {
      if (0xf < bVar8) break;
      bVar8 = bVar8 + 8;
      pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
      bVar1 = *pbVar9;
      pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
      bVar2 = *pbVar9;
      pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
      bVar3 = *pbVar9;
      pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
      bVar4 = *pbVar9;
      pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
      bVar5 = *pbVar9;
      pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
      bVar6 = *pbVar9;
      pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
      bVar7 = *pbVar9;
      pbVar9 = *(byte **)(DAT_803dee90 + 0x69c);
      *(byte **)(DAT_803dee90 + 0x69c) = pbVar9 + 1;
      uVar11 = uVar11 + bVar1 + (ushort)bVar2 + (ushort)bVar3 + (ushort)bVar4 + (ushort)bVar5 +
               (ushort)bVar6 + (ushort)bVar7 + (ushort)*pbVar9;
    }
    *(undefined4 *)(DAT_803dee90 + uVar10 * 0xe0 + 0x340) = *(undefined4 *)(DAT_803dee90 + 0x69c);
    *(uint *)(DAT_803dee90 + 0x69c) = *(int *)(DAT_803dee90 + 0x69c) + (uint)uVar11;
    FUN_8026568c();
    FUN_8026577c();
    FUN_802657e4(uVar10);
    sVar12 = sVar12 - (uVar11 + 0x11);
    *(byte *)(DAT_803dee90 + 0x6a8) = *(byte *)(DAT_803dee90 + 0x6a8) | (byte)(1 << uVar10);
  } while (sVar12 != 0);
  return 0;
}

