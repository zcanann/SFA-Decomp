// Function: FUN_8005d270
// Entry: 8005d270
// Size: 324 bytes

void FUN_8005d270(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  uint uVar9;
  int iVar10;
  undefined4 *puVar11;
  int iVar12;
  
  iVar1 = (DAT_803dce30 + -1) / 9 + (DAT_803dce30 + -1 >> 0x1f);
  for (iVar7 = 1; iVar7 <= iVar1 - (iVar1 >> 0x1f); iVar7 = iVar7 * 3 + 1) {
  }
  for (; 0 < iVar7; iVar7 = iVar7 / 3) {
    iVar6 = iVar7 + 1;
    iVar1 = iVar6 * 0x10;
    puVar11 = &DAT_8037e0c0 + iVar6 * 4;
    for (; iVar6 <= DAT_803dce30; iVar6 = iVar6 + 1) {
      uVar8 = puVar11[-4];
      uVar2 = puVar11[-3];
      uVar9 = puVar11[-2];
      uVar3 = puVar11[-1];
      iVar10 = (int)&DAT_8037e0c0 + iVar1;
      iVar12 = iVar6;
      while ((iVar7 < iVar12 && (iVar5 = iVar12 - iVar7, (uint)(&DAT_8037e0b8)[iVar5 * 4] < uVar9)))
      {
        uVar4 = (&DAT_8037e0b4)[iVar5 * 4];
        *(undefined4 *)(iVar10 + -0x10) = (&DAT_8037e0b0)[iVar5 * 4];
        *(undefined4 *)(iVar10 + -0xc) = uVar4;
        uVar4 = (&DAT_8037e0bc)[iVar5 * 4];
        *(undefined4 *)(iVar10 + -8) = (&DAT_8037e0b8)[iVar5 * 4];
        *(undefined4 *)(iVar10 + -4) = uVar4;
        iVar10 = iVar10 + iVar7 * -0x10;
        iVar12 = iVar12 - iVar7;
      }
      (&DAT_8037e0b0)[iVar12 * 4] = uVar8;
      (&DAT_8037e0b4)[iVar12 * 4] = uVar2;
      (&DAT_8037e0b8)[iVar12 * 4] = uVar9;
      (&DAT_8037e0bc)[iVar12 * 4] = uVar3;
      puVar11 = puVar11 + 4;
      iVar1 = iVar1 + 0x10;
    }
  }
  return;
}

