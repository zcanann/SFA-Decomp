// Function: FUN_80006744
// Entry: 80006744
// Size: 984 bytes

void FUN_80006744(undefined4 param_1,undefined4 param_2,int *param_3,int param_4,uint param_5)

{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  byte *pbVar12;
  int iVar13;
  ulonglong uVar14;
  
  uVar14 = FUN_80286838();
  pbVar4 = (byte *)(uVar14 >> 0x20);
  uVar2 = param_5 & 0xff;
  iVar6 = uVar2 - 4;
  if (iVar6 < 0) {
    iVar6 = 0;
  }
  uVar3 = (uint)(*pbVar4 >> 4) << iVar6;
  pbVar12 = pbVar4 + 1;
  iVar6 = (*pbVar4 & 0xf) << 3;
  iVar5 = FUN_80013a74((int)param_3);
  iVar13 = param_4 - uVar2;
  iVar8 = 0x10 - uVar2;
  iVar7 = (int)uVar14 / 2;
  if (0 < iVar7) {
    do {
      bVar1 = *pbVar12;
      iVar10 = (&DAT_802c2040)[iVar6];
      iVar9 = 0;
      if ((bVar1 & 1) != 0) {
        iVar9 = iVar10 >> 2;
      }
      if ((bVar1 & 2) != 0) {
        iVar9 = iVar9 + (iVar10 >> 1);
      }
      if ((bVar1 & 4) != 0) {
        iVar9 = iVar9 + iVar10;
      }
      if ((bVar1 & 8) != 0) {
        iVar9 = -iVar9;
      }
      iVar6 = iVar6 + *(int *)(&DAT_802c21a4 + (bVar1 & 0xf) * 4);
      if (iVar6 < 0) {
        iVar6 = 0;
      }
      else if (0x58 < iVar6) {
        iVar6 = 0x58;
      }
      iVar10 = param_3[4] >> 3;
      iVar11 = (uVar3 + iVar9 & 0xffff) << (8 - (param_3[4] & 7U)) + iVar8;
      *(byte *)(*param_3 + iVar10) = *(byte *)(*param_3 + iVar10) | (byte)((uint)iVar11 >> 0x10);
      *(byte *)(*param_3 + iVar10 + 1) =
           *(byte *)(*param_3 + iVar10 + 1) | (byte)((uint)iVar11 >> 8);
      *(byte *)(*param_3 + iVar10 + 2) = *(byte *)(*param_3 + iVar10 + 2) | (byte)iVar11;
      param_3[4] = param_3[4] + uVar2;
      param_3[4] = param_3[4] + iVar13;
      bVar1 = *pbVar12;
      pbVar12 = pbVar12 + 1;
      bVar1 = bVar1 >> 4;
      iVar11 = (&DAT_802c2040)[iVar6];
      iVar10 = 0;
      if ((bVar1 & 1) != 0) {
        iVar10 = iVar11 >> 2;
      }
      if ((bVar1 & 2) != 0) {
        iVar10 = iVar10 + (iVar11 >> 1);
      }
      if ((bVar1 & 4) != 0) {
        iVar10 = iVar10 + iVar11;
      }
      if ((bVar1 & 8) != 0) {
        iVar10 = -iVar10;
      }
      uVar3 = uVar3 + iVar9 + iVar10;
      iVar6 = iVar6 + *(int *)(&DAT_802c21a4 + (uint)bVar1 * 4);
      if (iVar6 < 0) {
        iVar6 = 0;
      }
      else if (0x58 < iVar6) {
        iVar6 = 0x58;
      }
      iVar9 = param_3[4] >> 3;
      iVar10 = (uVar3 & 0xffff) << (8 - (param_3[4] & 7U)) + iVar8;
      *(byte *)(*param_3 + iVar9) = *(byte *)(*param_3 + iVar9) | (byte)((uint)iVar10 >> 0x10);
      *(byte *)(*param_3 + iVar9 + 1) = *(byte *)(*param_3 + iVar9 + 1) | (byte)((uint)iVar10 >> 8);
      *(byte *)(*param_3 + iVar9 + 2) = *(byte *)(*param_3 + iVar9 + 2) | (byte)iVar10;
      param_3[4] = param_3[4] + uVar2;
      param_3[4] = param_3[4] + iVar13;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
  }
  if ((uVar14 & 1) != 0) {
    bVar1 = *pbVar12;
    iVar7 = (&DAT_802c2040)[iVar6];
    iVar6 = 0;
    if ((bVar1 & 1) != 0) {
      iVar6 = iVar7 >> 2;
    }
    if ((bVar1 & 2) != 0) {
      iVar6 = iVar6 + (iVar7 >> 1);
    }
    if ((bVar1 & 4) != 0) {
      iVar6 = iVar6 + iVar7;
    }
    if ((bVar1 & 8) != 0) {
      iVar6 = -iVar6;
    }
    iVar7 = param_3[4] >> 3;
    iVar6 = (uVar3 + iVar6 & 0xffff) << (8 - (param_3[4] & 7U)) + iVar8;
    *(byte *)(*param_3 + iVar7) = *(byte *)(*param_3 + iVar7) | (byte)((uint)iVar6 >> 0x10);
    *(byte *)(*param_3 + iVar7 + 1) = *(byte *)(*param_3 + iVar7 + 1) | (byte)((uint)iVar6 >> 8);
    *(byte *)(*param_3 + iVar7 + 2) = *(byte *)(*param_3 + iVar7 + 2) | (byte)iVar6;
    param_3[4] = param_3[4] + uVar2;
  }
  if (iVar13 != 0) {
    FUN_80013a7c((int)param_3,iVar5 + uVar2);
  }
  FUN_80286884();
  return;
}

