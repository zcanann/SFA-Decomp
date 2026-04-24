// Function: FUN_80006744
// Entry: 80006744
// Size: 984 bytes

void FUN_80006744(undefined4 param_1,undefined4 param_2,int *param_3,int param_4,uint param_5)

{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  byte *pbVar11;
  ulonglong uVar12;
  
  uVar12 = FUN_802860d4();
  pbVar3 = (byte *)(uVar12 >> 0x20);
  param_5 = param_5 & 0xff;
  iVar5 = param_5 - 4;
  if (iVar5 < 0) {
    iVar5 = 0;
  }
  uVar2 = (uint)(*pbVar3 >> 4) << iVar5;
  pbVar11 = pbVar3 + 1;
  iVar5 = (*pbVar3 & 0xf) << 3;
  iVar4 = FUN_80013a54(param_3);
  param_4 = param_4 - param_5;
  iVar7 = 0x10 - param_5;
  iVar6 = (int)uVar12 / 2;
  if (0 < iVar6) {
    do {
      bVar1 = *pbVar11;
      iVar9 = (&DAT_802c18c0)[iVar5];
      iVar8 = 0;
      if ((bVar1 & 1) != 0) {
        iVar8 = iVar9 >> 2;
      }
      if ((bVar1 & 2) != 0) {
        iVar8 = iVar8 + (iVar9 >> 1);
      }
      if ((bVar1 & 4) != 0) {
        iVar8 = iVar8 + iVar9;
      }
      if ((bVar1 & 8) != 0) {
        iVar8 = -iVar8;
      }
      iVar5 = iVar5 + *(int *)(&DAT_802c1a24 + (bVar1 & 0xf) * 4);
      if (iVar5 < 0) {
        iVar5 = 0;
      }
      else if (0x58 < iVar5) {
        iVar5 = 0x58;
      }
      iVar9 = param_3[4] >> 3;
      iVar10 = (uVar2 + iVar8 & 0xffff) << (8 - (param_3[4] & 7U)) + iVar7;
      *(byte *)(*param_3 + iVar9) = *(byte *)(*param_3 + iVar9) | (byte)((uint)iVar10 >> 0x10);
      *(byte *)(*param_3 + iVar9 + 1) = *(byte *)(*param_3 + iVar9 + 1) | (byte)((uint)iVar10 >> 8);
      *(byte *)(*param_3 + iVar9 + 2) = *(byte *)(*param_3 + iVar9 + 2) | (byte)iVar10;
      param_3[4] = param_3[4] + param_5;
      param_3[4] = param_3[4] + param_4;
      bVar1 = *pbVar11;
      pbVar11 = pbVar11 + 1;
      bVar1 = bVar1 >> 4;
      iVar10 = (&DAT_802c18c0)[iVar5];
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
      uVar2 = uVar2 + iVar8 + iVar9;
      iVar5 = iVar5 + *(int *)(&DAT_802c1a24 + (uint)bVar1 * 4);
      if (iVar5 < 0) {
        iVar5 = 0;
      }
      else if (0x58 < iVar5) {
        iVar5 = 0x58;
      }
      iVar8 = param_3[4] >> 3;
      iVar9 = (uVar2 & 0xffff) << (8 - (param_3[4] & 7U)) + iVar7;
      *(byte *)(*param_3 + iVar8) = *(byte *)(*param_3 + iVar8) | (byte)((uint)iVar9 >> 0x10);
      *(byte *)(*param_3 + iVar8 + 1) = *(byte *)(*param_3 + iVar8 + 1) | (byte)((uint)iVar9 >> 8);
      *(byte *)(*param_3 + iVar8 + 2) = *(byte *)(*param_3 + iVar8 + 2) | (byte)iVar9;
      param_3[4] = param_3[4] + param_5;
      param_3[4] = param_3[4] + param_4;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  if ((uVar12 & 1) != 0) {
    bVar1 = *pbVar11;
    pbVar11 = pbVar11 + 1;
    iVar6 = (&DAT_802c18c0)[iVar5];
    iVar5 = 0;
    if ((bVar1 & 1) != 0) {
      iVar5 = iVar6 >> 2;
    }
    if ((bVar1 & 2) != 0) {
      iVar5 = iVar5 + (iVar6 >> 1);
    }
    if ((bVar1 & 4) != 0) {
      iVar5 = iVar5 + iVar6;
    }
    if ((bVar1 & 8) != 0) {
      iVar5 = -iVar5;
    }
    iVar6 = param_3[4] >> 3;
    iVar5 = (uVar2 + iVar5 & 0xffff) << (8 - (param_3[4] & 7U)) + iVar7;
    *(byte *)(*param_3 + iVar6) = *(byte *)(*param_3 + iVar6) | (byte)((uint)iVar5 >> 0x10);
    *(byte *)(*param_3 + iVar6 + 1) = *(byte *)(*param_3 + iVar6 + 1) | (byte)((uint)iVar5 >> 8);
    *(byte *)(*param_3 + iVar6 + 2) = *(byte *)(*param_3 + iVar6 + 2) | (byte)iVar5;
    param_3[4] = param_3[4] + param_5;
  }
  if (param_4 != 0) {
    FUN_80013a5c(param_3,iVar4 + param_5);
  }
  FUN_80286120(pbVar11);
  return;
}

