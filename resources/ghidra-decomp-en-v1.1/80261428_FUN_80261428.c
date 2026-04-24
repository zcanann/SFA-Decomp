// Function: FUN_80261428
// Entry: 80261428
// Size: 644 bytes

undefined4 FUN_80261428(int param_1)

{
  ushort uVar1;
  ushort *puVar2;
  undefined4 uVar3;
  ushort uVar5;
  undefined2 *puVar4;
  ushort *puVar6;
  ushort uVar7;
  uint uVar8;
  byte *pbVar9;
  int iVar10;
  int iVar11;
  longlong lVar12;
  undefined8 uVar13;
  
  puVar2 = *(ushort **)(param_1 + 0x80);
  if ((puVar2[0x10] == 0) && (puVar2[0x11] == *(ushort *)(param_1 + 8))) {
    uVar7 = 0;
    uVar5 = 0;
    iVar11 = 0x1f;
    puVar6 = puVar2;
    do {
      uVar5 = uVar5 + *puVar6 + puVar6[1] + puVar6[2] + puVar6[3] + puVar6[4] + puVar6[5] +
              puVar6[6] + puVar6[7];
      uVar7 = uVar7 + ~*puVar6 + ~puVar6[1] + ~puVar6[2] + ~puVar6[3] + ~puVar6[4] + ~puVar6[5] +
              ~puVar6[6] + ~puVar6[7];
      puVar6 = puVar6 + 8;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    iVar11 = 6;
    do {
      uVar1 = *puVar6;
      puVar6 = puVar6 + 1;
      uVar5 = uVar5 + uVar1;
      uVar7 = uVar7 + ~uVar1;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    if (uVar5 == 0xffff) {
      uVar5 = 0;
    }
    if (uVar7 == 0xffff) {
      uVar7 = 0;
    }
    if ((puVar2[0xfe] == uVar5) && (puVar2[0xff] == uVar7)) {
      uVar5 = FUN_80243618();
      if (puVar2[0x12] == uVar5) {
        iVar10 = *(int *)(puVar2 + 6);
        uVar8 = *(uint *)(puVar2 + 8);
        puVar4 = FUN_802458dc();
        iVar11 = (param_1 + 0x7fc501c0) / 0x110 + (param_1 + 0x7fc501c0 >> 0x1f);
        pbVar9 = (byte *)(puVar4 + (iVar11 - (iVar11 >> 0x1f)) * 6);
        iVar11 = 0;
        do {
          lVar12 = FUN_80286bf4(iVar10 * 0x41c64e6d + (int)((ulonglong)uVar8 * 0x41c64e6d >> 0x20) +
                                (uint)(0xffffcfc6 < uVar8 * 0x41c64e6d),uVar8 * 0x41c64e6d + 0x3039,
                                0x10);
          if ((uint)*(byte *)puVar2 != ((int)lVar12 + (uint)*pbVar9 & 0xff)) {
            FUN_80245c64(0);
            return 0xfffffffa;
          }
          lVar12 = lVar12 * 0x41c64e6d + 0x3039;
          uVar13 = FUN_80286bf4((int)((ulonglong)lVar12 >> 0x20),(uint)lVar12,0x10);
          iVar11 = iVar11 + 1;
          uVar8 = (uint)uVar13 & 0x7fff;
          iVar10 = 0;
          pbVar9 = pbVar9 + 1;
          puVar2 = (ushort *)((int)puVar2 + 1);
        } while (iVar11 < 0xc);
        FUN_80245c64(0);
        uVar3 = 0;
      }
      else {
        uVar3 = 0xfffffff3;
      }
    }
    else {
      uVar3 = 0xfffffffa;
    }
  }
  else {
    uVar3 = 0xfffffffa;
  }
  return uVar3;
}

