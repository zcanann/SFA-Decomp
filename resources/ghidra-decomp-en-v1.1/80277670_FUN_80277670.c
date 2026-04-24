// Function: FUN_80277670
// Entry: 80277670
// Size: 5388 bytes

void FUN_80277670(int *param_1)

{
  short sVar2;
  int iVar1;
  char cVar7;
  undefined *puVar3;
  int iVar4;
  ushort uVar6;
  byte bVar8;
  uint uVar5;
  uint uVar9;
  int *piVar10;
  uint uVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  uint local_98;
  uint local_94 [3];
  uint local_88;
  undefined4 local_84;
  short local_80;
  undefined2 local_7e;
  undefined4 local_7c;
  undefined4 local_78;
  int local_6c;
  undefined *local_68;
  undefined *local_64;
  
  uVar11 = param_1[0x46];
  if ((uVar11 & 3) != 0) {
    if ((uVar11 & 1) != 0) {
      param_1[0x46] = uVar11 & 0xfffffffe;
      param_1[0x45] = param_1[0x45];
      FUN_80283ba0(param_1[0x3d] & 0xff);
    }
    iVar12 = (uint)*(byte *)((int)param_1 + 0x209) << 0x10;
    param_1[0x60] = iVar12;
    param_1[0x5c] = iVar12;
    param_1[0x61] = 0;
    param_1[0x5d] = 0;
    param_1[0x55] = (uint)*(byte *)(param_1 + 0x82) << 0x10;
    *(undefined *)((int)param_1 + 0x192) = 0;
    param_1[0x56] = param_1[0x55];
    *(undefined *)((int)param_1 + 0x121) = *(undefined *)((int)param_1 + 0x20a);
    *(undefined *)((int)param_1 + 0x122) = *(undefined *)((int)param_1 + 0x20b);
    *(undefined *)((int)param_1 + 0x123) = *(undefined *)(param_1 + 0x83);
    *(undefined *)(param_1 + 0x48) = *(undefined *)((int)param_1 + 0x20d);
    *(undefined *)((int)param_1 + 0x193) = *(undefined *)(param_1 + 0x84);
    *(undefined *)(param_1 + 0x41) = 0;
    *(undefined2 *)(param_1 + 0x54) = 0;
    *(undefined2 *)(param_1 + 0x5b) = 0;
    FUN_80283134((int)param_1);
    cVar7 = FUN_80282790((uint)*(byte *)((int)param_1 + 0x121),(uint)*(byte *)((int)param_1 + 0x122)
                        );
    if (cVar7 == -1) {
      *(undefined *)(param_1 + 0x4c) = *(undefined *)((int)param_1 + 0x12f);
    }
    else {
      *(char *)(param_1 + 0x4c) = cVar7;
    }
    FUN_8028274c((uint)*(byte *)((int)param_1 + 0x121),(uint)*(byte *)((int)param_1 + 0x122),
                 *(undefined *)((int)param_1 + 0x12f));
    FUN_8027a9bc((int)param_1);
    *(undefined *)((int)param_1 + 0x11e) = *(undefined *)((int)param_1 + 0x20e);
    *(undefined *)((int)param_1 + 0x11f) = *(undefined *)((int)param_1 + 0x20f);
    param_1[0x4f] = 0;
    param_1[0x4d] = 0x6400;
    *(undefined *)((int)param_1 + 0x131) = 0;
    if (*(byte *)((int)param_1 + 0x121) == 0xff) {
      *(undefined2 *)((int)param_1 + 0x132) = 0;
    }
    else {
      uVar11 = FUN_80282288(0x41,(uint)*(byte *)((int)param_1 + 0x121),
                            (uint)*(byte *)((int)param_1 + 0x122));
      *(short *)((int)param_1 + 0x132) = (short)uVar11;
    }
    puVar3 = FUN_80282514((uint)*(byte *)((int)param_1 + 0x121),
                          (uint)*(byte *)((int)param_1 + 0x122));
    *(undefined *)((int)param_1 + 0x1d6) = *puVar3;
    *(undefined *)((int)param_1 + 0x1d7) = *puVar3;
    *(undefined *)(param_1 + 100) = 0x80;
    *(undefined *)((int)param_1 + 0x191) = 0;
    *(undefined2 *)((int)param_1 + 0xaa) = 0;
    *(undefined *)(param_1 + 0x6e) = 0;
    *(undefined *)((int)param_1 + 0x1b9) = 0;
    param_1[0x68] = 0;
    param_1[0x69] = 0;
    param_1[0x70] = 0;
    *(undefined2 *)(param_1 + 0x71) = 0;
    *(undefined2 *)((int)param_1 + 0x1c6) = 0x7fff;
    param_1[0x73] = 0;
    *(undefined2 *)(param_1 + 0x74) = 0;
    *(undefined2 *)((int)param_1 + 0x1d2) = 0x7fff;
    param_1[0x14] = 0;
    param_1[0x15] = 0;
    param_1[0x16] = 0;
    *(undefined *)(param_1 + 0x1a) = 0;
    param_1[0x49] = -1;
    param_1[0x4a] = -1;
    *(undefined2 *)(param_1 + 0x76) = 0x2000;
    *(undefined2 *)(param_1 + 0x100) = 0;
    param_1[0x46] = param_1[0x46] & 8;
    param_1[0x45] = 0;
    param_1[0x45] = param_1[0x45] | 0x3000;
    FUN_800033a8((int)(param_1 + 0x2b),0,0x40);
    iVar12 = DAT_803def60;
    param_1[0x29] = DAT_803def64;
    param_1[0x28] = iVar12;
    iVar12 = DAT_803def60;
    param_1[0x25] = DAT_803def64;
    param_1[0x24] = iVar12;
    FUN_80271a2c(param_1);
  }
  dVar16 = (double)FLOAT_803e84a8;
  DAT_803def50 = 0;
  dVar17 = (double)FLOAT_803e84ac;
  local_64 = &DAT_803be6d4;
  local_68 = &DAT_803beb54;
  local_6c = 0x7fff8000;
  iVar12 = -0x7fcd0000;
  do {
    DAT_803def50 = DAT_803def50 + 1;
    if (0x20 < DAT_803def50) {
      return;
    }
    uVar13 = 0;
    DAT_803def68 = *(uint *)param_1[0xe];
    uRam803def6c = *(uint *)(param_1[0xe] + 4);
    param_1[0xe] = param_1[0xe] + 8;
    uVar11 = DAT_803def68;
    bVar8 = (byte)(DAT_803def68 >> 8);
    uVar6 = (ushort)(DAT_803def68 >> 8);
    sVar2 = (short)(DAT_803def68 >> 0x10);
    switch(DAT_803def68 & 0x7f) {
    case 0:
      FUN_8027979c((int)param_1);
      FUN_8027a2fc((int)param_1);
      uVar13 = 1;
      break;
    case 1:
      FUN_8027979c((int)param_1);
      FUN_8027a2fc((int)param_1);
      uVar13 = 1;
      break;
    case 2:
      if (((DAT_803def68 >> 8 & 0xff) <= (uint)*(ushort *)(param_1 + 0x4b)) &&
         (iVar1 = FUN_802755e0(DAT_803def68 >> 0x10), iVar1 != 0)) {
        param_1[0xd] = iVar1;
        param_1[0xe] = iVar1 + (uRam803def6c & 0xffff) * 8;
      }
      break;
    case 3:
      if (((DAT_803def68 >> 8 & 0xff) <= ((uint)param_1[0x55] >> 0x10 & 0xff)) &&
         (iVar1 = FUN_802755e0(DAT_803def68 >> 0x10), iVar1 != 0)) {
        param_1[0xd] = iVar1;
        param_1[0xe] = iVar1 + (uRam803def6c & 0xffff) * 8;
      }
      break;
    case 4:
      uVar13 = FUN_80275ac8((int)param_1,&DAT_803def68);
      break;
    case 5:
      FUN_80275dd0((int)param_1,&DAT_803def68);
      break;
    case 6:
      iVar1 = FUN_802755e0(DAT_803def68 >> 0x10);
      if (iVar1 == 0) {
        FUN_8027979c((int)param_1);
        FUN_8027a2fc((int)param_1);
      }
      else {
        param_1[0xd] = iVar1;
        param_1[0xe] = iVar1 + (uRam803def6c & 0xffff) * 8;
      }
      uVar13 = (uint)(iVar1 == 0);
      break;
    case 7:
      uRam803def6c._2_2_ = CONCAT11(1,(undefined)uRam803def6c);
      uVar13 = FUN_80275ac8((int)param_1,&DAT_803def68);
      break;
    case 8:
      FUN_80275f28((int)param_1,&DAT_803def68);
      break;
    case 9:
      bVar8 = *(byte *)((int)param_1 + 0x12f);
      uVar11 = DAT_803def68 >> 8;
      uVar5 = DAT_803def68 & 0xffff0000;
      iVar1 = 0;
      for (uVar14 = 0; uVar14 < DAT_803bdfc0; uVar14 = uVar14 + 1) {
        uVar9 = ((uint)bVar8 + (uVar11 & 0xff)) * 0x100 | uVar5 | uVar14;
        if (((*(uint *)(DAT_803deee8 + iVar1 + 0xf4) == uVar9) && (uVar9 != 0xffffffff)) &&
           (iVar4 = (uVar14 & 0xff) * 0x404, uVar9 == *(uint *)(DAT_803deee8 + iVar4 + 0xf4))) {
          FUN_80278d74((int *)(DAT_803deee8 + iVar4));
        }
        iVar1 = iVar1 + 0x404;
      }
      break;
    case 10:
      if (((*(char *)((int)param_1 + 0x121) != -1) &&
          (uVar11 = FUN_80282dc4((int)param_1), (DAT_803def68 >> 8 & 0xff) <= (uVar11 >> 7 & 0xff)))
         && (iVar1 = FUN_802755e0(DAT_803def68 >> 0x10), iVar1 != 0)) {
        param_1[0xd] = iVar1;
        param_1[0xe] = iVar1 + (uRam803def6c & 0xffff) * 8;
      }
      break;
    case 0xb:
      iVar1 = ((int)(((uint)*(ushort *)(param_1 + 0x4b) - (DAT_803def68 >> 0x10 & 0xff)) * 0x10000 *
                    (int)(char)bVar8) >> 7) + (DAT_803def68 >> 8 & 0xff0000);
      if (iVar1 < 0) {
        iVar1 = 0;
      }
      else if (0x7f0000 < iVar1) {
        iVar1 = 0x7f0000;
      }
      param_1[0x60] = iVar1;
      param_1[0x5c] = iVar1;
      break;
    case 0xc:
      FUN_802765ac((int)param_1,&DAT_803def68);
      break;
    case 0xd:
      uVar11 = DAT_803def68 >> 8 & 0xff;
      if ((uRam803def6c >> 8 & 0xff) == 0) {
        param_1[0x55] = (param_1[0x55] * uVar11) / 0x7f;
      }
      else {
        param_1[0x55] = (param_1[0x56] * uVar11) / 0x7f;
      }
      param_1[0x55] = param_1[0x55] + (DAT_803def68 & 0xff0000);
      if (0x7f0000 < (uint)param_1[0x55]) {
        param_1[0x55] = 0x7f0000;
      }
      uVar11 = FUN_80276b24(param_1[0x55],
                            (ushort)(byte)(DAT_803def68 >> 0x18) | (ushort)(uRam803def6c << 8));
      param_1[0x55] = uVar11;
      param_1[0x45] = param_1[0x45] | 0x1000;
      break;
    case 0xe:
      FUN_80276a84((int)param_1,&DAT_803def68,0);
      break;
    case 0xf:
      FUN_80276ba4((int)param_1,&DAT_803def68,param_1[0x55]);
      break;
    case 0x10:
      FUN_802760c0(param_1,&DAT_803def68);
      break;
    case 0x11:
      FUN_80283ba0(param_1[0x3d] & 0xff);
      break;
    case 0x12:
      param_1[0x46] = param_1[0x46] | 0x80;
      FUN_80271ad4(param_1);
      break;
    case 0x13:
      uVar11 = FUN_802835c0();
      if (((DAT_803def68 >> 8 & 0xff) <= (uVar11 & 0xff)) &&
         (iVar1 = FUN_802755e0(DAT_803def68 >> 0x10), iVar1 != 0)) {
        param_1[0xd] = iVar1;
        param_1[0xe] = iVar1 + (uRam803def6c & 0xffff) * 8;
      }
      break;
    case 0x14:
      FUN_80276ba4((int)param_1,&DAT_803def68,0);
      break;
    case 0x15:
      FUN_80276a84((int)param_1,&DAT_803def68,1);
      break;
    case 0x16:
      uVar11 = FUN_80282288(DAT_803def68 >> 0x18,(uint)*(byte *)((int)param_1 + 0x121),
                            (uint)*(byte *)((int)param_1 + 0x122));
      dVar15 = (double)*(float *)(&DAT_803307fc + (uVar11 >> 5 & 0x7fc));
      uVar11 = FUN_80282288(DAT_803def68 >> 8 & 0xff,(uint)*(byte *)((int)param_1 + 0x121),
                            (uint)*(byte *)((int)param_1 + 0x122));
      local_88 = *(uint *)(&DAT_8032fa4c + (uVar11 >> 5 & 0x7fc));
      uVar11 = FUN_80282288(DAT_803def68 >> 0x10 & 0xff,(uint)*(byte *)((int)param_1 + 0x121),
                            (uint)*(byte *)((int)param_1 + 0x122));
      local_84 = *(undefined4 *)(&DAT_8032fa4c + (uVar11 >> 5 & 0x7fc));
      iVar1 = FUN_80286718((double)(float)(dVar16 * dVar15));
      local_80 = 0xc1 - (ushort)(byte)(&DAT_803303fc)[iVar1];
      uVar11 = FUN_80282288(uRam803def6c & 0xff,(uint)*(byte *)((int)param_1 + 0x121),
                            (uint)*(byte *)((int)param_1 + 0x122));
      local_7e = (undefined2)*(undefined4 *)(&DAT_8032fa4c + (uVar11 >> 5 & 0x7fc));
      local_7c = 0x80000000;
      local_78 = 0x80000000;
      FUN_80283bf0(param_1[0x3d] & 0xff,&local_88,2);
      param_1[0x46] = param_1[0x46] | 0x100;
      break;
    case 0x17:
      FUN_80276cd0((int)param_1,&DAT_803def68);
      break;
    case 0x18:
      if (DAT_803def68 >> 0x18 == 0) {
        *(short *)(param_1 + 0x4b) = *(short *)(param_1 + 0x4b) + (short)(char)bVar8;
      }
      else {
        *(ushort *)(param_1 + 0x4b) = (ushort)*(byte *)((int)param_1 + 0x12f) + (short)(char)bVar8;
      }
      uVar6 = *(ushort *)(param_1 + 0x4b);
      if ((short)uVar6 < 0) {
        uVar6 = 0;
      }
      else if (0x7f < uVar6) {
        uVar6 = 0x7f;
      }
      *(ushort *)(param_1 + 0x4b) = uVar6;
      *(char *)((int)param_1 + 0x12e) = (char)(DAT_803def68 >> 0x10);
      iVar1 = FUN_8027a940((int)param_1);
      if (iVar1 != 0) {
        FUN_8028274c((uint)*(byte *)((int)param_1 + 0x121),(uint)*(byte *)((int)param_1 + 0x122),
                     (char)*(undefined2 *)(param_1 + 0x4b));
      }
      DAT_803def68 = 4;
      uVar13 = FUN_80275ac8((int)param_1,&DAT_803def68);
      break;
    case 0x19:
      *(ushort *)(param_1 + 0x4b) = uVar6 & 0x7f;
      *(char *)((int)param_1 + 0x12e) = (char)(DAT_803def68 >> 0x10);
      iVar1 = FUN_8027a940((int)param_1);
      if (iVar1 != 0) {
        FUN_8028274c((uint)*(byte *)((int)param_1 + 0x121),(uint)*(byte *)((int)param_1 + 0x122),
                     (char)*(undefined2 *)(param_1 + 0x4b));
      }
      DAT_803def68 = 4;
      uVar13 = FUN_80275ac8((int)param_1,&DAT_803def68);
      break;
    case 0x1a:
      *(ushort *)(param_1 + 0x4b) = (ushort)*(byte *)(param_1 + 0x4c) + (short)(char)bVar8;
      uVar6 = *(ushort *)(param_1 + 0x4b);
      if ((short)uVar6 < 0) {
        uVar6 = 0;
      }
      else if (0x7f < uVar6) {
        uVar6 = 0x7f;
      }
      *(ushort *)(param_1 + 0x4b) = uVar6;
      *(char *)((int)param_1 + 0x12e) = (char)(DAT_803def68 >> 0x10);
      if (*(byte *)((int)param_1 + 0x121) != 0xff) {
        FUN_8028274c((uint)*(byte *)((int)param_1 + 0x121),(uint)*(byte *)((int)param_1 + 0x122),
                     (char)*(undefined2 *)(param_1 + 0x4b));
      }
      DAT_803def68 = 4;
      uVar13 = FUN_80275ac8((int)param_1,&DAT_803def68);
      break;
    case 0x1b:
      FUN_80276fa4((int)param_1,&DAT_803def68);
      break;
    case 0x1c:
      FUN_8027629c((int)param_1,&DAT_803def68);
      break;
    case 0x1d:
      param_1[0x68] = 0;
      *(char *)(param_1 + 0x6e) = (char)(DAT_803def68 >> 8);
      param_1[0x6c] = (uint)*(byte *)(param_1 + 0x6e) << 0x10;
      iVar1 = (int)(short)(DAT_803def68 >> 0x10);
      if (iVar1 < 0) {
        iVar1 = FUN_802844c0(-iVar1);
        iVar1 = -iVar1;
      }
      else {
        iVar1 = FUN_802844c0(iVar1);
      }
      param_1[0x6a] = iVar1 << 0x10;
      DAT_803def68 = 0;
      uVar13 = FUN_80275ac8((int)param_1,&DAT_803def68);
      break;
    case 0x1e:
      param_1[0x69] = 0;
      *(char *)((int)param_1 + 0x1b9) = (char)(DAT_803def68 >> 8);
      param_1[0x6d] = (uint)*(byte *)((int)param_1 + 0x1b9) << 0x10;
      iVar1 = (int)(short)(DAT_803def68 >> 0x10);
      if (iVar1 < 0) {
        iVar1 = FUN_802844c0(-iVar1);
        iVar1 = -iVar1;
      }
      else {
        iVar1 = FUN_802844c0(iVar1);
      }
      param_1[0x6b] = iVar1 << 0x10;
      DAT_803def68 = 0;
      uVar13 = FUN_80275ac8((int)param_1,&DAT_803def68);
      break;
    case 0x1f:
      param_1[0x4a] = DAT_803def68 >> 8;
      param_1[0x4a] = param_1[0x4a] | uRam803def6c & 0xff;
      if (param_1[0x49] != -1) {
        FUN_8027641c((int)param_1);
      }
      break;
    case 0x20:
      FUN_80276804((int)param_1,&DAT_803def68);
      break;
    case 0x21:
      uVar11 = DAT_803def68 >> 8 & 0xffff;
      if (DAT_803def68 >> 0x18 == 0) {
        param_1[0x55] = ((uint)param_1[0x55] >> 5) * uVar11 >> 7;
      }
      else {
        param_1[0x55] = ((uint)param_1[0x56] >> 5) * uVar11 >> 7;
      }
      if (0x7f0000 < (uint)param_1[0x55]) {
        param_1[0x55] = 0x7f0000;
      }
      param_1[0x45] = param_1[0x45] | 0x1000;
      break;
    case 0x22:
      *(short *)(param_1 + 0x54) = (short)((int)(char)bVar8 << 8);
      sVar2 = *(short *)(param_1 + 0x54);
      cVar7 = (char)(DAT_803def68 >> 0x10);
      if (sVar2 < 0) {
        uVar5 = (uint)(short)cVar7;
        uVar11 = uVar5 << 8;
        iVar1 = (int)uVar11 / 100 + ((int)(uVar11 | uVar5 >> 0x18) >> 0x1f);
        *(short *)(param_1 + 0x54) = sVar2 - ((short)iVar1 - (short)(iVar1 >> 0x1f));
      }
      else {
        uVar5 = (uint)(short)cVar7;
        uVar11 = uVar5 << 8;
        iVar1 = (int)uVar11 / 100 + ((int)(uVar11 | uVar5 >> 0x18) >> 0x1f);
        *(short *)(param_1 + 0x54) = sVar2 + ((short)iVar1 - (short)(iVar1 >> 0x1f));
      }
      break;
    case 0x23:
      *(ushort *)(param_1 + 0x5b) = uVar6;
      *(short *)((int)param_1 + 0x16e) = (short)uRam803def6c;
      param_1[0x5a] = (int)(float)dVar17;
      break;
    case 0x24:
      if (*(char *)(param_1 + 0x23) != '\0') {
        param_1[0xd] = param_1[(uint)*(byte *)((int)param_1 + 0x8d) * 2 + 0x1b];
        param_1[0xe] = param_1[(uint)*(byte *)((int)param_1 + 0x8d) * 2 + 0x1c];
        *(byte *)((int)param_1 + 0x8d) = *(char *)((int)param_1 + 0x8d) - 1U & 3;
        *(char *)(param_1 + 0x23) = *(char *)(param_1 + 0x23) + -1;
      }
      break;
    case 0x25:
      iVar1 = FUN_802755e0(DAT_803def68 >> 0x10);
      if (iVar1 == 0) {
        FUN_8027979c((int)param_1);
        FUN_8027a2fc((int)param_1);
        uVar13 = 1;
      }
      else {
        *(byte *)((int)param_1 + 0x8d) = *(char *)((int)param_1 + 0x8d) + 1U & 3;
        param_1[(uint)*(byte *)((int)param_1 + 0x8d) * 2 + 0x1b] = param_1[0xd];
        param_1[(uint)*(byte *)((int)param_1 + 0x8d) * 2 + 0x1c] = param_1[0xe];
        cVar7 = *(char *)(param_1 + 0x23);
        *(byte *)(param_1 + 0x23) = cVar7 + 1U;
        if (4 < (byte)(cVar7 + 1U)) {
          *(undefined *)(param_1 + 0x23) = 4;
        }
        param_1[0xd] = iVar1;
        uVar13 = 0;
        param_1[0xe] = iVar1 + (uRam803def6c & 0xffff) * 8;
      }
      break;
    case 0x28:
      iVar1 = FUN_802755e0(DAT_803def68 >> 0x10);
      if (iVar1 != 0) {
        uVar11 = DAT_803def68 >> 8;
        uVar5 = DAT_803def68 >> 6 & 0x3fc;
        *(int *)((int)param_1 + uVar5 + 0x50) = iVar1;
        *(uint *)((int)param_1 + uVar5 + 0x5c) = iVar1 + (uRam803def6c & 0xffff) * 8;
        *(undefined *)(param_1 + 0x1a) = 1;
        if ((uVar11 & 0xff) == 0) {
          iVar12 = 8;
          if ((param_1[0x46] & 8U) == 8 && (param_1[0x45] & 0x100U) == 0x100) {
            param_1[0x46] = param_1[0x46];
            param_1[0x45] = param_1[0x45] | 0x400;
          }
        }
      }
      break;
    case 0x29:
      *(undefined4 *)((int)param_1 + (DAT_803def68 >> 6 & 0x3fc) + 0x50) = 0;
      piVar10 = param_1;
      for (bVar8 = 0; bVar8 < 3; bVar8 = bVar8 + 1) {
        if (piVar10[0x14] != 0) goto switchD_802779b4_caseD_26;
        piVar10 = piVar10 + 1;
      }
      *(undefined *)(param_1 + 0x1a) = 0;
      break;
    case 0x2a:
      FUN_80277368((int)param_1,&DAT_803def68);
      break;
    case 0x2b:
      iVar12 = 0;
      if (*(char *)(param_1 + 0xfb) != '\0') {
        iVar12 = param_1[*(byte *)((int)param_1 + 0x3ed) + 0xfc];
        *(byte *)((int)param_1 + 0x3ed) = *(byte *)((int)param_1 + 0x3ed) + 1 & 3;
        *(char *)(param_1 + 0xfb) = *(char *)(param_1 + 0xfb) + -1;
      }
      FUN_802771d4((int)param_1,0,DAT_803def68 >> 8 & 0xff,iVar12);
      break;
    case 0x2c:
      if ((DAT_803def68 >> 0x10 & 0xff) == 0) {
        iVar12 = *(int *)(param_1[0x3e] + 8);
        FUN_802771d4((int)param_1,0,DAT_803def68 >> 8 & 0xff,iVar12);
      }
      else {
        iVar12 = param_1[0x42];
        FUN_802771d4((int)param_1,0,DAT_803def68 >> 8 & 0xff,iVar12);
      }
      break;
    case 0x30:
      iVar1 = ((uint)param_1[0x44] >> 0xf) + (int)sVar2;
      if (iVar1 < 0) {
        param_1[0x44] = 0;
      }
      else if (iVar1 < 0x10000) {
        param_1[0x44] = iVar1 * 0x8000;
      }
      else {
        param_1[0x44] = local_6c;
      }
      FUN_802839e0(param_1[0x3d] & 0xff,
                   (uint)*(byte *)(param_1 + 0x43) << 0x18 | (uint)param_1[0x44] >> 0xf);
      break;
    case 0x31:
      param_1[0x44] = DAT_803def68 >> 1 & 0x7fff8000;
      FUN_802839e0(param_1[0x3d] & 0xff,
                   (uint)*(byte *)(param_1 + 0x43) << 0x18 | (uint)param_1[0x44] >> 0xf);
      break;
    case 0x32:
      *(uint *)((int)&DAT_803be694 + (DAT_803def68 >> 6 & 0x3fc)) = DAT_803def68 >> 0x10 & 0xff;
      break;
    case 0x33:
      *(char *)((int)param_1 + 0x1d6) = (char)(DAT_803def68 >> 0x10);
      *(char *)((int)param_1 + 0x1d7) = (char)(DAT_803def68 >> 8);
      break;
    case 0x34:
      *(byte *)(param_1 + 100) = bVar8;
      *(char *)((int)param_1 + 0x191) = (char)(DAT_803def68 >> 0x10);
      break;
    case 0x35:
      param_1[0x46] = param_1[0x46] | 0x10000;
      break;
    case 0x36:
      FUN_80279d30((int)param_1,bVar8);
      break;
    case 0x37:
      sVar2 = (ushort)*(byte *)(param_1 + 0x43) + sVar2;
      if (sVar2 < 0) {
        sVar2 = 0;
      }
      else if (0xff < sVar2) {
        sVar2 = 0xff;
      }
      FUN_80279d30((int)param_1,(byte)sVar2);
      break;
    case 0x38:
      if (uRam803def6c == 0) {
        *(undefined2 *)((int)param_1 + 0x10e) = 0;
      }
      else {
        *(short *)((int)param_1 + 0x10e) = (short)(((uint)param_1[0x44] >> 8) / uRam803def6c);
      }
      break;
    case 0x39:
      uVar11 = (DAT_803def68 >> 0x10) +
               ((int)((uRam803def6c & 0xffff) * ((uint)param_1[0x55] >> 0x10 & 0xff)) >> 7);
      if (uVar11 < 0xea61) {
        iVar1 = uVar11 * 0x8000;
      }
      else {
        iVar1 = 0x75300000;
      }
      param_1[0x44] = iVar1;
      FUN_802839e0(param_1[0x3d] & 0xff,
                   (uint)*(byte *)(param_1 + 0x43) << 0x18 | (uint)param_1[0x44] >> 0xf);
      break;
    case 0x40:
      FUN_80276e70((int)param_1,(int)(param_1 + 0x86),&DAT_803def68,iVar12,0,0x80000,1);
      break;
    case 0x41:
      FUN_80276e70((int)param_1,(int)(param_1 + 0x8f),&DAT_803def68,iVar12,0,0x100000,2);
      break;
    case 0x42:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xa1),&DAT_803def68,iVar12,0,0x200000,8);
      break;
    case 0x43:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xb3),&DAT_803def68,iVar12,0,0x400000,0x20);
      break;
    case 0x44:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xbc),&DAT_803def68,iVar12,0,0x2000000,0x40);
      break;
    case 0x45:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xc5),&DAT_803def68,iVar12,0,0x1000000,0x80);
      break;
    case 0x46:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xd7),&DAT_803def68,iVar12,0,0x800000,0x200);
      break;
    case 0x47:
      FUN_80276e70((int)param_1,(int)(param_1 + 0x98),&DAT_803def68,iVar12,0,0x4000000,4);
      break;
    case 0x48:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xaa),&DAT_803def68,iVar12,0,0x8000000,0x10);
      break;
    case 0x49:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xf2),&DAT_803def68,iVar12,0,0x10000000,0x1000);
      break;
    case 0x4a:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xce),&DAT_803def68,iVar12,0,0x20000000,0x100);
      break;
    case 0x4b:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xe0),&DAT_803def68,iVar12,0,0x40000000,0x400);
      break;
    case 0x4c:
      FUN_80276e70((int)param_1,(int)(param_1 + 0xe9),&DAT_803def68,iVar12,0,0x80000000,0x800);
      break;
    case 0x4d:
      uVar11 = uRam803def6c >> 0x18;
      iVar12 = uVar11 * 4 + -0x7fcd05d0;
      FUN_80276e70((int)param_1,
                   (int)(local_68 + uVar11 * 0x24 + (uint)*(byte *)((int)param_1 + 0x11f) * 0x90),
                   &DAT_803def68,iVar12,*(uint *)(&DAT_8032fc50 + uVar11 * 8),
                   *(uint *)(&DAT_8032fc54 + uVar11 * 8),(uint)(&PTR_DAT_8032fc70)[uVar11]);
      break;
    case 0x4e:
      uVar11 = uRam803def6c >> 0x18;
      iVar12 = uVar11 * 4 + -0x7fcd05d0;
      FUN_80276e70((int)param_1,
                   (int)(local_64 + uVar11 * 0x24 + (uint)*(byte *)((int)param_1 + 0x11f) * 0x90),
                   &DAT_803def68,iVar12,*(uint *)(&DAT_8032fc80 + uVar11 * 8),
                   *(uint *)(&DAT_8032fc84 + uVar11 * 8),(uint)(&PTR_DAT_8032fca0)[uVar11]);
      break;
    case 0x50:
      local_98 = DAT_803def68 >> 0x10;
      FUN_802836e4((int *)&local_98);
      uVar11 = uVar11 >> 8 & 0xff;
      if (param_1[uVar11 * 3 + 0x70] != 0) {
        local_94[0] = uRam803def6c & 0xffff;
        FUN_802836e4((int *)local_94);
        param_1[uVar11 * 3 + 0x6f] = local_94[0];
      }
      param_1[uVar11 * 3 + 0x70] = local_98;
      break;
    case 0x58:
      *(bool *)((int)param_1 + 0x192) = (DAT_803def68 >> 8 & 0xff) != 0;
      *(bool *)((int)param_1 + 0x193) = (DAT_803def68 >> 0x10 & 0xff) == 0;
      break;
    case 0x59:
      FUN_8027759c((int)param_1,&DAT_803def68);
      break;
    case 0x5a:
      FUN_80283eec(param_1[0x3d] & 0xff,DAT_803def68 >> 8 & 0xff);
      FUN_80283f18(param_1[0x3d] & 0xff,DAT_803def68 >> 0x10 & 0xff);
      param_1[0x45] = param_1[0x45] | 0x800;
      break;
    case 0x60:
      FUN_80277238((int)param_1,&DAT_803def68,0);
      break;
    case 0x61:
      FUN_80277238((int)param_1,&DAT_803def68,1);
      break;
    case 0x62:
      FUN_80277238((int)param_1,&DAT_803def68,2);
      break;
    case 99:
      FUN_80277238((int)param_1,&DAT_803def68,3);
      break;
    case 100:
      FUN_80277238((int)param_1,&DAT_803def68,4);
      break;
    case 0x65:
      iVar12 = (int)(short)uRam803def6c;
      FUN_802771d4((int)param_1,DAT_803def68 >> 8 & 0xff,DAT_803def68 >> 0x10 & 0xff,iVar12);
      break;
    case 0x70:
      if ((DAT_803def68 >> 8 & 0xff) == 0) {
        uVar11 = DAT_803def68 >> 0x10 & 0x1f;
        if (uVar11 < 0x10) {
          uVar11 = param_1[uVar11 + 0x2b];
        }
        else {
          uVar11 = *(uint *)(&DAT_803be654 + uVar11 * 4);
        }
      }
      else {
        uVar11 = FUN_80283488((int)param_1,DAT_803def68 >> 0x10 & 0xff);
        uVar11 = uVar11 & 0xffff;
      }
      if (DAT_803def68 >> 0x18 == 0) {
        uVar5 = uRam803def6c & 0x1f;
        if (uVar5 < 0x10) {
          uVar5 = param_1[uVar5 + 0x2b];
        }
        else {
          uVar5 = *(uint *)(&DAT_803be654 + uVar5 * 4);
        }
      }
      else {
        uVar5 = FUN_80283488((int)param_1,uRam803def6c & 0xff);
        uVar5 = uVar5 & 0xffff;
      }
      uVar11 = countLeadingZeros(uVar5 - uVar11);
      uVar11 = uVar11 >> 5 & 0xff;
      if ((uRam803def6c >> 8 & 0xff) != 0) {
        uVar11 = countLeadingZeros(uVar11);
        uVar11 = uVar11 >> 5 & 0xff;
      }
      if (uVar11 != 0) {
        param_1[0xe] = param_1[0xd] + (uRam803def6c >> 0x10) * 8;
      }
      break;
    case 0x71:
      if ((DAT_803def68 >> 8 & 0xff) == 0) {
        uVar11 = DAT_803def68 >> 0x10 & 0x1f;
        if (uVar11 < 0x10) {
          uVar11 = param_1[uVar11 + 0x2b];
        }
        else {
          uVar11 = *(uint *)(&DAT_803be654 + uVar11 * 4);
        }
      }
      else {
        uVar11 = FUN_80283488((int)param_1,DAT_803def68 >> 0x10 & 0xff);
        uVar11 = uVar11 & 0xffff;
      }
      if (DAT_803def68 >> 0x18 == 0) {
        uVar5 = uRam803def6c & 0x1f;
        if (uVar5 < 0x10) {
          uVar5 = param_1[uVar5 + 0x2b];
        }
        else {
          uVar5 = *(uint *)(&DAT_803be654 + uVar5 * 4);
        }
      }
      else {
        uVar5 = FUN_80283488((int)param_1,uRam803def6c & 0xff);
        uVar5 = uVar5 & 0xffff;
      }
      uVar11 = (uint)(uVar5 <= uVar11) - ((int)~(uVar5 ^ uVar11) >> 0x1f) & 1;
      if ((uRam803def6c >> 8 & 0xff) != 0) {
        uVar11 = countLeadingZeros(uVar11);
        uVar11 = uVar11 >> 5 & 0xff;
      }
      if (uVar11 != 0) {
        param_1[0xe] = param_1[0xd] + (uRam803def6c >> 0xd & 0x7fff8);
      }
    }
switchD_802779b4_caseD_26:
    if (uVar13 != 0) {
      return;
    }
  } while( true );
}

