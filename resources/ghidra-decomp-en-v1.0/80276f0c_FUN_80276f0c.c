// Function: FUN_80276f0c
// Entry: 80276f0c
// Size: 5388 bytes

void FUN_80276f0c(int param_1)

{
  short sVar1;
  ushort uVar2;
  char cVar6;
  undefined2 uVar5;
  undefined *puVar3;
  uint uVar4;
  uint uVar7;
  byte bVar9;
  int iVar8;
  uint uVar10;
  undefined4 uVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  uint local_98;
  uint local_94 [3];
  undefined4 local_88;
  undefined4 local_84;
  short local_80;
  undefined2 local_7e;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_6c;
  undefined *local_68;
  undefined *local_64;
  
  uVar10 = *(uint *)(param_1 + 0x118);
  if ((uVar10 & 3) != 0) {
    if ((uVar10 & 1) != 0) {
      *(uint *)(param_1 + 0x118) = uVar10 & 0xfffffffe;
      *(undefined4 *)(param_1 + 0x114) = *(undefined4 *)(param_1 + 0x114);
      FUN_8028343c(*(uint *)(param_1 + 0xf4) & 0xff);
    }
    iVar13 = (uint)*(byte *)(param_1 + 0x209) << 0x10;
    *(int *)(param_1 + 0x180) = iVar13;
    *(int *)(param_1 + 0x170) = iVar13;
    *(undefined4 *)(param_1 + 0x184) = 0;
    *(undefined4 *)(param_1 + 0x174) = 0;
    *(uint *)(param_1 + 0x154) = (uint)*(byte *)(param_1 + 0x208) << 0x10;
    *(undefined *)(param_1 + 0x192) = 0;
    *(undefined4 *)(param_1 + 0x158) = *(undefined4 *)(param_1 + 0x154);
    *(undefined *)(param_1 + 0x121) = *(undefined *)(param_1 + 0x20a);
    *(undefined *)(param_1 + 0x122) = *(undefined *)(param_1 + 0x20b);
    *(undefined *)(param_1 + 0x123) = *(undefined *)(param_1 + 0x20c);
    *(undefined *)(param_1 + 0x120) = *(undefined *)(param_1 + 0x20d);
    *(undefined *)(param_1 + 0x193) = *(undefined *)(param_1 + 0x210);
    *(undefined *)(param_1 + 0x104) = 0;
    *(undefined2 *)(param_1 + 0x150) = 0;
    *(undefined2 *)(param_1 + 0x16c) = 0;
    FUN_802829d0(param_1);
    cVar6 = FUN_8028202c(*(undefined *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122));
    if (cVar6 == -1) {
      *(undefined *)(param_1 + 0x130) = *(undefined *)(param_1 + 0x12f);
    }
    else {
      *(char *)(param_1 + 0x130) = cVar6;
    }
    FUN_80281fe8(*(undefined *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122),
                 *(undefined *)(param_1 + 0x12f));
    FUN_8027a258(param_1);
    *(undefined *)(param_1 + 0x11e) = *(undefined *)(param_1 + 0x20e);
    *(undefined *)(param_1 + 0x11f) = *(undefined *)(param_1 + 0x20f);
    *(undefined4 *)(param_1 + 0x13c) = 0;
    *(undefined4 *)(param_1 + 0x134) = 0x6400;
    *(undefined *)(param_1 + 0x131) = 0;
    if (*(char *)(param_1 + 0x121) == -1) {
      *(undefined2 *)(param_1 + 0x132) = 0;
    }
    else {
      uVar5 = FUN_80281b24(0x41,*(char *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122));
      *(undefined2 *)(param_1 + 0x132) = uVar5;
    }
    puVar3 = (undefined *)
             FUN_80281db0(*(undefined *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122));
    *(undefined *)(param_1 + 0x1d6) = *puVar3;
    *(undefined *)(param_1 + 0x1d7) = *puVar3;
    *(undefined *)(param_1 + 400) = 0x80;
    *(undefined *)(param_1 + 0x191) = 0;
    *(undefined2 *)(param_1 + 0xaa) = 0;
    *(undefined *)(param_1 + 0x1b8) = 0;
    *(undefined *)(param_1 + 0x1b9) = 0;
    *(undefined4 *)(param_1 + 0x1a0) = 0;
    *(undefined4 *)(param_1 + 0x1a4) = 0;
    *(undefined4 *)(param_1 + 0x1c0) = 0;
    *(undefined2 *)(param_1 + 0x1c4) = 0;
    *(undefined2 *)(param_1 + 0x1c6) = 0x7fff;
    *(undefined4 *)(param_1 + 0x1cc) = 0;
    *(undefined2 *)(param_1 + 0x1d0) = 0;
    *(undefined2 *)(param_1 + 0x1d2) = 0x7fff;
    *(undefined4 *)(param_1 + 0x50) = 0;
    *(undefined4 *)(param_1 + 0x54) = 0;
    *(undefined4 *)(param_1 + 0x58) = 0;
    *(undefined *)(param_1 + 0x68) = 0;
    *(undefined4 *)(param_1 + 0x124) = 0xffffffff;
    *(undefined4 *)(param_1 + 0x128) = 0xffffffff;
    *(undefined2 *)(param_1 + 0x1d8) = 0x2000;
    *(undefined2 *)(param_1 + 0x400) = 0;
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) & 8;
    *(undefined4 *)(param_1 + 0x114) = 0;
    *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x3000;
    FUN_800033a8(param_1 + 0xac,0,0x40);
    uVar11 = DAT_803de2e0;
    *(undefined4 *)(param_1 + 0xa4) = DAT_803de2e4;
    *(undefined4 *)(param_1 + 0xa0) = uVar11;
    uVar11 = DAT_803de2e0;
    *(undefined4 *)(param_1 + 0x94) = DAT_803de2e4;
    *(undefined4 *)(param_1 + 0x90) = uVar11;
    FUN_802712c8(param_1);
  }
  dVar16 = (double)FLOAT_803e7810;
  DAT_803de2d0 = 0;
  dVar17 = (double)FLOAT_803e7814;
  local_64 = &DAT_803bda74;
  local_68 = &DAT_803bdef4;
  local_6c = 0x7fff8000;
  do {
    DAT_803de2d0 = DAT_803de2d0 + 1;
    if (0x20 < DAT_803de2d0) {
      return;
    }
    uVar12 = 0;
    DAT_803de2e8 = **(uint **)(param_1 + 0x38);
    uRam803de2ec = *(uint *)(*(int *)(param_1 + 0x38) + 4);
    *(int *)(param_1 + 0x38) = *(int *)(param_1 + 0x38) + 8;
    uVar10 = DAT_803de2e8;
    cVar6 = (char)(DAT_803de2e8 >> 8);
    uVar2 = (ushort)(DAT_803de2e8 >> 8);
    sVar1 = (short)(DAT_803de2e8 >> 0x10);
    switch(DAT_803de2e8 & 0x7f) {
    case 0:
      FUN_80279038(param_1);
      FUN_80279b98(param_1);
      uVar12 = 1;
      break;
    case 1:
      FUN_80279038(param_1);
      FUN_80279b98(param_1);
      uVar12 = 1;
      break;
    case 2:
      if (((DAT_803de2e8 >> 8 & 0xff) <= (uint)*(ushort *)(param_1 + 300)) &&
         (iVar13 = FUN_80274e7c(DAT_803de2e8 >> 0x10), iVar13 != 0)) {
        *(int *)(param_1 + 0x34) = iVar13;
        *(uint *)(param_1 + 0x38) = iVar13 + (uRam803de2ec & 0xffff) * 8;
      }
      break;
    case 3:
      if (((DAT_803de2e8 >> 8 & 0xff) <= (*(uint *)(param_1 + 0x154) >> 0x10 & 0xff)) &&
         (iVar13 = FUN_80274e7c(DAT_803de2e8 >> 0x10), iVar13 != 0)) {
        *(int *)(param_1 + 0x34) = iVar13;
        *(uint *)(param_1 + 0x38) = iVar13 + (uRam803de2ec & 0xffff) * 8;
      }
      break;
    case 4:
      uVar12 = FUN_80275364(param_1,&DAT_803de2e8);
      break;
    case 5:
      FUN_8027566c(param_1,&DAT_803de2e8);
      break;
    case 6:
      iVar13 = FUN_80274e7c(DAT_803de2e8 >> 0x10);
      if (iVar13 == 0) {
        FUN_80279038(param_1);
        FUN_80279b98(param_1);
      }
      else {
        *(int *)(param_1 + 0x34) = iVar13;
        *(uint *)(param_1 + 0x38) = iVar13 + (uRam803de2ec & 0xffff) * 8;
      }
      uVar12 = (uint)(iVar13 == 0);
      break;
    case 7:
      uRam803de2ec._2_2_ = CONCAT11(1,(undefined)uRam803de2ec);
      uRam803de2ec = uRam803de2ec & 0xffff0000 | (uint)uRam803de2ec._2_2_;
      uVar12 = FUN_80275364(param_1,&DAT_803de2e8);
      break;
    case 8:
      FUN_802757c4(param_1,&DAT_803de2e8);
      break;
    case 9:
      bVar9 = *(byte *)(param_1 + 0x12f);
      uVar10 = DAT_803de2e8 >> 8;
      uVar4 = DAT_803de2e8 & 0xffff0000;
      iVar13 = 0;
      for (uVar14 = 0; uVar14 < DAT_803bd360; uVar14 = uVar14 + 1) {
        uVar7 = ((uint)bVar9 + (uVar10 & 0xff)) * 0x100 | uVar4 | uVar14;
        if (((*(uint *)(DAT_803de268 + iVar13 + 0xf4) == uVar7) && (uVar7 != 0xffffffff)) &&
           (iVar8 = (uVar14 & 0xff) * 0x404, uVar7 == *(uint *)(DAT_803de268 + iVar8 + 0xf4))) {
          FUN_80278610(DAT_803de268 + iVar8);
        }
        iVar13 = iVar13 + 0x404;
      }
      break;
    case 10:
      if (((*(char *)(param_1 + 0x121) != -1) &&
          (uVar10 = FUN_80282660(param_1), (DAT_803de2e8 >> 8 & 0xff) <= (uVar10 >> 7 & 0xff))) &&
         (iVar13 = FUN_80274e7c(DAT_803de2e8 >> 0x10), iVar13 != 0)) {
        *(int *)(param_1 + 0x34) = iVar13;
        *(uint *)(param_1 + 0x38) = iVar13 + (uRam803de2ec & 0xffff) * 8;
      }
      break;
    case 0xb:
      iVar13 = ((int)(((uint)*(ushort *)(param_1 + 300) - (DAT_803de2e8 >> 0x10 & 0xff)) * 0x10000 *
                     (int)cVar6) >> 7) + (DAT_803de2e8 >> 8 & 0xff0000);
      if (iVar13 < 0) {
        iVar13 = 0;
      }
      else if (0x7f0000 < iVar13) {
        iVar13 = 0x7f0000;
      }
      *(int *)(param_1 + 0x180) = iVar13;
      *(int *)(param_1 + 0x170) = iVar13;
      break;
    case 0xc:
      FUN_80275e48(param_1,&DAT_803de2e8);
      break;
    case 0xd:
      uVar10 = DAT_803de2e8 >> 8 & 0xff;
      if ((uRam803de2ec >> 8 & 0xff) == 0) {
        *(uint *)(param_1 + 0x154) = (*(int *)(param_1 + 0x154) * uVar10) / 0x7f;
      }
      else {
        *(uint *)(param_1 + 0x154) = (*(int *)(param_1 + 0x158) * uVar10) / 0x7f;
      }
      *(uint *)(param_1 + 0x154) = *(int *)(param_1 + 0x154) + (DAT_803de2e8 & 0xff0000);
      if (0x7f0000 < *(uint *)(param_1 + 0x154)) {
        *(undefined4 *)(param_1 + 0x154) = 0x7f0000;
      }
      uVar11 = FUN_802763c0(*(undefined4 *)(param_1 + 0x154),
                            DAT_803de2e8 >> 0x18 | (uRam803de2ec & 0xff) << 8);
      *(undefined4 *)(param_1 + 0x154) = uVar11;
      *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x1000;
      break;
    case 0xe:
      FUN_80276320(param_1,&DAT_803de2e8,0);
      break;
    case 0xf:
      FUN_80276440(param_1,&DAT_803de2e8,*(undefined4 *)(param_1 + 0x154));
      break;
    case 0x10:
      FUN_8027595c(param_1,&DAT_803de2e8);
      break;
    case 0x11:
      FUN_8028343c(*(uint *)(param_1 + 0xf4) & 0xff);
      break;
    case 0x12:
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x80;
      FUN_80271370(param_1);
      break;
    case 0x13:
      uVar10 = FUN_80282e5c();
      if (((DAT_803de2e8 >> 8 & 0xff) <= (uVar10 & 0xff)) &&
         (iVar13 = FUN_80274e7c(DAT_803de2e8 >> 0x10), iVar13 != 0)) {
        *(int *)(param_1 + 0x34) = iVar13;
        *(uint *)(param_1 + 0x38) = iVar13 + (uRam803de2ec & 0xffff) * 8;
      }
      break;
    case 0x14:
      FUN_80276440(param_1,&DAT_803de2e8,0);
      break;
    case 0x15:
      FUN_80276320(param_1,&DAT_803de2e8,1);
      break;
    case 0x16:
      uVar10 = FUN_80281b24(DAT_803de2e8 >> 0x18,*(undefined *)(param_1 + 0x121),
                            *(undefined *)(param_1 + 0x122));
      dVar15 = (double)*(float *)(&DAT_8032fb9c + (uVar10 >> 5 & 0x7fc));
      uVar10 = FUN_80281b24(DAT_803de2e8 >> 8 & 0xff,*(undefined *)(param_1 + 0x121),
                            *(undefined *)(param_1 + 0x122));
      local_88 = *(undefined4 *)(&DAT_8032edec + (uVar10 >> 5 & 0x7fc));
      uVar10 = FUN_80281b24(DAT_803de2e8 >> 0x10 & 0xff,*(undefined *)(param_1 + 0x121),
                            *(undefined *)(param_1 + 0x122));
      local_84 = *(undefined4 *)(&DAT_8032edec + (uVar10 >> 5 & 0x7fc));
      iVar13 = FUN_80285fb4((double)(float)(dVar16 * dVar15));
      local_80 = 0xc1 - (ushort)(byte)(&DAT_8032f79c)[iVar13];
      uVar10 = FUN_80281b24(uRam803de2ec & 0xff,*(undefined *)(param_1 + 0x121),
                            *(undefined *)(param_1 + 0x122));
      local_7e = (undefined2)*(undefined4 *)(&DAT_8032edec + (uVar10 >> 5 & 0x7fc));
      local_7c = 0x80000000;
      local_78 = 0x80000000;
      FUN_8028348c(*(uint *)(param_1 + 0xf4) & 0xff,&local_88,2);
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x100;
      break;
    case 0x17:
      FUN_8027656c(param_1,&DAT_803de2e8);
      break;
    case 0x18:
      if (DAT_803de2e8 >> 0x18 == 0) {
        *(short *)(param_1 + 300) = *(short *)(param_1 + 300) + (short)cVar6;
      }
      else {
        *(ushort *)(param_1 + 300) = (ushort)*(byte *)(param_1 + 0x12f) + (short)cVar6;
      }
      uVar2 = *(ushort *)(param_1 + 300);
      if ((short)uVar2 < 0) {
        uVar2 = 0;
      }
      else if (0x7f < uVar2) {
        uVar2 = 0x7f;
      }
      *(ushort *)(param_1 + 300) = uVar2;
      *(char *)(param_1 + 0x12e) = (char)(DAT_803de2e8 >> 0x10);
      iVar13 = FUN_8027a1dc(param_1);
      if (iVar13 != 0) {
        FUN_80281fe8(*(undefined *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122),
                     *(ushort *)(param_1 + 300) & 0xff);
      }
      DAT_803de2e8 = 4;
      uVar12 = FUN_80275364(param_1,&DAT_803de2e8);
      break;
    case 0x19:
      *(ushort *)(param_1 + 300) = uVar2 & 0x7f;
      *(char *)(param_1 + 0x12e) = (char)(DAT_803de2e8 >> 0x10);
      iVar13 = FUN_8027a1dc(param_1);
      if (iVar13 != 0) {
        FUN_80281fe8(*(undefined *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122),
                     *(ushort *)(param_1 + 300) & 0xff);
      }
      DAT_803de2e8 = 4;
      uVar12 = FUN_80275364(param_1,&DAT_803de2e8);
      break;
    case 0x1a:
      *(ushort *)(param_1 + 300) = (ushort)*(byte *)(param_1 + 0x130) + (short)cVar6;
      uVar2 = *(ushort *)(param_1 + 300);
      if ((short)uVar2 < 0) {
        uVar2 = 0;
      }
      else if (0x7f < uVar2) {
        uVar2 = 0x7f;
      }
      *(ushort *)(param_1 + 300) = uVar2;
      *(char *)(param_1 + 0x12e) = (char)(DAT_803de2e8 >> 0x10);
      if (*(char *)(param_1 + 0x121) != -1) {
        FUN_80281fe8(*(char *)(param_1 + 0x121),*(undefined *)(param_1 + 0x122),
                     *(ushort *)(param_1 + 300) & 0xff);
      }
      DAT_803de2e8 = 4;
      uVar12 = FUN_80275364(param_1,&DAT_803de2e8);
      break;
    case 0x1b:
      FUN_80276840(param_1,&DAT_803de2e8);
      break;
    case 0x1c:
      FUN_80275b38(param_1,&DAT_803de2e8);
      break;
    case 0x1d:
      *(undefined4 *)(param_1 + 0x1a0) = 0;
      *(char *)(param_1 + 0x1b8) = (char)(DAT_803de2e8 >> 8);
      *(uint *)(param_1 + 0x1b0) = (uint)*(byte *)(param_1 + 0x1b8) << 0x10;
      iVar13 = (int)(short)(DAT_803de2e8 >> 0x10);
      if (iVar13 < 0) {
        iVar13 = FUN_80283d5c(-iVar13);
        iVar13 = -iVar13;
      }
      else {
        iVar13 = FUN_80283d5c();
      }
      *(int *)(param_1 + 0x1a8) = iVar13 << 0x10;
      DAT_803de2e8 = 0;
      uVar12 = FUN_80275364(param_1,&DAT_803de2e8);
      break;
    case 0x1e:
      *(undefined4 *)(param_1 + 0x1a4) = 0;
      *(char *)(param_1 + 0x1b9) = (char)(DAT_803de2e8 >> 8);
      *(uint *)(param_1 + 0x1b4) = (uint)*(byte *)(param_1 + 0x1b9) << 0x10;
      iVar13 = (int)(short)(DAT_803de2e8 >> 0x10);
      if (iVar13 < 0) {
        iVar13 = FUN_80283d5c(-iVar13);
        iVar13 = -iVar13;
      }
      else {
        iVar13 = FUN_80283d5c();
      }
      *(int *)(param_1 + 0x1ac) = iVar13 << 0x10;
      DAT_803de2e8 = 0;
      uVar12 = FUN_80275364(param_1,&DAT_803de2e8);
      break;
    case 0x1f:
      *(uint *)(param_1 + 0x128) = DAT_803de2e8 >> 8;
      *(uint *)(param_1 + 0x128) = *(uint *)(param_1 + 0x128) | uRam803de2ec & 0xff;
      if (*(int *)(param_1 + 0x124) != -1) {
        FUN_80275cb8(param_1);
      }
      break;
    case 0x20:
      FUN_802760a0(param_1,&DAT_803de2e8);
      break;
    case 0x21:
      uVar10 = DAT_803de2e8 >> 8 & 0xffff;
      if (DAT_803de2e8 >> 0x18 == 0) {
        *(uint *)(param_1 + 0x154) = (*(uint *)(param_1 + 0x154) >> 5) * uVar10 >> 7;
      }
      else {
        *(uint *)(param_1 + 0x154) = (*(uint *)(param_1 + 0x158) >> 5) * uVar10 >> 7;
      }
      if (0x7f0000 < *(uint *)(param_1 + 0x154)) {
        *(undefined4 *)(param_1 + 0x154) = 0x7f0000;
      }
      *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x1000;
      break;
    case 0x22:
      *(short *)(param_1 + 0x150) = (short)((int)cVar6 << 8);
      sVar1 = *(short *)(param_1 + 0x150);
      cVar6 = (char)(DAT_803de2e8 >> 0x10);
      if (sVar1 < 0) {
        uVar4 = (uint)(short)cVar6;
        uVar10 = uVar4 << 8;
        iVar13 = (int)uVar10 / 100 + ((int)(uVar10 | uVar4 >> 0x18) >> 0x1f);
        *(short *)(param_1 + 0x150) = sVar1 - ((short)iVar13 - (short)(iVar13 >> 0x1f));
      }
      else {
        uVar4 = (uint)(short)cVar6;
        uVar10 = uVar4 << 8;
        iVar13 = (int)uVar10 / 100 + ((int)(uVar10 | uVar4 >> 0x18) >> 0x1f);
        *(short *)(param_1 + 0x150) = sVar1 + ((short)iVar13 - (short)(iVar13 >> 0x1f));
      }
      break;
    case 0x23:
      *(ushort *)(param_1 + 0x16c) = uVar2;
      *(short *)(param_1 + 0x16e) = (short)uRam803de2ec;
      *(float *)(param_1 + 0x168) = (float)dVar17;
      break;
    case 0x24:
      if (*(char *)(param_1 + 0x8c) != '\0') {
        *(undefined4 *)(param_1 + 0x34) =
             *(undefined4 *)(param_1 + (uint)*(byte *)(param_1 + 0x8d) * 8 + 0x6c);
        *(undefined4 *)(param_1 + 0x38) =
             *(undefined4 *)(param_1 + (uint)*(byte *)(param_1 + 0x8d) * 8 + 0x70);
        *(byte *)(param_1 + 0x8d) = *(char *)(param_1 + 0x8d) - 1U & 3;
        *(char *)(param_1 + 0x8c) = *(char *)(param_1 + 0x8c) + -1;
      }
      break;
    case 0x25:
      iVar13 = FUN_80274e7c(DAT_803de2e8 >> 0x10);
      if (iVar13 == 0) {
        FUN_80279038(param_1);
        FUN_80279b98(param_1);
        uVar12 = 1;
      }
      else {
        *(byte *)(param_1 + 0x8d) = *(char *)(param_1 + 0x8d) + 1U & 3;
        *(undefined4 *)(param_1 + (uint)*(byte *)(param_1 + 0x8d) * 8 + 0x6c) =
             *(undefined4 *)(param_1 + 0x34);
        *(undefined4 *)(param_1 + (uint)*(byte *)(param_1 + 0x8d) * 8 + 0x70) =
             *(undefined4 *)(param_1 + 0x38);
        bVar9 = *(char *)(param_1 + 0x8c) + 1;
        *(byte *)(param_1 + 0x8c) = bVar9;
        if (4 < bVar9) {
          *(undefined *)(param_1 + 0x8c) = 4;
        }
        *(int *)(param_1 + 0x34) = iVar13;
        uVar12 = 0;
        *(uint *)(param_1 + 0x38) = iVar13 + (uRam803de2ec & 0xffff) * 8;
      }
      break;
    case 0x28:
      iVar13 = FUN_80274e7c(DAT_803de2e8 >> 0x10);
      if (iVar13 != 0) {
        uVar10 = DAT_803de2e8 >> 8;
        iVar8 = param_1 + (DAT_803de2e8 >> 6 & 0x3fc);
        *(int *)(iVar8 + 0x50) = iVar13;
        *(uint *)(iVar8 + 0x5c) = iVar13 + (uRam803de2ec & 0xffff) * 8;
        *(undefined *)(param_1 + 0x68) = 1;
        if ((uVar10 & 0xff) == 0) {
          if ((*(uint *)(param_1 + 0x118) & 8 ^ 8 | *(uint *)(param_1 + 0x114) & 0x100 ^ 0x100) == 0
             ) {
            *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118);
            *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x400;
          }
        }
      }
      break;
    case 0x29:
      *(undefined4 *)(param_1 + (DAT_803de2e8 >> 6 & 0x3fc) + 0x50) = 0;
      iVar13 = param_1;
      for (bVar9 = 0; bVar9 < 3; bVar9 = bVar9 + 1) {
        if (*(int *)(iVar13 + 0x50) != 0) goto switchD_80277250_caseD_26;
        iVar13 = iVar13 + 4;
      }
      *(undefined *)(param_1 + 0x68) = 0;
      break;
    case 0x2a:
      FUN_80276c04(param_1,&DAT_803de2e8);
      break;
    case 0x2b:
      uVar11 = 0;
      if (*(char *)(param_1 + 0x3ec) != '\0') {
        uVar11 = *(undefined4 *)(param_1 + (uint)*(byte *)(param_1 + 0x3ed) * 4 + 0x3f0);
        *(byte *)(param_1 + 0x3ed) = *(byte *)(param_1 + 0x3ed) + 1 & 3;
        *(char *)(param_1 + 0x3ec) = *(char *)(param_1 + 0x3ec) + -1;
      }
      FUN_80276a70(param_1,0,DAT_803de2e8 >> 8 & 0xff,uVar11);
      break;
    case 0x2c:
      if ((DAT_803de2e8 >> 0x10 & 0xff) == 0) {
        FUN_80276a70(param_1,0,DAT_803de2e8 >> 8 & 0xff,
                     *(undefined4 *)(*(int *)(param_1 + 0xf8) + 8));
      }
      else {
        FUN_80276a70(param_1,0,DAT_803de2e8 >> 8 & 0xff,*(undefined4 *)(param_1 + 0x108));
      }
      break;
    case 0x30:
      iVar13 = (*(uint *)(param_1 + 0x110) >> 0xf) + (int)sVar1;
      if (iVar13 < 0) {
        *(undefined4 *)(param_1 + 0x110) = 0;
      }
      else if (iVar13 < 0x10000) {
        *(int *)(param_1 + 0x110) = iVar13 * 0x8000;
      }
      else {
        *(undefined4 *)(param_1 + 0x110) = local_6c;
      }
      FUN_8028327c(*(uint *)(param_1 + 0xf4) & 0xff,
                   (uint)*(byte *)(param_1 + 0x10c) << 0x18 | *(uint *)(param_1 + 0x110) >> 0xf);
      break;
    case 0x31:
      *(uint *)(param_1 + 0x110) = DAT_803de2e8 >> 1 & 0x7fff8000;
      FUN_8028327c(*(uint *)(param_1 + 0xf4) & 0xff,
                   (uint)*(byte *)(param_1 + 0x10c) << 0x18 | *(uint *)(param_1 + 0x110) >> 0xf);
      break;
    case 0x32:
      *(uint *)((int)&DAT_803bda34 + (DAT_803de2e8 >> 6 & 0x3fc)) = DAT_803de2e8 >> 0x10 & 0xff;
      break;
    case 0x33:
      *(char *)(param_1 + 0x1d6) = (char)(DAT_803de2e8 >> 0x10);
      *(char *)(param_1 + 0x1d7) = (char)(DAT_803de2e8 >> 8);
      break;
    case 0x34:
      *(char *)(param_1 + 400) = cVar6;
      *(char *)(param_1 + 0x191) = (char)(DAT_803de2e8 >> 0x10);
      break;
    case 0x35:
      *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x10000;
      break;
    case 0x36:
      FUN_802795cc(param_1,DAT_803de2e8 >> 8 & 0xff);
      break;
    case 0x37:
      uVar2 = (ushort)*(byte *)(param_1 + 0x10c) + sVar1;
      if ((short)uVar2 < 0) {
        uVar2 = 0;
      }
      else if (0xff < (short)uVar2) {
        uVar2 = 0xff;
      }
      FUN_802795cc(param_1,uVar2 & 0xff);
      break;
    case 0x38:
      if (uRam803de2ec == 0) {
        *(undefined2 *)(param_1 + 0x10e) = 0;
      }
      else {
        *(short *)(param_1 + 0x10e) = (short)((*(uint *)(param_1 + 0x110) >> 8) / uRam803de2ec);
      }
      break;
    case 0x39:
      uVar10 = (DAT_803de2e8 >> 0x10) +
               ((int)((uRam803de2ec & 0xffff) * (*(uint *)(param_1 + 0x154) >> 0x10 & 0xff)) >> 7);
      if (uVar10 < 0xea61) {
        iVar13 = uVar10 * 0x8000;
      }
      else {
        iVar13 = 0x75300000;
      }
      *(int *)(param_1 + 0x110) = iVar13;
      FUN_8028327c(*(uint *)(param_1 + 0xf4) & 0xff,
                   (uint)*(byte *)(param_1 + 0x10c) << 0x18 | *(uint *)(param_1 + 0x110) >> 0xf);
      break;
    case 0x40:
      FUN_8027670c(param_1,param_1 + 0x218,&DAT_803de2e8);
      break;
    case 0x41:
      FUN_8027670c(param_1,param_1 + 0x23c,&DAT_803de2e8);
      break;
    case 0x42:
      FUN_8027670c(param_1,param_1 + 0x284,&DAT_803de2e8);
      break;
    case 0x43:
      FUN_8027670c(param_1,param_1 + 0x2cc,&DAT_803de2e8);
      break;
    case 0x44:
      FUN_8027670c(param_1,param_1 + 0x2f0,&DAT_803de2e8);
      break;
    case 0x45:
      FUN_8027670c(param_1,param_1 + 0x314,&DAT_803de2e8);
      break;
    case 0x46:
      FUN_8027670c(param_1,param_1 + 0x35c,&DAT_803de2e8);
      break;
    case 0x47:
      FUN_8027670c(param_1,param_1 + 0x260,&DAT_803de2e8);
      break;
    case 0x48:
      FUN_8027670c(param_1,param_1 + 0x2a8,&DAT_803de2e8);
      break;
    case 0x49:
      FUN_8027670c(param_1,param_1 + 0x3c8,&DAT_803de2e8);
      break;
    case 0x4a:
      FUN_8027670c(param_1,param_1 + 0x338,&DAT_803de2e8);
      break;
    case 0x4b:
      FUN_8027670c(param_1,param_1 + 0x380,&DAT_803de2e8);
      break;
    case 0x4c:
      FUN_8027670c(param_1,param_1 + 0x3a4,&DAT_803de2e8);
      break;
    case 0x4d:
      uVar10 = uRam803de2ec >> 0x18;
      FUN_8027670c(param_1,local_68 + uVar10 * 0x24 + (uint)*(byte *)(param_1 + 0x11f) * 0x90,
                   &DAT_803de2e8,uVar10 * 4 + -0x7fcd1230,
                   *(undefined4 *)(&DAT_8032eff0 + uVar10 * 8),
                   *(undefined4 *)(&DAT_8032eff4 + uVar10 * 8),(&PTR_DAT_8032f010)[uVar10]);
      break;
    case 0x4e:
      uVar10 = uRam803de2ec >> 0x18;
      FUN_8027670c(param_1,local_64 + uVar10 * 0x24 + (uint)*(byte *)(param_1 + 0x11f) * 0x90,
                   &DAT_803de2e8,uVar10 * 4 + -0x7fcd1230,
                   *(undefined4 *)(&DAT_8032f020 + uVar10 * 8),
                   *(undefined4 *)(&DAT_8032f024 + uVar10 * 8),(&PTR_DAT_8032f040)[uVar10]);
      break;
    case 0x50:
      local_98 = DAT_803de2e8 >> 0x10;
      FUN_80282f80(&local_98);
      iVar13 = param_1 + (uVar10 >> 8 & 0xff) * 0xc;
      if (*(int *)(iVar13 + 0x1c0) != 0) {
        local_94[0] = uRam803de2ec & 0xffff;
        FUN_80282f80(local_94);
        *(uint *)(iVar13 + 0x1bc) = local_94[0];
      }
      *(uint *)(iVar13 + 0x1c0) = local_98;
      break;
    case 0x58:
      *(bool *)(param_1 + 0x192) = (DAT_803de2e8 >> 8 & 0xff) != 0;
      *(bool *)(param_1 + 0x193) = (DAT_803de2e8 >> 0x10 & 0xff) == 0;
      break;
    case 0x59:
      FUN_80276e38(param_1,&DAT_803de2e8);
      break;
    case 0x5a:
      FUN_80283788(*(uint *)(param_1 + 0xf4) & 0xff,DAT_803de2e8 >> 8 & 0xff);
      FUN_802837b4(*(uint *)(param_1 + 0xf4) & 0xff,DAT_803de2e8 >> 0x10 & 0xff);
      *(uint *)(param_1 + 0x114) = *(uint *)(param_1 + 0x114) | 0x800;
      break;
    case 0x60:
      FUN_80276ad4(param_1,&DAT_803de2e8,0);
      break;
    case 0x61:
      FUN_80276ad4(param_1,&DAT_803de2e8,1);
      break;
    case 0x62:
      FUN_80276ad4(param_1,&DAT_803de2e8,2);
      break;
    case 99:
      FUN_80276ad4(param_1,&DAT_803de2e8,3);
      break;
    case 100:
      FUN_80276ad4(param_1,&DAT_803de2e8,4);
      break;
    case 0x65:
      FUN_80276a70(param_1,DAT_803de2e8 >> 8 & 0xff,DAT_803de2e8 >> 0x10 & 0xff,
                   (int)(short)uRam803de2ec);
      break;
    case 0x70:
      if ((DAT_803de2e8 >> 8 & 0xff) == 0) {
        uVar10 = DAT_803de2e8 >> 0x10 & 0x1f;
        if (uVar10 < 0x10) {
          uVar10 = *(uint *)(param_1 + uVar10 * 4 + 0xac);
        }
        else {
          uVar10 = *(uint *)(&DAT_803bd9f4 + uVar10 * 4);
        }
      }
      else {
        uVar10 = FUN_80282d24(param_1);
        uVar10 = uVar10 & 0xffff;
      }
      if (DAT_803de2e8 >> 0x18 == 0) {
        uVar4 = uRam803de2ec & 0x1f;
        if (uVar4 < 0x10) {
          uVar4 = *(uint *)(param_1 + uVar4 * 4 + 0xac);
        }
        else {
          uVar4 = *(uint *)(&DAT_803bd9f4 + uVar4 * 4);
        }
      }
      else {
        uVar4 = FUN_80282d24(param_1);
        uVar4 = uVar4 & 0xffff;
      }
      uVar10 = countLeadingZeros(uVar4 - uVar10);
      uVar10 = uVar10 >> 5 & 0xff;
      if ((uRam803de2ec >> 8 & 0xff) != 0) {
        uVar10 = countLeadingZeros(uVar10);
        uVar10 = uVar10 >> 5 & 0xff;
      }
      if (uVar10 != 0) {
        *(uint *)(param_1 + 0x38) = *(int *)(param_1 + 0x34) + (uRam803de2ec >> 0x10) * 8;
      }
      break;
    case 0x71:
      if ((DAT_803de2e8 >> 8 & 0xff) == 0) {
        uVar10 = DAT_803de2e8 >> 0x10 & 0x1f;
        if (uVar10 < 0x10) {
          uVar10 = *(uint *)(param_1 + uVar10 * 4 + 0xac);
        }
        else {
          uVar10 = *(uint *)(&DAT_803bd9f4 + uVar10 * 4);
        }
      }
      else {
        uVar10 = FUN_80282d24(param_1);
        uVar10 = uVar10 & 0xffff;
      }
      if (DAT_803de2e8 >> 0x18 == 0) {
        uVar4 = uRam803de2ec & 0x1f;
        if (uVar4 < 0x10) {
          uVar4 = *(uint *)(param_1 + uVar4 * 4 + 0xac);
        }
        else {
          uVar4 = *(uint *)(&DAT_803bd9f4 + uVar4 * 4);
        }
      }
      else {
        uVar4 = FUN_80282d24(param_1);
        uVar4 = uVar4 & 0xffff;
      }
      uVar10 = (uint)(uVar4 <= uVar10) - ((int)~(uVar4 ^ uVar10) >> 0x1f) & 1;
      if ((uRam803de2ec >> 8 & 0xff) != 0) {
        uVar10 = countLeadingZeros(uVar10);
        uVar10 = uVar10 >> 5 & 0xff;
      }
      if (uVar10 != 0) {
        *(uint *)(param_1 + 0x38) = *(int *)(param_1 + 0x34) + (uRam803de2ec >> 0xd & 0x7fff8);
      }
    }
switchD_80277250_caseD_26:
    if (uVar12 != 0) {
      return;
    }
  } while( true );
}

