// Function: FUN_80123204
// Entry: 80123204
// Size: 3684 bytes

void FUN_80123204(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  float fVar1;
  short sVar2;
  int iVar3;
  short sVar4;
  short sVar5;
  ushort uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  char *pcVar10;
  int iVar11;
  int iVar12;
  byte bVar13;
  undefined4 uVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  byte *pbVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  double dVar22;
  double dVar23;
  double dVar24;
  undefined8 uVar25;
  undefined auStack232 [4];
  undefined auStack228 [4];
  undefined auStack224 [4];
  undefined auStack220 [4];
  undefined auStack216 [4];
  undefined auStack212 [4];
  undefined auStack208 [4];
  undefined auStack204 [4];
  undefined auStack200 [4];
  undefined auStack196 [4];
  int local_c0;
  int local_bc;
  undefined auStack184 [4];
  undefined auStack180 [4];
  int local_b0;
  int local_ac;
  undefined4 local_a8;
  char local_a4 [68];
  double local_60;
  double local_58;
  double local_50;
  double local_48;
  
  uVar25 = FUN_802860bc();
  iVar7 = FUN_8002b9ec();
  sVar2 = DAT_803dd798;
  local_a8 = DAT_803e1e18;
  uVar19 = 0;
  if ((DAT_803dd798 != 0) && (DAT_803dd793 != '\0')) {
    iVar16 = 3;
    iVar15 = 1;
    iVar12 = 0;
    if (0 < DAT_803dd8b0) {
      if (8 < DAT_803dd8b0) {
        pcVar10 = local_a4;
        uVar20 = DAT_803dd8b0 - 1U >> 3;
        if (0 < DAT_803dd8b0 + -8) {
          do {
            *pcVar10 = '\0';
            pcVar10[1] = '\0';
            pcVar10[2] = '\0';
            pcVar10[3] = '\0';
            pcVar10[4] = '\0';
            pcVar10[5] = '\0';
            pcVar10[6] = '\0';
            pcVar10[7] = '\0';
            pcVar10 = pcVar10 + 8;
            iVar12 = iVar12 + 8;
            uVar20 = uVar20 - 1;
          } while (uVar20 != 0);
        }
      }
      pcVar10 = local_a4 + iVar12;
      iVar3 = DAT_803dd8b0 - iVar12;
      if (iVar12 < DAT_803dd8b0) {
        do {
          *pcVar10 = '\0';
          pcVar10 = pcVar10 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
    pcVar10 = local_a4 + DAT_803dd8b0;
    uVar20 = 3 - DAT_803dd8b0;
    if (DAT_803dd8b0 < 3) {
      uVar21 = uVar20 >> 3;
      if (uVar21 != 0) {
        do {
          *pcVar10 = '\x01';
          pcVar10[1] = '\x01';
          pcVar10[2] = '\x01';
          pcVar10[3] = '\x01';
          pcVar10[4] = '\x01';
          pcVar10[5] = '\x01';
          pcVar10[6] = '\x01';
          pcVar10[7] = '\x01';
          pcVar10 = pcVar10 + 8;
          uVar21 = uVar21 - 1;
        } while (uVar21 != 0);
        uVar20 = uVar20 & 7;
        if (uVar20 == 0) goto LAB_8012335c;
      }
      do {
        *pcVar10 = '\x01';
        pcVar10 = pcVar10 + 1;
        uVar20 = uVar20 - 1;
      } while (uVar20 != 0);
    }
LAB_8012335c:
    if (DAT_803dd8b0 < 3) {
      DAT_803dd8b0 = 3;
    }
    if (DAT_803dd796 < 1) {
      if ((DAT_803dd796 < 0) && (iVar16 = 4, DAT_803dd796 < -0x32)) {
        iVar15 = 0;
      }
    }
    else {
      iVar15 = 2;
      iVar16 = 4;
      if (0x32 < DAT_803dd796) {
        iVar15 = 3;
      }
    }
    iVar12 = DAT_803dd8b4 - iVar15;
    if (iVar12 < 0) {
      iVar12 = iVar12 + DAT_803dd8b0;
    }
    if (DAT_803dd8b0 <= iVar12) {
      iVar12 = iVar12 - DAT_803dd8b0;
    }
    iVar3 = (int)DAT_803dd798;
    DAT_803a93c4 = 0;
    pbVar18 = &DAT_803dd848;
    DAT_803dd848 = 0;
    DAT_803a93a8 = 0;
    DAT_803a93c8 = 0;
    uRam803dd849 = 0;
    DAT_803a93ac = 0;
    DAT_803a93cc = 0;
    uRam803dd84a = 0;
    DAT_803a93b0 = 0;
    DAT_803a93d0 = 0;
    uRam803dd84b = 0;
    DAT_803a93b4 = 0;
    DAT_803a93d4 = 0;
    uRam803dd84c = 0;
    DAT_803a93b8 = 0;
    DAT_803a93d8 = 0;
    uRam803dd84d = 0;
    DAT_803a93bc = 0;
    DAT_803a93dc = 0;
    uRam803dd84e = 0;
    DAT_803a93c0 = 0;
    for (iVar17 = 0; iVar17 < iVar16; iVar17 = iVar17 + 1) {
      if (local_a4[iVar12] == '\0') {
        FUN_8025d324(0,0,0x280,0x1e0);
        iVar11 = (iVar17 + 3) - iVar15;
        (&DAT_803a93c4)[iVar11] = (&DAT_803a91b8)[iVar12];
        (&DAT_803a93a8)[iVar11] = (uint)(byte)(&DAT_803a8c78)[iVar12];
        if (1 < (byte)(&DAT_803a8c38)[iVar12]) {
          (&DAT_803dd848)[iVar11] = (&DAT_803a8c38)[iVar12];
        }
      }
      iVar12 = iVar12 + 1;
      if (DAT_803dd8b0 <= iVar12) {
        iVar12 = iVar12 - DAT_803dd8b0;
      }
    }
    FUN_8025d324(0,0,0x280,0x1e0);
    FUN_80124998((int)((ulonglong)uVar25 >> 0x20),(int)uVar25,param_3);
    iVar12 = 0;
    iVar15 = 0;
    do {
      if (1 < *pbVar18) {
        sVar4 = DAT_803dd796 + (short)iVar15;
        sVar5 = sVar2;
        if (sVar4 < DAT_803dbacc) {
          sVar5 = sVar2 + (sVar4 - DAT_803dbacc) * 8;
        }
        if (DAT_803dbace < sVar4) {
          sVar5 = sVar5 + (sVar4 - DAT_803dbace) * -8;
        }
        if (sVar5 < 0) {
          sVar5 = 0;
        }
        if (0xff < sVar5) {
          sVar5 = 0xff;
        }
        iVar16 = (int)((int)sVar5 * (uint)DAT_803dd8d4) / 0xff +
                 ((int)((int)sVar5 * (uint)DAT_803dd8d4) >> 0x1f);
        uVar6 = (short)iVar16 - (short)(iVar16 >> 0x1f);
        FUN_8025d324(0,0,0x280,0x1e0);
        FUN_8028f688(&local_a8,&DAT_803dbb58,*pbVar18);
        FUN_80019908(0,0,0,uVar6 & 0xff);
        FUN_80015dc8(&local_a8,0x93,0x247,(int)DAT_803dd796 + iVar15 + 0x2b);
        FUN_80019908(0xff,0xff,0xff,uVar6 & 0xff);
        FUN_80015dc8(&local_a8,0x93,0x246,(int)DAT_803dd796 + iVar15 + 0x2a);
      }
      pbVar18 = pbVar18 + 1;
      iVar15 = iVar15 + 0x32;
      iVar12 = iVar12 + 1;
    } while (iVar12 < 7);
    iVar12 = (int)(iVar3 * (uint)DAT_803dd8d4) / 0xff + ((int)(iVar3 * (uint)DAT_803dd8d4) >> 0x1f);
    FUN_8007719c((double)FLOAT_803e1fcc,(double)FLOAT_803e1fd0,DAT_803a8a34,
                 iVar12 - (iVar12 >> 0x1f) & 0xff,0x100);
    iVar12 = (int)(iVar3 * (uint)DAT_803dd8d4) / 0xff + ((int)(iVar3 * (uint)DAT_803dd8d4) >> 0x1f);
    FUN_8007681c((double)FLOAT_803e1fd4,(double)FLOAT_803e1fd0,DAT_803a8a34,
                 iVar12 - (iVar12 >> 0x1f) & 0xff,0x100,0x12,10,1);
    iVar12 = (int)(iVar3 * (uint)DAT_803dd8d4) / 0xff + ((int)(iVar3 * (uint)DAT_803dd8d4) >> 0x1f);
    FUN_8007681c((double)FLOAT_803e1fcc,(double)FLOAT_803e1fd8,DAT_803a8a34,
                 iVar12 - (iVar12 >> 0x1f) & 0xff,0x100,0x12,10,2);
    iVar12 = (int)(iVar3 * (uint)DAT_803dd8d4) / 0xff + ((int)(iVar3 * (uint)DAT_803dd8d4) >> 0x1f);
    FUN_8007681c((double)FLOAT_803e1fd4,(double)FLOAT_803e1fd8,DAT_803a8a34,
                 iVar12 - (iVar12 >> 0x1f) & 0xff,0x100,0x12,10,3);
    if ((iVar7 != 0) && (iVar7 = FUN_80295bc8(iVar7), iVar7 != 0)) {
      if (DAT_803dd8b6 == '\x01') {
        uVar19 = 0x5a;
      }
      else if (DAT_803dd8b6 < '\x01') {
        if (-1 < DAT_803dd8b6) {
          uVar19 = 0x59;
        }
      }
      else if (DAT_803dd8b6 < '\x03') {
        uVar19 = 0x58;
      }
      iVar7 = (int)(iVar3 * (uint)DAT_803dd8d4) / 0xff + ((int)(iVar3 * (uint)DAT_803dd8d4) >> 0x1f)
      ;
      FUN_8007719c((double)FLOAT_803e1fdc,(double)FLOAT_803e1fb4,(&DAT_803a89b0)[uVar19],
                   iVar7 - (iVar7 >> 0x1f) & 0xff,0x100);
    }
  }
  if ((DAT_803dd870 != 0) && (DAT_803dd876 != DAT_803dd874)) {
    FUN_80054308();
    DAT_803dd876 = -1;
    DAT_803dd870 = 0;
  }
  if ((DAT_803dd870 == 0) && (0 < DAT_803dd874)) {
    DAT_803dd876 = DAT_803dd874;
    DAT_803dd870 = FUN_80054d54();
  }
  if (FLOAT_803dd83c == FLOAT_803e1e3c) goto LAB_80124038;
  local_60 = (double)(longlong)(int)FLOAT_803dd83c;
  FUN_8007719c((double)FLOAT_803e1fe0,(double)FLOAT_803e1f9c,DAT_803a89b0,(int)FLOAT_803dd83c,0x100)
  ;
  local_58 = (double)(longlong)(int)FLOAT_803dd83c;
  FUN_8007719c((double)FLOAT_803e1fe4,(double)FLOAT_803e1fe8,DAT_803a89b4,(int)FLOAT_803dd83c,0x100)
  ;
  local_50 = (double)(longlong)(int)FLOAT_803dd83c;
  FUN_8007719c((double)FLOAT_803e1fec,(double)FLOAT_803e1ff0,DAT_803a89b8,(int)FLOAT_803dd83c,0x100)
  ;
  if ((DAT_803dd7b1 & 8) == 0) {
    local_50 = (double)(longlong)(int)FLOAT_803dd83c;
    FUN_8007719c((double)FLOAT_803e1ff4,(double)FLOAT_803e1ff8,DAT_803a89d4,(int)FLOAT_803dd83c,
                 0x100);
  }
  if ((DAT_803dd7aa == 0) || (DAT_803dd7aa == 0x1c)) {
    local_48 = (double)(longlong)(int)FLOAT_803dd83c;
    FUN_8007719c((double)FLOAT_803e1fcc,(double)FLOAT_803e1ffc,DAT_803a89bc,(int)FLOAT_803dd83c,
                 0x100);
    DAT_803dd7ae = 0;
    DAT_803dd7b1 = 0;
  }
  else {
    if (DAT_803dd7aa != DAT_803dd7ae) {
      DAT_803dd7b1 = 0x3f;
    }
    if (DAT_803dd7b1 != 0) {
      DAT_803dd7b1 = DAT_803dd7b1 - 1;
    }
    if ((DAT_803dd7b1 & 8) == 0) {
      local_50 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_80019908(200,0xe6,0xff,(int)FLOAT_803dd83c);
    }
    else {
      local_50 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_80019908(0x32,0x32,0xff,(int)FLOAT_803dd83c);
    }
    uVar8 = FUN_80019b14();
    FUN_80019b1c(3,3);
    if ((short)DAT_803dd7aa < 0x3e9) {
      for (bVar13 = 0; bVar13 < 0x1d; bVar13 = bVar13 + 1) {
        if (DAT_803dd7aa == (byte)(&DAT_8031b6f0)[(uint)bVar13 * 2]) {
          uVar19 = (uint)bVar13;
        }
      }
      iVar7 = FUN_80019570(0x2ad);
    }
    else {
      iVar7 = FUN_80019570();
      uVar19 = 1;
    }
    if ((uVar19 == 0) || (iVar7 == 0)) {
LAB_80123b4c:
      local_48 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_8007719c((double)FLOAT_803e2000,(double)FLOAT_803e1ffc,DAT_803a89cc,(int)FLOAT_803dd83c,
                   0x100);
    }
    else {
      uVar20 = (uint)(byte)(&DAT_8031b6f1)[uVar19 * 2];
      if (*(ushort *)(iVar7 + 2) <= uVar20) goto LAB_80123b4c;
      uVar14 = *(undefined4 *)(*(int *)(iVar7 + 8) + uVar20 * 4);
      uVar9 = FUN_80019b14();
      FUN_80019b1c(3,3);
      FUN_800163c4(uVar14,8,0,0,auStack216,auStack212,auStack208,auStack204);
      FUN_80015dc8(uVar14,8,0,0);
      FUN_80019b1c(uVar9,3);
      FUN_800163c4(*(undefined4 *)
                    (*(int *)(iVar7 + 8) + (uint)(byte)(&DAT_8031b6f1)[uVar19 * 2] * 4),8,0,0,
                   &local_ac,&local_b0,auStack180,auStack184);
      iVar7 = (local_b0 - local_ac) + -0x19;
      if (iVar7 < 1) {
        iVar7 = 1;
      }
      local_50 = (double)CONCAT44(0x43300000,0x219U - iVar7 ^ 0x80000000);
      local_58 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_8007681c((double)(float)(local_50 - DOUBLE_803e1e78),(double)FLOAT_803e1ffc,DAT_803a89d0,
                   (int)FLOAT_803dd83c,0x100,iVar7,0x16,0);
      local_60 = (double)CONCAT44(0x43300000,0x20dU - iVar7 ^ 0x80000000);
      local_48 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_8007719c((double)(float)(local_60 - DOUBLE_803e1e78),(double)FLOAT_803e1ffc,DAT_803a89cc,
                   (int)FLOAT_803dd83c,0x100);
    }
    DAT_803dd7ae = DAT_803dd7aa;
    local_48 = (double)(longlong)(int)FLOAT_803dd83c;
    FUN_8007719c((double)FLOAT_803e1fcc,(double)FLOAT_803e1ffc,DAT_803a89c4,(int)FLOAT_803dd83c,
                 0x100);
    FUN_80019b1c(uVar8,3);
  }
  if (DAT_803dd7ac == '\0') {
    local_48 = (double)(longlong)(int)FLOAT_803dd83c;
    FUN_8007719c((double)FLOAT_803e1fcc,(double)FLOAT_803e200c,DAT_803a89c0,(int)FLOAT_803dd83c,
                 0x100);
    DAT_803dd7b0 = '\0';
  }
  else {
    if (DAT_803dd7ac != DAT_803dd7b0) {
      DAT_803dd7b2 = 0x3f;
    }
    if (DAT_803dd7b2 != 0) {
      DAT_803dd7b2 = DAT_803dd7b2 - 1;
    }
    if ((DAT_803dd7b2 & 8) == 0) {
      local_48 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_80019908(200,0xe6,0xff,(int)FLOAT_803dd83c);
    }
    else {
      local_48 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_80019908(0x32,0x32,0xff,(int)FLOAT_803dd83c);
    }
    uVar19 = 0;
    for (bVar13 = 0; bVar13 < 0x1d; bVar13 = bVar13 + 1) {
      if (DAT_803dd7ac == (&DAT_8031b6f0)[(uint)bVar13 * 2]) {
        uVar19 = (uint)bVar13;
      }
    }
    uVar8 = FUN_80019b14();
    FUN_80019b1c(3,3);
    iVar7 = FUN_80019570(0x2ad);
    if ((uVar19 == 0) || (iVar7 == 0)) {
LAB_80123e3c:
      local_48 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_8007719c((double)FLOAT_803e2008,(double)FLOAT_803e2004,DAT_803a89cc,(int)FLOAT_803dd83c,
                   0x100);
    }
    else {
      uVar20 = (uint)(byte)(&DAT_8031b6f1)[uVar19 * 2];
      if (*(ushort *)(iVar7 + 2) <= uVar20) goto LAB_80123e3c;
      uVar14 = *(undefined4 *)(*(int *)(iVar7 + 8) + uVar20 * 4);
      uVar9 = FUN_80019b14();
      FUN_80019b1c(3,3);
      FUN_800163c4(uVar14,9,0,0,auStack232,auStack228,auStack224,auStack220);
      FUN_80015dc8(uVar14,9,0,0);
      FUN_80019b1c(uVar9,3);
      FUN_800163c4(*(undefined4 *)
                    (*(int *)(iVar7 + 8) + (uint)(byte)(&DAT_8031b6f1)[uVar19 * 2] * 4),9,0,0,
                   &local_bc,&local_c0,auStack196,auStack200);
      iVar7 = (local_c0 - local_bc) + -7;
      if (iVar7 < 1) {
        iVar7 = 1;
      }
      local_48 = (double)CONCAT44(0x43300000,0x219U - iVar7 ^ 0x80000000);
      local_50 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_8007681c((double)(float)(local_48 - DOUBLE_803e1e78),(double)FLOAT_803e2004,DAT_803a89d0,
                   (int)FLOAT_803dd83c,0x100,iVar7,0x16,0);
      local_58 = (double)CONCAT44(0x43300000,0x20dU - iVar7 ^ 0x80000000);
      local_60 = (double)(longlong)(int)FLOAT_803dd83c;
      FUN_8007719c((double)(float)(local_58 - DOUBLE_803e1e78),(double)FLOAT_803e2004,DAT_803a89cc,
                   (int)FLOAT_803dd83c,0x100);
    }
    DAT_803dd7b0 = DAT_803dd7ac;
    local_48 = (double)(longlong)(int)FLOAT_803dd83c;
    FUN_8007719c((double)FLOAT_803e1fcc,(double)FLOAT_803e200c,DAT_803a89c8,(int)FLOAT_803dd83c,
                 0x100);
    FUN_80019b1c(uVar8,3);
  }
  if (DAT_803dd870 == 0) {
    local_48 = (double)(longlong)(int)FLOAT_803dd83c;
    FUN_80019908(0xff,0xff,0xff,(int)FLOAT_803dd83c);
    uVar8 = FUN_80019b14();
    FUN_80019b1c(3,3);
    FUN_80015dc8(&DAT_803dbb5c,0x93,0x216,0x22);
    FUN_80019b1c(uVar8,3);
  }
  else {
    fVar1 = FLOAT_803e1e68;
    if (DAT_803dd87c != '\0') {
      fVar1 = FLOAT_803e2010;
    }
    dVar24 = (double)fVar1;
    dVar23 = (double)FLOAT_803dd7e8;
    if (dVar23 <= dVar24) {
      dVar22 = DOUBLE_803e1ea8 + dVar23;
      if (dVar24 < DOUBLE_803e1ea8 + dVar23) {
        dVar22 = dVar24;
      }
    }
    else {
      dVar22 = dVar23 - DOUBLE_803e1ea8;
      if (dVar23 - DOUBLE_803e1ea8 < dVar24) {
        dVar22 = dVar24;
      }
    }
    FLOAT_803dd7e8 = (float)dVar22;
    FLOAT_803dd878 =
         FLOAT_803dd878 -
         (FLOAT_803dba74 + (FLOAT_803db414 * (FLOAT_803dd878 - FLOAT_803dba74)) / FLOAT_803dba84);
    fVar1 = FLOAT_803e1e68;
    if (FLOAT_803dd878 <= FLOAT_803e1e3c) {
      FLOAT_803dd878 = FLOAT_803e1e3c;
      fVar1 = FLOAT_803dd7e8;
    }
    FLOAT_803dd7e8 = fVar1;
    local_48 = (double)(longlong)(int)(FLOAT_803dd7e8 * FLOAT_803dd83c);
    iVar7 = (int)(FLOAT_803dba80 * FLOAT_803dd878 + FLOAT_803e2018);
    local_50 = (double)(longlong)iVar7;
    FUN_8007719c((double)(FLOAT_803dba78 * FLOAT_803dd878 + FLOAT_803e2014),
                 (double)(FLOAT_803dba7c * FLOAT_803dd878 + FLOAT_803e1f9c),DAT_803dd870,
                 (int)(FLOAT_803dd7e8 * FLOAT_803dd83c),iVar7);
  }
LAB_80124038:
  FUN_8005d118(0,0xff,0xff,0xff,0xff);
  FUN_80286108();
  return;
}

