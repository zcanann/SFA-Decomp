// Function: FUN_801234e8
// Entry: 801234e8
// Size: 3684 bytes

void FUN_801234e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  short sVar2;
  int iVar3;
  short sVar4;
  int iVar5;
  ushort *puVar6;
  int extraout_r4;
  int extraout_r4_00;
  int extraout_r4_01;
  char *pcVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  byte bVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  byte *pbVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  double dVar19;
  undefined8 extraout_f1;
  undefined8 uVar20;
  double dVar21;
  double dVar22;
  undefined8 uVar23;
  int iStack_d8;
  int iStack_d4;
  int iStack_d0;
  int iStack_cc;
  int iStack_c8;
  int iStack_c4;
  int iStack_c0;
  int iStack_bc;
  int iStack_b8;
  int iStack_b4;
  int local_b0;
  int local_ac;
  undefined4 local_a8;
  char local_a4 [68];
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  
  uVar23 = FUN_80286820();
  iVar9 = (int)uVar23;
  uVar10 = param_11;
  uVar20 = extraout_f1;
  iVar5 = FUN_8002bac4();
  sVar2 = DAT_803de418;
  local_a8 = DAT_803e2a98;
  uVar16 = 0;
  if ((DAT_803de418 != 0) && (DAT_803de413 != '\0')) {
    iVar13 = 3;
    iVar12 = 1;
    iVar9 = 0;
    if (0 < DAT_803de530) {
      if (8 < DAT_803de530) {
        pcVar7 = local_a4;
        uVar17 = DAT_803de530 - 1U >> 3;
        if (0 < DAT_803de530 + -8) {
          do {
            *pcVar7 = '\0';
            pcVar7[1] = '\0';
            pcVar7[2] = '\0';
            pcVar7[3] = '\0';
            pcVar7[4] = '\0';
            pcVar7[5] = '\0';
            pcVar7[6] = '\0';
            pcVar7[7] = '\0';
            pcVar7 = pcVar7 + 8;
            iVar9 = iVar9 + 8;
            uVar17 = uVar17 - 1;
          } while (uVar17 != 0);
        }
      }
      pcVar7 = local_a4 + iVar9;
      iVar3 = DAT_803de530 - iVar9;
      if (iVar9 < DAT_803de530) {
        do {
          *pcVar7 = '\0';
          pcVar7 = pcVar7 + 1;
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
    pcVar7 = local_a4 + DAT_803de530;
    uVar17 = 3 - DAT_803de530;
    if (DAT_803de530 < 3) {
      uVar18 = uVar17 >> 3;
      if (uVar18 != 0) {
        do {
          builtin_strncpy(pcVar7,"\x01\x01\x01\x01\x01\x01\x01\x01",8);
          pcVar7 = pcVar7 + 8;
          uVar18 = uVar18 - 1;
        } while (uVar18 != 0);
        uVar17 = uVar17 & 7;
        if (uVar17 == 0) goto LAB_80123640;
      }
      do {
        *pcVar7 = '\x01';
        pcVar7 = pcVar7 + 1;
        uVar17 = uVar17 - 1;
      } while (uVar17 != 0);
    }
LAB_80123640:
    if (DAT_803de530 < 3) {
      DAT_803de530 = 3;
    }
    if (DAT_803de416 < 1) {
      if ((DAT_803de416 < 0) && (iVar13 = 4, DAT_803de416 < -0x32)) {
        iVar12 = 0;
      }
    }
    else {
      iVar12 = 2;
      iVar13 = 4;
      if (0x32 < DAT_803de416) {
        iVar12 = 3;
      }
    }
    iVar9 = DAT_803de534 - iVar12;
    if (iVar9 < 0) {
      iVar9 = iVar9 + DAT_803de530;
    }
    if (DAT_803de530 <= iVar9) {
      iVar9 = iVar9 - DAT_803de530;
    }
    iVar3 = (int)DAT_803de418;
    DAT_803aa024 = 0;
    pbVar15 = &DAT_803de4c8;
    DAT_803de4c8 = 0;
    DAT_803aa008 = 0;
    DAT_803aa028 = 0;
    uRam803de4c9 = 0;
    DAT_803aa00c = 0;
    DAT_803aa02c = 0;
    uRam803de4ca = 0;
    DAT_803aa010 = 0;
    DAT_803aa030 = 0;
    uRam803de4cb = 0;
    DAT_803aa014 = 0;
    DAT_803aa034 = 0;
    uRam803de4cc = 0;
    DAT_803aa018 = 0;
    DAT_803aa038 = 0;
    uRam803de4cd = 0;
    DAT_803aa01c = 0;
    DAT_803aa03c = 0;
    uRam803de4ce = 0;
    DAT_803aa020 = 0;
    for (iVar14 = 0; iVar14 < iVar13; iVar14 = iVar14 + 1) {
      if (local_a4[iVar9] == '\0') {
        FUN_8025da88(0,0,0x280,0x1e0);
        iVar8 = (iVar14 + 3) - iVar12;
        (&DAT_803aa024)[iVar8] = (&DAT_803a9e18)[iVar9];
        (&DAT_803aa008)[iVar8] = (uint)(byte)(&DAT_803a98d8)[iVar9];
        if (1 < (byte)(&DAT_803a9898)[iVar9]) {
          (&DAT_803de4c8)[iVar8] = (&DAT_803a9898)[iVar9];
        }
      }
      iVar9 = iVar9 + 1;
      if (DAT_803de530 <= iVar9) {
        iVar9 = iVar9 - DAT_803de530;
      }
    }
    FUN_8025da88(0,0,0x280,0x1e0);
    FUN_80124c7c((int)((ulonglong)uVar23 >> 0x20),(int)uVar23,param_11);
    iVar9 = 0;
    iVar12 = 0;
    do {
      if (1 < *pbVar15) {
        iVar13 = (int)(short)(DAT_803de416 + (short)iVar12);
        sVar4 = sVar2;
        if (iVar13 < DAT_803dc734) {
          sVar4 = sVar2 + (short)(iVar13 - DAT_803dc734) * 8;
        }
        if (DAT_803dc736 < iVar13) {
          sVar4 = sVar4 + (short)(iVar13 - DAT_803dc736) * -8;
        }
        if (sVar4 < 0) {
          sVar4 = 0;
        }
        if (0xff < sVar4) {
          sVar4 = 0xff;
        }
        iVar13 = (int)((int)sVar4 * (uint)DAT_803de554) / 0xff +
                 ((int)((int)sVar4 * (uint)DAT_803de554) >> 0x1f);
        bVar11 = (char)iVar13 - (char)(iVar13 >> 0x1f);
        uVar10 = 0x1e0;
        uVar20 = FUN_8025da88(0,0,0x280,0x1e0);
        FUN_8028fde8(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)&local_a8,
                     &DAT_803dc7c0,(uint)*pbVar15,uVar10,param_13,param_14,param_15,param_16);
        FUN_80019940(0,0,0,bVar11);
        FUN_80015e00(&local_a8,0x93,0x247,(int)DAT_803de416 + iVar12 + 0x2b);
        FUN_80019940(0xff,0xff,0xff,bVar11);
        FUN_80015e00(&local_a8,0x93,0x246,(int)DAT_803de416 + iVar12 + 0x2a);
      }
      pbVar15 = pbVar15 + 1;
      iVar12 = iVar12 + 0x32;
      iVar9 = iVar9 + 1;
    } while (iVar9 < 7);
    iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f);
    FUN_80077318((double)FLOAT_803e2c4c,(double)FLOAT_803e2c50,DAT_803a9694,
                 iVar9 - (iVar9 >> 0x1f) & 0xff,0x100);
    iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f);
    FUN_80076998((double)FLOAT_803e2c54,(double)FLOAT_803e2c50,DAT_803a9694,
                 iVar9 - (iVar9 >> 0x1f) & 0xff,0x100,0x12,10,1);
    iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f);
    FUN_80076998((double)FLOAT_803e2c4c,(double)FLOAT_803e2c58,DAT_803a9694,
                 iVar9 - (iVar9 >> 0x1f) & 0xff,0x100,0x12,10,2);
    param_2 = (double)FLOAT_803e2c58;
    iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f);
    uVar10 = 0x100;
    param_12 = 0x12;
    param_13 = 10;
    param_14 = 3;
    uVar20 = FUN_80076998((double)FLOAT_803e2c54,param_2,DAT_803a9694,iVar9 - (iVar9 >> 0x1f) & 0xff
                          ,0x100,0x12,10,3);
    iVar9 = extraout_r4;
    if ((iVar5 != 0) && (uVar17 = FUN_80296328(iVar5), uVar17 != 0)) {
      if (DAT_803de536 == '\x01') {
        uVar16 = 0x5a;
      }
      else if (DAT_803de536 < '\x01') {
        if (-1 < DAT_803de536) {
          uVar16 = 0x59;
        }
      }
      else if (DAT_803de536 < '\x03') {
        uVar16 = 0x58;
      }
      param_2 = (double)FLOAT_803e2c34;
      iVar9 = (int)(iVar3 * (uint)DAT_803de554) / 0xff + ((int)(iVar3 * (uint)DAT_803de554) >> 0x1f)
      ;
      uVar10 = 0x100;
      uVar20 = FUN_80077318((double)FLOAT_803e2c5c,param_2,(&DAT_803a9610)[uVar16],
                            iVar9 - (iVar9 >> 0x1f) & 0xff,0x100);
      iVar9 = extraout_r4_00;
    }
  }
  if ((DAT_803de4f0 != 0) && (iVar9 = (int)DAT_803de4f6, iVar9 != DAT_803de4f4)) {
    uVar20 = FUN_80054484();
    DAT_803de4f6 = -1;
    DAT_803de4f0 = 0;
    iVar9 = extraout_r4_01;
  }
  if ((DAT_803de4f0 == 0) && (0 < DAT_803de4f4)) {
    DAT_803de4f6 = DAT_803de4f4;
    DAT_803de4f0 = FUN_80054ed0(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                (int)DAT_803de4f4,iVar9,uVar10,param_12,param_13,param_14,param_15,
                                param_16);
  }
  dVar22 = (double)FLOAT_803de4bc;
  if (dVar22 == (double)FLOAT_803e2abc) goto LAB_8012431c;
  local_60 = (double)(longlong)(int)FLOAT_803de4bc;
  FUN_80077318((double)FLOAT_803e2c60,(double)FLOAT_803e2c1c,DAT_803a9610,(int)FLOAT_803de4bc,0x100)
  ;
  local_58 = (double)(longlong)(int)FLOAT_803de4bc;
  FUN_80077318((double)FLOAT_803e2c64,(double)FLOAT_803e2c68,DAT_803a9614,(int)FLOAT_803de4bc,0x100)
  ;
  dVar21 = (double)FLOAT_803e2c70;
  local_50 = (double)(longlong)(int)FLOAT_803de4bc;
  FUN_80077318((double)FLOAT_803e2c6c,dVar21,DAT_803a9618,(int)FLOAT_803de4bc,0x100);
  if ((DAT_803de431 & 8) == 0) {
    dVar21 = (double)FLOAT_803e2c78;
    local_50 = (double)(longlong)(int)FLOAT_803de4bc;
    FUN_80077318((double)FLOAT_803e2c74,dVar21,DAT_803a9634,(int)FLOAT_803de4bc,0x100);
  }
  if ((DAT_803de42a == 0) || (DAT_803de42a == 0x1c)) {
    dVar21 = (double)FLOAT_803e2c7c;
    local_48 = (double)(longlong)(int)FLOAT_803de4bc;
    FUN_80077318((double)FLOAT_803e2c4c,dVar21,DAT_803a961c,(int)FLOAT_803de4bc,0x100);
    DAT_803de42e = 0;
    DAT_803de431 = 0;
  }
  else {
    if (DAT_803de42a != DAT_803de42e) {
      DAT_803de431 = 0x3f;
    }
    if (DAT_803de431 != 0) {
      DAT_803de431 = DAT_803de431 - 1;
    }
    if ((DAT_803de431 & 8) == 0) {
      local_50 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80019940(200,0xe6,0xff,(byte)(int)FLOAT_803de4bc);
    }
    else {
      local_50 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80019940(0x32,0x32,0xff,(byte)(int)FLOAT_803de4bc);
    }
    iVar9 = FUN_80019b4c();
    uVar20 = FUN_80019b54(3,3);
    uVar17 = (uint)DAT_803de42a;
    if ((int)uVar17 < 0x3e9) {
      for (bVar11 = 0; bVar11 < 0x1d; bVar11 = bVar11 + 1) {
        if (uVar17 == (byte)(&DAT_8031c340)[(uint)bVar11 * 2]) {
          uVar16 = (uint)bVar11;
        }
      }
      puVar6 = FUN_800195a8(uVar20,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,0x2ad);
    }
    else {
      puVar6 = FUN_800195a8(uVar20,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,uVar17);
      uVar16 = 1;
    }
    if ((uVar16 == 0) || (puVar6 == (ushort *)0x0)) {
LAB_80123e30:
      local_48 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80077318((double)FLOAT_803e2c80,(double)FLOAT_803e2c7c,DAT_803a962c,(int)FLOAT_803de4bc,
                   0x100);
    }
    else {
      uVar17 = (uint)(byte)(&DAT_8031c341)[uVar16 * 2];
      if (puVar6[1] <= uVar17) goto LAB_80123e30;
      uVar10 = *(undefined4 *)(*(int *)(puVar6 + 4) + uVar17 * 4);
      iVar5 = FUN_80019b4c();
      FUN_80019b54(3,3);
      FUN_800163fc(uVar10,8,0,0,&iStack_c8,&iStack_c4,&iStack_c0,&iStack_bc);
      FUN_80015e00(uVar10,8,0,0);
      FUN_80019b54(iVar5,3);
      FUN_800163fc(*(undefined4 *)
                    (*(int *)(puVar6 + 4) + (uint)(byte)(&DAT_8031c341)[uVar16 * 2] * 4),8,0,0,
                   &local_ac,&local_b0,&iStack_b4,&iStack_b8);
      iVar5 = (local_b0 - local_ac) + -0x19;
      if (iVar5 < 1) {
        iVar5 = 1;
      }
      local_50 = (double)CONCAT44(0x43300000,0x219U - iVar5 ^ 0x80000000);
      local_58 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80076998((double)(float)(local_50 - DOUBLE_803e2af8),(double)FLOAT_803e2c7c,DAT_803a9630,
                   (int)FLOAT_803de4bc,0x100,iVar5,0x16,0);
      local_60 = (double)CONCAT44(0x43300000,0x20dU - iVar5 ^ 0x80000000);
      local_48 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80077318((double)(float)(local_60 - DOUBLE_803e2af8),(double)FLOAT_803e2c7c,DAT_803a962c,
                   (int)FLOAT_803de4bc,0x100);
    }
    DAT_803de42e = DAT_803de42a;
    dVar21 = (double)FLOAT_803e2c7c;
    local_48 = (double)(longlong)(int)FLOAT_803de4bc;
    FUN_80077318((double)FLOAT_803e2c4c,dVar21,DAT_803a9624,(int)FLOAT_803de4bc,0x100);
    FUN_80019b54(iVar9,3);
  }
  if (DAT_803de42c == '\0') {
    local_48 = (double)(longlong)(int)FLOAT_803de4bc;
    FUN_80077318((double)FLOAT_803e2c4c,(double)FLOAT_803e2c8c,DAT_803a9620,(int)FLOAT_803de4bc,
                 0x100);
    DAT_803de430 = '\0';
  }
  else {
    if (DAT_803de42c != DAT_803de430) {
      DAT_803de432 = 0x3f;
    }
    if (DAT_803de432 != 0) {
      DAT_803de432 = DAT_803de432 - 1;
    }
    if ((DAT_803de432 & 8) == 0) {
      local_48 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80019940(200,0xe6,0xff,(byte)(int)FLOAT_803de4bc);
    }
    else {
      local_48 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80019940(0x32,0x32,0xff,(byte)(int)FLOAT_803de4bc);
    }
    uVar16 = 0;
    for (bVar11 = 0; bVar11 < 0x1d; bVar11 = bVar11 + 1) {
      if (DAT_803de42c == (&DAT_8031c340)[(uint)bVar11 * 2]) {
        uVar16 = (uint)bVar11;
      }
    }
    iVar9 = FUN_80019b4c();
    uVar20 = FUN_80019b54(3,3);
    puVar6 = FUN_800195a8(uVar20,dVar21,dVar22,param_4,param_5,param_6,param_7,param_8,0x2ad);
    if ((uVar16 == 0) || (puVar6 == (ushort *)0x0)) {
LAB_80124120:
      local_48 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80077318((double)FLOAT_803e2c88,(double)FLOAT_803e2c84,DAT_803a962c,(int)FLOAT_803de4bc,
                   0x100);
    }
    else {
      uVar17 = (uint)(byte)(&DAT_8031c341)[uVar16 * 2];
      if (puVar6[1] <= uVar17) goto LAB_80124120;
      uVar10 = *(undefined4 *)(*(int *)(puVar6 + 4) + uVar17 * 4);
      iVar5 = FUN_80019b4c();
      FUN_80019b54(3,3);
      FUN_800163fc(uVar10,9,0,0,&iStack_d8,&iStack_d4,&iStack_d0,&iStack_cc);
      FUN_80015e00(uVar10,9,0,0);
      FUN_80019b54(iVar5,3);
      FUN_800163fc(*(undefined4 *)
                    (*(int *)(puVar6 + 4) + (uint)(byte)(&DAT_8031c341)[uVar16 * 2] * 4),9,0,0,
                   &local_ac,&local_b0,&iStack_b4,&iStack_b8);
      iVar5 = (local_b0 - local_ac) + -7;
      if (iVar5 < 1) {
        iVar5 = 1;
      }
      local_48 = (double)CONCAT44(0x43300000,0x219U - iVar5 ^ 0x80000000);
      local_50 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80076998((double)(float)(local_48 - DOUBLE_803e2af8),(double)FLOAT_803e2c84,DAT_803a9630,
                   (int)FLOAT_803de4bc,0x100,iVar5,0x16,0);
      local_58 = (double)CONCAT44(0x43300000,0x20dU - iVar5 ^ 0x80000000);
      local_60 = (double)(longlong)(int)FLOAT_803de4bc;
      FUN_80077318((double)(float)(local_58 - DOUBLE_803e2af8),(double)FLOAT_803e2c84,DAT_803a962c,
                   (int)FLOAT_803de4bc,0x100);
    }
    DAT_803de430 = DAT_803de42c;
    local_48 = (double)(longlong)(int)FLOAT_803de4bc;
    FUN_80077318((double)FLOAT_803e2c4c,(double)FLOAT_803e2c8c,DAT_803a9628,(int)FLOAT_803de4bc,
                 0x100);
    FUN_80019b54(iVar9,3);
  }
  if (DAT_803de4f0 == 0) {
    local_48 = (double)(longlong)(int)FLOAT_803de4bc;
    FUN_80019940(0xff,0xff,0xff,(byte)(int)FLOAT_803de4bc);
    iVar9 = FUN_80019b4c();
    FUN_80019b54(3,3);
    FUN_80015e00(&DAT_803dc7c4,0x93,0x216,0x22);
    FUN_80019b54(iVar9,3);
  }
  else {
    fVar1 = FLOAT_803e2ae8;
    if (DAT_803de4fc != '\0') {
      fVar1 = FLOAT_803e2c90;
    }
    dVar21 = (double)fVar1;
    dVar22 = (double)FLOAT_803de468;
    if (dVar22 <= dVar21) {
      dVar19 = DOUBLE_803e2b28 + dVar22;
      if (dVar21 < DOUBLE_803e2b28 + dVar22) {
        dVar19 = dVar21;
      }
    }
    else {
      dVar19 = dVar22 - DOUBLE_803e2b28;
      if (dVar22 - DOUBLE_803e2b28 < dVar21) {
        dVar19 = dVar21;
      }
    }
    FLOAT_803de468 = (float)dVar19;
    FLOAT_803de4f8 =
         FLOAT_803de4f8 -
         (FLOAT_803dc6dc + (FLOAT_803dc074 * (FLOAT_803de4f8 - FLOAT_803dc6dc)) / FLOAT_803dc6ec);
    fVar1 = FLOAT_803e2ae8;
    if (FLOAT_803de4f8 <= FLOAT_803e2abc) {
      FLOAT_803de4f8 = FLOAT_803e2abc;
      fVar1 = FLOAT_803de468;
    }
    FLOAT_803de468 = fVar1;
    local_48 = (double)(longlong)(int)(FLOAT_803de468 * FLOAT_803de4bc);
    uVar16 = (uint)(FLOAT_803dc6e8 * FLOAT_803de4f8 + FLOAT_803e2c98);
    local_50 = (double)(longlong)(int)uVar16;
    FUN_80077318((double)(FLOAT_803dc6e0 * FLOAT_803de4f8 + FLOAT_803e2c94),
                 (double)(FLOAT_803dc6e4 * FLOAT_803de4f8 + FLOAT_803e2c1c),DAT_803de4f0,
                 (int)(FLOAT_803de468 * FLOAT_803de4bc),uVar16);
  }
LAB_8012431c:
  FUN_8005d294(0,0xff,0xff,0xff,0xff);
  FUN_8028686c();
  return;
}

