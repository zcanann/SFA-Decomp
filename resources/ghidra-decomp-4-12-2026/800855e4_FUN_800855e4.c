// Function: FUN_800855e4
// Entry: 800855e4
// Size: 2012 bytes

void FUN_800855e4(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,undefined4 *param_11,undefined **param_12,undefined4 param_13,
                 undefined4 param_14,int *param_15,int param_16)

{
  float fVar1;
  char cVar2;
  ushort uVar3;
  short sVar4;
  float fVar5;
  bool bVar6;
  undefined uVar7;
  byte bVar10;
  int iVar8;
  uint uVar9;
  short *psVar11;
  short *psVar12;
  int *piVar13;
  int iVar14;
  uint uVar15;
  short sVar16;
  short sVar17;
  undefined **ppuVar18;
  int *piVar19;
  uint uVar20;
  char *pcVar21;
  int *piVar22;
  double extraout_f1;
  double dVar23;
  undefined8 uVar24;
  
  uVar24 = FUN_80286838();
  cVar2 = DAT_803ddd93;
  psVar11 = (short *)((ulonglong)uVar24 >> 0x20);
  piVar13 = (int *)uVar24;
  pcVar21 = (char *)*param_11;
  uVar20 = (uint)(char)(byte)param_12;
  bVar10 = (byte)param_12 & 2;
  if (((uint)param_12 & 1) == 0) {
    bVar10 = 1;
  }
  piVar22 = *(int **)(psVar11 + 0x5c);
  psVar12 = (short *)*piVar22;
  if ((short *)*piVar22 == (short *)0x0) {
    psVar12 = psVar11;
  }
  piVar19 = (int *)(int)*pcVar21;
  ppuVar18 = &switchD_80085670::switchdataD_8030fe1c;
  dVar23 = extraout_f1;
  switch(piVar19) {
  case (int *)0x1:
    if (((uint)param_12 & 8) == 0) {
      if ((*(char *)((int)piVar22 + 0x7b) == '\0') ||
         ((&DAT_8039afb8)[*(char *)((int)piVar22 + 0x57)] == '\0')) {
        *(char *)(piVar22 + 0x1e) = '\x01' - *(char *)(piVar22 + 0x1e);
      }
      else {
        *(undefined *)(piVar22 + 0x1e) = 0;
      }
    }
    break;
  case (int *)0x2:
    if (((uint)param_12 & 8) == 0) {
      *(ushort *)(piVar22 + 0x1b) = *(ushort *)(pcVar21 + 2) & 0xfff;
      if ((psVar12[0x22] == 1) && (*(short *)(piVar22 + 0x1b) < 4)) {
        *(short *)(piVar22 + 0x1b) = *(short *)(piVar22 + 0x1b) + 0x531;
      }
      *(byte *)(piVar22 + 0x23) = (byte)((ushort)*(undefined2 *)(pcVar21 + 2) >> 8) & 0xf0;
      if (piVar13 != (int *)0x0) {
        ppuVar18 = (undefined **)piVar13[0xb];
        if (psVar12[0x50] == *(short *)(piVar22 + 0x1b)) {
          if (*(char *)(ppuVar18 + 0x18) == '\0') {
            bVar6 = true;
          }
          else {
            bVar6 = false;
          }
        }
        else {
          bVar6 = true;
        }
        if ((((bVar10 != 0) && (bVar6)) && ((*(ushort *)((int)piVar22 + 0x6e) & 4) != 0)) &&
           (piVar13 != (int *)0x0)) {
          fVar1 = *(float *)(psVar12 + 0x4c);
          ppuVar18[1] = (undefined *)(float)((double)fVar1 * (double)(float)ppuVar18[5]);
          uVar9 = (uint)*(short *)((int)piVar22 + 0xd6);
          if (uVar9 != 0) {
            if ((piVar22[0x26] != 0) && (uVar9 != 0)) {
              FUN_80082e7c((double)fVar1,param_2,param_3,
                           (float *)(piVar22[0x26] + *(short *)(piVar22 + 0x2c) * 8),uVar9 & 0xfff,
                           *(short *)(piVar22 + 0x16) + -1);
            }
          }
          if (psVar12[0x22] == 1) {
            iVar8 = *(int *)(*(int *)(psVar12 + 0x3e) + *(char *)((int)psVar12 + 0xad) * 4);
            iVar14 = *(int *)(iVar8 + 0x2c);
            *(undefined2 *)(iVar14 + 100) = 0xffff;
            *(undefined2 *)(iVar14 + 0x5a) = 0;
            *(undefined2 *)(iVar14 + 0x5c) = 0;
            iVar8 = *(int *)(iVar8 + 0x30);
            if (iVar8 != 0) {
              *(undefined2 *)(iVar8 + 100) = 0xffff;
              *(undefined2 *)(iVar8 + 0x58) = 0;
              *(undefined2 *)(iVar8 + 0x5a) = 0;
              *(undefined2 *)(iVar8 + 0x5c) = 0;
            }
          }
          piVar22[8] = (int)FLOAT_803dfc48;
          dVar23 = (double)FUN_8003042c((double)((float)((double)CONCAT44(0x43300000,
                                                                          (uint)*(byte *)(piVar22 +
                                                                                         0x23)) -
                                                        DOUBLE_803dfc60) * FLOAT_803dfcac),param_2,
                                        param_3,param_4,param_5,param_6,param_7,param_8,psVar12,
                                        (int)*(short *)(piVar22 + 0x1b),0,ppuVar18,piVar19,uVar20,
                                        param_15,param_16);
        }
      }
    }
    break;
  case (int *)0x3:
    if ((((uint)param_12 & 8) == 0) && ((uVar20 & 4) == 0)) {
      psVar12 = FUN_80086050(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             psVar11,piVar22,*(int *)(psVar11 + 0x26),
                             (int *)&switchD_80085670::switchdataD_8030fe1c,piVar19,uVar20,param_15,
                             param_16);
      psVar12[0x51] = -1;
    }
    break;
  case (int *)0x4:
    if ((((((uint)param_12 & 8) == 0) && (bVar10 != 0)) && (piVar13 != (int *)0x0)) &&
       (*(char *)(*piVar13 + 0xf9) != '\0')) {
      fVar1 = (float)((double)CONCAT44(0x43300000,
                                       (uint)(int)*(short *)(pcVar21 + 2) >> 8 & 0xff ^ 0x80000000)
                     - DOUBLE_803dfc38);
      fVar5 = FLOAT_803dfc48;
      if (FLOAT_803dfc30 != fVar1) {
        fVar5 = FLOAT_803dfc48 / fVar1;
      }
      uVar9 = (int)*(short *)(pcVar21 + 2) & 0xff;
      if (uVar9 < 0xf) {
        ppuVar18 = (undefined **)(uVar9 - 1);
        piVar19 = (int *)0x0;
        dVar23 = (double)FUN_80027a90((double)fVar5,piVar13,2,(int)*(char *)(piVar13[10] + 0x2d),
                                      (int)ppuVar18,0);
      }
      else {
        ppuVar18 = (undefined **)(uVar9 - 1);
        piVar19 = (int *)0x0;
        dVar23 = (double)FUN_80027a90((double)fVar5,piVar13,0,(int)*(char *)(piVar13[10] + 0xd),
                                      (int)ppuVar18,0);
      }
    }
    break;
  case (int *)0x7:
    *(char *)((int)piVar22 + 0x7a) = '\x01' - *(char *)((int)piVar22 + 0x7a);
    break;
  case (int *)0xb:
    if (((bVar10 != 0) && (0 < *(short *)(pcVar21 + 2))) && (DAT_803ddd40 < 0x14)) {
      (&DAT_8039a0ac)[DAT_803ddd40 * 2] = pcVar21 + 4;
      (&DAT_8039a0b2)[DAT_803ddd40 * 4] = *(undefined2 *)(piVar22 + 0x16);
      iVar8 = DAT_803ddd40 * 4;
      DAT_803ddd40 = DAT_803ddd40 + 1;
      (&DAT_8039a0b0)[iVar8] = *(undefined2 *)(pcVar21 + 2);
    }
    *(short *)((int)piVar22 + 0x66) = *(short *)((int)piVar22 + 0x66) + *(short *)(pcVar21 + 2);
    break;
  case (int *)0xd:
    if (((((uint)param_12 & 1) == 0) && (((uint)(int)*(short *)(pcVar21 + 2) >> 0xc & 0xf) != 8)) &&
       (DAT_803ddd93 < 10)) {
      iVar8 = DAT_803ddd93 * 8;
      *(short **)(&DAT_8039b21c + iVar8) = psVar12;
      (&DAT_8039b222)[iVar8] = (byte)((uint)(int)*(short *)(pcVar21 + 2) >> 0xc) & 0xf;
      bVar10 = (&DAT_8039b222)[iVar8];
      if ((bVar10 == 0xb) || (bVar10 == 0xc)) {
        iVar8 = (int)DAT_803ddd93;
        DAT_803ddd93 = DAT_803ddd93 + '\x01';
        *(undefined2 *)(&DAT_8039b220 + iVar8 * 8) = *(undefined2 *)(pcVar21 + 6);
      }
      else {
        DAT_803ddd93 = cVar2 + '\x01';
        *(ushort *)(&DAT_8039b220 + iVar8) = *(ushort *)(pcVar21 + 2) & 0xfff;
      }
    }
    break;
  case (int *)0xe:
    if (((uint)param_12 & 8) == 0) {
      ppuVar18 = (undefined **)0x0;
      piVar19 = (int *)*DAT_803dd6e8;
      dVar23 = (double)(*(code *)piVar19[0xe])((int)*(short *)(pcVar21 + 2),0x14,0x8c);
    }
  }
  if (((uint)param_12 & 1) == 0) {
    if ((DAT_803ddd92 == '\0') && (DAT_803ddd91 == '\0')) {
      cVar2 = *pcVar21;
      if (cVar2 == '\r') {
        uVar9 = (uint)*(short *)(pcVar21 + 2);
        uVar7 = (undefined)*(short *)(pcVar21 + 2);
        switch(uVar9 >> 0xc & 0xf) {
        case 0:
          if ((((&DAT_8039aab0)[*(char *)((int)piVar22 + 0x57)] & 0x20) != 0) &&
             ((piVar13 = (int *)((uVar9 & 0xfff) + 1), piVar13 == (int *)0xd9 ||
              (piVar13 == (int *)0x92)))) {
            FUN_8000a538(piVar13,1);
          }
          break;
        case 2:
          FUN_80008cbc(dVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar12,
                       psVar12,uVar9 & 0xfff,0,piVar19,uVar20,param_15,param_16);
          break;
        case 6:
          if (((uint)param_12 & 8) == 0) {
            FUN_80055464(dVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         uVar9 & 0xfff,'\0',uVar9,ppuVar18,piVar19,uVar20,param_15,param_16);
          }
          break;
        case 7:
          break;
        case 8:
          if (((uint)param_12 & 8) == 0) {
            *(undefined *)((int)piVar22 + 0x8d) = uVar7;
            *(undefined *)((int)piVar22 + 0x8e) = *(undefined *)((int)piVar22 + 0x8d);
          }
          break;
        case 0xe:
          if (((uint)param_12 & 8) == 0) {
            *(undefined *)((int)piVar22 + 0x8d) = uVar7;
          }
          break;
        case 0xf:
          if (((uint)param_12 & 8) == 0) {
            *(undefined *)((int)piVar22 + 0x8e) = uVar7;
          }
        }
      }
      else if (cVar2 < '\r') {
        if (((cVar2 == '\x06') && (((uint)param_12 & 8) == 0)) &&
           ((((&DAT_8039aab0)[*(char *)((int)piVar22 + 0x57)] & 0x20) != 0 &&
            ((&DAT_8039b1c4)[*(char *)((int)piVar22 + 0x57)] != '\x03')))) {
          uVar3 = *(ushort *)(pcVar21 + 2);
          if (((uint)(int)(short)uVar3 >> 0xc & 0xf) == 0xf) {
            FUN_8000bb38((uint)psVar11,uVar3 & 0xfff);
            *(undefined2 *)((int)piVar22 + 0x36) = 0xffff;
            *(ushort *)((int)piVar22 + 0x3e) = *(ushort *)(pcVar21 + 2) & 0xfff;
          }
          else {
            FUN_8000bb38((uint)psVar11,uVar3 & 0xfff);
          }
        }
      }
      else if ((((cVar2 == '\x0f') && (((uint)param_12 & 8) == 0)) &&
               (((&DAT_8039aab0)[*(char *)((int)piVar22 + 0x57)] & 0x20) != 0)) &&
              ((&DAT_8039b1c4)[*(char *)((int)piVar22 + 0x57)] != '\x03')) {
        if (((uint)(int)*(short *)(pcVar21 + 2) >> 0xc & 0xf) == 0xf) {
          uVar20 = 3;
        }
        else {
          sVar16 = 0x7fff;
          if (*(short *)(piVar22 + 0xc) < 0x7fff) {
            sVar16 = *(short *)(piVar22 + 0xc);
          }
          sVar4 = *(short *)((int)piVar22 + 0x32);
          sVar17 = sVar16;
          if (sVar4 < sVar16) {
            sVar17 = sVar4;
          }
          uVar20 = (uint)(sVar4 < sVar16);
          if (*(short *)(piVar22 + 0xd) < sVar17) {
            uVar20 = 2;
          }
        }
        iVar8 = uVar20 * 2;
        if (0 < *(short *)((int)piVar22 + iVar8 + 0x30)) {
          FUN_8000dbb0();
        }
        pcVar21[1] = pcVar21[5];
        pcVar21[4] = 'c';
        *(undefined2 *)((int)piVar22 + iVar8 + 0x30) = *(undefined2 *)(pcVar21 + 6);
        *(ushort *)((int)piVar22 + iVar8 + 0x38) = *(ushort *)(pcVar21 + 2) & 0xfff;
        FUN_8000dcdc((uint)psVar11,*(ushort *)((int)piVar22 + iVar8 + 0x38));
      }
    }
    else if (*pcVar21 == '\r') {
      uVar15 = (uint)*(short *)(pcVar21 + 2);
      uVar9 = uVar15 >> 0xc & 0xf;
      if (uVar9 != 5) {
        if (uVar9 < 5) {
          if (uVar9 == 2) {
            FUN_80008cbc(dVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar12,
                         psVar12,uVar15 & 0xfff,0,piVar19,uVar20,param_15,param_16);
          }
        }
        else if (uVar9 < 7) {
          FUN_80055464(dVar23,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar15 & 0xfff
                       ,'\0',uVar15,ppuVar18,piVar19,uVar20,param_15,param_16);
        }
      }
    }
  }
  FUN_80286884();
  return;
}

