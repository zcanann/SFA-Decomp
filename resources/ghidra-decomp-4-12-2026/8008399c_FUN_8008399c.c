// Function: FUN_8008399c
// Entry: 8008399c
// Size: 1248 bytes

void FUN_8008399c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint *param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,uint param_16)

{
  byte bVar1;
  char cVar2;
  bool bVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  short sVar11;
  undefined4 uVar12;
  uint uVar13;
  char cVar14;
  int iVar15;
  uint unaff_r26;
  short sVar16;
  undefined uVar17;
  uint uVar18;
  uint uVar19;
  int iVar20;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar21;
  
  uVar21 = FUN_8028681c();
  uVar6 = (uint)((ulonglong)uVar21 >> 0x20);
  uVar9 = (uint)uVar21;
  iVar15 = 0;
  sVar11 = (short)param_14;
  uVar10 = param_13;
  uVar12 = param_15;
  uVar13 = param_16;
  uVar21 = extraout_f1;
  do {
    if (sVar11 <= iVar15) {
LAB_80083e64:
      FUN_80286868();
      return;
    }
    uVar5 = *param_12;
    uVar4 = uVar5 & 0x3f;
    uVar18 = uVar5 >> 6 & 0x3ff;
    uVar5 = uVar5 >> 0x10;
    if ((uVar4 == 2) || (uVar19 = uVar18, uVar4 == 3)) {
      if ((uVar5 & 0x8000) != 0) {
        uVar5 = uVar5 | 0xffff0000;
      }
      uVar19 = 0;
      unaff_r26 = uVar18;
    }
    iVar7 = 0;
    cVar14 = (char)param_16;
    if (uVar4 == 8) {
      if (cVar14 == '\0') {
        bVar3 = false;
        iVar7 = -1;
        iVar8 = 0;
        iVar20 = 2;
        do {
          uVar18 = (uint)*(byte *)(param_11 + iVar8 + 300);
          if (uVar18 == uVar19) {
            bVar3 = true;
          }
          if (uVar18 == 0) {
            iVar7 = iVar8;
          }
          uVar18 = (uint)*(byte *)(param_11 + iVar8 + 0x12d);
          if (uVar18 == uVar19) {
            bVar3 = true;
          }
          if (uVar18 == 0) {
            iVar7 = iVar8 + 1;
          }
          uVar18 = (uint)*(byte *)(param_11 + iVar8 + 0x12e);
          if (uVar18 == uVar19) {
            bVar3 = true;
          }
          if (uVar18 == 0) {
            iVar7 = iVar8 + 2;
          }
          uVar18 = (uint)*(byte *)(param_11 + iVar8 + 0x12f);
          if (uVar18 == uVar19) {
            bVar3 = true;
          }
          if (uVar18 == 0) {
            iVar7 = iVar8 + 3;
          }
          uVar18 = (uint)*(byte *)(param_11 + iVar8 + 0x130);
          if (uVar18 == uVar19) {
            bVar3 = true;
          }
          if (uVar18 == 0) {
            iVar7 = iVar8 + 4;
          }
          iVar8 = iVar8 + 5;
          iVar20 = iVar20 + -1;
        } while (iVar20 != 0);
        if ((!bVar3) && (iVar7 != -1)) {
          *(char *)(param_11 + iVar7 + 300) = (char)uVar19;
          iVar8 = FUN_80084ee4(param_11,uVar5);
          *(short *)(param_11 + iVar7 * 2 + 0x118) = (short)iVar8;
        }
        iVar7 = 0;
      }
    }
    else if (uVar4 < 8) {
      if (uVar4 == 6) {
        uVar10 = param_16;
        iVar7 = FUN_80083108(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar6,
                             uVar9,param_11,uVar19 | uVar5 << 8,param_16,param_14,uVar12,uVar13);
        if (iVar7 == 0) goto LAB_80083e64;
        iVar7 = -1;
        uVar19 = 0;
        uVar21 = extraout_f1_00;
      }
      else {
        if (uVar4 < 6) goto LAB_80083c3c;
        if (uVar9 != uVar6) {
          cVar2 = (&DAT_8030f9dc)[uVar19];
          if (cVar2 == '\x02') {
            uVar10 = uVar6;
            uVar21 = FUN_80037694((double)FLOAT_803dfc98,param_2,param_3,param_4,param_5,param_6,
                                  param_7,param_8,0,2,uVar6,(&DAT_8030f980)[uVar19],uVar6,param_14,
                                  uVar12,uVar13);
          }
          else if ((cVar2 < '\x02') && ('\0' < cVar2)) {
            uVar10 = uVar6;
            uVar21 = FUN_800377d0(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,2
                                  ,uVar6,(&DAT_8030f980)[uVar19],uVar6,param_14,uVar12,uVar13);
          }
          else {
            FUN_800379bc(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar9,
                         (&DAT_8030f980)[uVar19],uVar6,0,uVar10,param_14,uVar12,uVar13);
          }
        }
        iVar7 = -1;
        uVar19 = 0;
      }
    }
    else if (9 < uVar4) {
LAB_80083c3c:
      iVar7 = FUN_80083e7c(uVar19,param_11);
    }
    if ((0 < iVar7) && ((char)param_15 == '\0')) {
      sVar16 = (short)uVar5;
      switch(uVar4) {
      case 1:
        if (cVar14 == '\0') {
          if ((&DAT_8039b26c)[*(char *)(param_11 + 0x57)] == '\0') {
            (&DAT_8039b26c)[*(char *)(param_11 + 0x57)] = 1;
            *(short *)(param_11 + 0x58) = sVar16;
            *(undefined2 *)(param_11 + 0x5a) = *(undefined2 *)(param_11 + 0x58);
          }
          goto LAB_80083e64;
        }
        break;
      case 2:
        uVar17 = (undefined)uVar5;
        switch(unaff_r26) {
        case 0:
          *(undefined *)(param_11 + 0x80) = uVar17;
          bVar1 = *(byte *)(param_11 + 0x8b);
          if (bVar1 < 10) {
            *(byte *)(param_11 + 0x8b) = bVar1 + 1;
            *(undefined *)(param_11 + bVar1 + 0x81) = uVar17;
          }
          break;
        case 1:
          *(short *)(param_11 + 0x60) = sVar16;
          break;
        case 3:
          DAT_803ddcec = sVar16;
          break;
        case 4:
          DAT_803ddcee = sVar16;
          break;
        case 5:
          (&DAT_8039b0bc)[*(char *)(param_11 + 0x57)] = uVar17;
          break;
        case 6:
          uVar21 = FUN_800201ac((int)*(short *)(param_11 + 0x6a),(-uVar5 | uVar5) >> 0x1f);
        }
        break;
      case 3:
        if ((((cVar14 == '\0') && (unaff_r26 != 1)) && ((int)unaff_r26 < 1)) &&
           (-1 < (int)unaff_r26)) {
          *(short *)(param_11 + 0x60) = *(short *)(param_11 + 0x60) + sVar16;
        }
        break;
      case 4:
        if (cVar14 == '\0') {
          *(short *)(param_11 + 0x58) = (short)param_13;
          *(short *)(param_11 + 0x5a) = (short)param_13;
          *(char *)(param_11 + 0x7c) = (char)uVar19 + '\x01';
          (&DAT_8039b26c)[*(char *)(param_11 + 0x57)] = 1;
          goto LAB_80083e64;
        }
        break;
      case 5:
        if (cVar14 == '\0') goto LAB_80083e64;
        break;
      case 10:
        if (cVar14 == '\0') {
          if ((&DAT_8039b26c)[*(char *)(param_11 + 0x57)] == '\0') {
            (&DAT_8039b26c)[*(char *)(param_11 + 0x57)] = 1;
            iVar15 = FUN_80084ee4(param_11,uVar5);
            *(short *)(param_11 + 0x58) = (short)iVar15;
            *(undefined2 *)(param_11 + 0x5a) = *(undefined2 *)(param_11 + 0x58);
          }
          goto LAB_80083e64;
        }
      }
    }
    param_12 = param_12 + 1;
    iVar15 = iVar15 + 1;
  } while( true );
}

