// Function: FUN_80083710
// Entry: 80083710
// Size: 1248 bytes

void FUN_80083710(undefined4 param_1,undefined4 param_2,int param_3,uint *param_4,undefined2 param_5
                 ,short param_6,char param_7,undefined4 param_8)

{
  byte bVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined2 uVar9;
  undefined4 uVar8;
  int iVar10;
  bool bVar11;
  char cVar12;
  int iVar13;
  uint unaff_r26;
  short sVar14;
  undefined uVar15;
  uint uVar16;
  uint uVar17;
  int iVar18;
  undefined8 uVar19;
  
  uVar19 = FUN_802860b8();
  iVar5 = (int)((ulonglong)uVar19 >> 0x20);
  iVar10 = (int)uVar19;
  iVar13 = 0;
  do {
    if (param_6 <= iVar13) {
      uVar8 = 0;
LAB_80083bd8:
      FUN_80286104(uVar8);
      return;
    }
    uVar4 = *param_4;
    uVar3 = uVar4 & 0x3f;
    uVar16 = uVar4 >> 6 & 0x3ff;
    uVar4 = uVar4 >> 0x10;
    if ((uVar3 == 2) || (uVar17 = uVar16, uVar3 == 3)) {
      if ((uVar4 & 0x8000) != 0) {
        uVar4 = uVar4 | 0xffff0000;
      }
      uVar17 = 0;
      unaff_r26 = uVar16;
    }
    iVar6 = 0;
    cVar12 = (char)param_8;
    if (uVar3 == 8) {
      if (cVar12 == '\0') {
        bVar11 = false;
        iVar6 = -1;
        iVar7 = 0;
        iVar18 = 2;
        do {
          uVar16 = (uint)*(byte *)(param_3 + iVar7 + 300);
          if (uVar16 == uVar17) {
            bVar11 = true;
          }
          if (uVar16 == 0) {
            iVar6 = iVar7;
          }
          uVar16 = (uint)*(byte *)(param_3 + iVar7 + 0x12d);
          if (uVar16 == uVar17) {
            bVar11 = true;
          }
          if (uVar16 == 0) {
            iVar6 = iVar7 + 1;
          }
          uVar16 = (uint)*(byte *)(param_3 + iVar7 + 0x12e);
          if (uVar16 == uVar17) {
            bVar11 = true;
          }
          if (uVar16 == 0) {
            iVar6 = iVar7 + 2;
          }
          uVar16 = (uint)*(byte *)(param_3 + iVar7 + 0x12f);
          if (uVar16 == uVar17) {
            bVar11 = true;
          }
          if (uVar16 == 0) {
            iVar6 = iVar7 + 3;
          }
          uVar16 = (uint)*(byte *)(param_3 + iVar7 + 0x130);
          if (uVar16 == uVar17) {
            bVar11 = true;
          }
          if (uVar16 == 0) {
            iVar6 = iVar7 + 4;
          }
          iVar7 = iVar7 + 5;
          iVar18 = iVar18 + -1;
        } while (iVar18 != 0);
        if ((!bVar11) && (iVar6 != -1)) {
          *(char *)(param_3 + iVar6 + 300) = (char)uVar17;
          uVar9 = FUN_80084c58(param_3,uVar4);
          *(undefined2 *)(param_3 + iVar6 * 2 + 0x118) = uVar9;
        }
        iVar6 = 0;
      }
    }
    else if (uVar3 < 8) {
      if (uVar3 == 6) {
        iVar6 = FUN_80082e7c(iVar5,iVar10,param_3,uVar17 | uVar4 << 8,param_8);
        if (iVar6 == 0) {
          uVar8 = 1;
          goto LAB_80083bd8;
        }
        iVar6 = -1;
        uVar17 = 0;
      }
      else {
        if (uVar3 < 6) goto LAB_800839b0;
        if (iVar10 != iVar5) {
          cVar2 = (&DAT_8030ee1c)[uVar17];
          if (cVar2 == '\x02') {
            FUN_8003759c((double)FLOAT_803df018,0,2,iVar5,(&DAT_8030edc0)[uVar17],iVar5);
          }
          else if ((cVar2 < '\x02') && ('\0' < cVar2)) {
            FUN_800376d8(0,2,iVar5,(&DAT_8030edc0)[uVar17],iVar5);
          }
          else {
            FUN_800378c4(iVar10,(&DAT_8030edc0)[uVar17],iVar5,0);
          }
        }
        iVar6 = -1;
        uVar17 = 0;
      }
    }
    else if (9 < uVar3) {
LAB_800839b0:
      iVar6 = FUN_80083bf0(uVar17,param_3,*(undefined4 *)(iVar5 + 0x4c));
    }
    if ((0 < iVar6) && (param_7 == '\0')) {
      sVar14 = (short)uVar4;
      switch(uVar3) {
      case 1:
        if (cVar12 == '\0') {
          if ((&DAT_8039a60c)[*(char *)(param_3 + 0x57)] == '\0') {
            (&DAT_8039a60c)[*(char *)(param_3 + 0x57)] = 1;
            *(short *)(param_3 + 0x58) = sVar14;
            *(undefined2 *)(param_3 + 0x5a) = *(undefined2 *)(param_3 + 0x58);
          }
          uVar8 = 1;
          goto LAB_80083bd8;
        }
        break;
      case 2:
        uVar15 = (undefined)uVar4;
        switch(unaff_r26) {
        case 0:
          *(undefined *)(param_3 + 0x80) = uVar15;
          bVar1 = *(byte *)(param_3 + 0x8b);
          if (bVar1 < 10) {
            *(byte *)(param_3 + 0x8b) = bVar1 + 1;
            *(undefined *)(param_3 + bVar1 + 0x81) = uVar15;
          }
          break;
        case 1:
          *(short *)(param_3 + 0x60) = sVar14;
          break;
        case 3:
          DAT_803dd06c = sVar14;
          break;
        case 4:
          DAT_803dd06e = sVar14;
          break;
        case 5:
          (&DAT_8039a45c)[*(char *)(param_3 + 0x57)] = uVar15;
          break;
        case 6:
          FUN_800200e8((int)*(short *)(param_3 + 0x6a),(-uVar4 | uVar4) >> 0x1f);
        }
        break;
      case 3:
        if ((((cVar12 == '\0') && (unaff_r26 != 1)) && ((int)unaff_r26 < 1)) &&
           (-1 < (int)unaff_r26)) {
          *(short *)(param_3 + 0x60) = *(short *)(param_3 + 0x60) + sVar14;
        }
        break;
      case 4:
        if (cVar12 == '\0') {
          *(undefined2 *)(param_3 + 0x58) = param_5;
          *(undefined2 *)(param_3 + 0x5a) = param_5;
          *(char *)(param_3 + 0x7c) = (char)uVar17 + '\x01';
          (&DAT_8039a60c)[*(char *)(param_3 + 0x57)] = 1;
          uVar8 = 1;
          goto LAB_80083bd8;
        }
        break;
      case 5:
        if (cVar12 == '\0') {
          uVar8 = 0;
          goto LAB_80083bd8;
        }
        break;
      case 10:
        if (cVar12 == '\0') {
          if ((&DAT_8039a60c)[*(char *)(param_3 + 0x57)] == '\0') {
            (&DAT_8039a60c)[*(char *)(param_3 + 0x57)] = 1;
            uVar9 = FUN_80084c58(param_3,uVar4);
            *(undefined2 *)(param_3 + 0x58) = uVar9;
            *(undefined2 *)(param_3 + 0x5a) = *(undefined2 *)(param_3 + 0x58);
          }
          uVar8 = 1;
          goto LAB_80083bd8;
        }
      }
    }
    param_4 = param_4 + 1;
    iVar13 = iVar13 + 1;
  } while( true );
}

