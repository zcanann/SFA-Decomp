// Function: FUN_8012e2a4
// Entry: 8012e2a4
// Size: 2328 bytes

void FUN_8012e2a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  int iVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar7;
  uint uVar8;
  short sVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar10;
  
  FUN_80286838();
  uVar2 = FUN_8002bac4();
  DAT_803de540 = 0xffff;
  if (uVar2 == 0) goto LAB_8012eba4;
  iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if (((iVar3 == 0x44) || ((*(ushort *)(uVar2 + 0xb0) & 0x1000) != 0)) || (DAT_803de400 != '\0')) {
    FUN_80014b68(0,0xe0800);
  }
  else if ((int)DAT_803de434 != 0) {
    FUN_80014b68(0,(int)DAT_803de434);
  }
  DAT_803de524 = FUN_80014e9c(0);
  uVar7 = DAT_803de524 & 0xffff;
  iVar3 = (**(code **)(*DAT_803dd6d0 + 0x10))();
  if (((iVar3 == 0x44) || ((*(ushort *)(uVar2 + 0xb0) & 0x1000) != 0)) ||
     ((DAT_803de400 != '\0' || ((DAT_803de434 != '\0' || (DAT_803de3db != '\0')))))) {
    DAT_803de524 = DAT_803de524 | 0x200;
  }
  else if (DAT_803de52c != '\0') {
    DAT_803de524 = DAT_803de520;
    uVar7 = DAT_803de520 & 0xffff;
  }
  if (DAT_803de538 == '\x01') {
    uVar10 = FUN_8000bb38(0,0xfd);
  }
  else {
    uVar10 = extraout_f1;
    if (('\0' < DAT_803de538) && (DAT_803de538 < '\x03')) {
      uVar10 = FUN_8000bb38(0,0xfb);
    }
  }
  DAT_803de542 = 0xffff;
  DAT_803de538 = '\0';
  iVar3 = (int)DAT_803de536;
  uVar8 = *(uint *)(&DAT_8031c230 + iVar3 * 0x10);
  DAT_803de534 = (&DAT_8031c22c)[iVar3 * 8];
  DAT_803de530 = FUN_801245c0(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar10 = extraout_f1_00;
  if (DAT_803de504 == 2) {
    uVar4 = FUN_80020078(0x4e4);
    if (uVar4 == 0) {
      DAT_803de504 = 0;
      DAT_803de4f4 = 0xffff;
    }
    if ((DAT_803de3b8 & 1 << (uint)DAT_803de50a) == 0) {
      DAT_803de4fc = '\x01';
    }
    else {
      DAT_803de4fc = '\0';
    }
  }
  else if (DAT_803de504 < 2) {
    if (DAT_803de504 != 0) {
LAB_8012e4e0:
      uVar4 = FUN_80020078((uint)DAT_803de50a);
      if ((uVar4 == 0) ||
         ((-1 < DAT_803de506 && (uVar4 = FUN_80020078((int)DAT_803de506), uVar4 != 0)))) {
        DAT_803de504 = 0;
        DAT_803de4f4 = 0xffff;
      }
      else if ((DAT_803de508 < 0) || (uVar4 = FUN_80020078((int)DAT_803de508), uVar4 == 0)) {
        DAT_803de4fc = '\0';
      }
      else {
        DAT_803de4fc = '\x01';
      }
    }
  }
  else if (DAT_803de504 < 4) goto LAB_8012e4e0;
  if (DAT_803de530 <= DAT_803de534) {
    DAT_803de534 = 0;
  }
  if (DAT_803de415 == '\0') {
    bVar1 = false;
  }
  else if (DAT_803de556 == DAT_803dc6ce) {
    bVar1 = true;
  }
  else {
    bVar1 = false;
  }
  if (bVar1) {
    iVar6 = (int)DAT_803de534;
    DAT_803de540 = (ushort)(&DAT_803a9c98)[iVar6];
    DAT_803de53c = (short)(&DAT_803a9a98)[iVar6];
    DAT_803de53e = (short)(&DAT_803a9b98)[iVar6];
    if (DAT_803de42a == 0) {
      DAT_803de42a = (&DAT_803a9998)[iVar6];
    }
    if (DAT_803de42c == '\0') {
      DAT_803de42c = '\n';
    }
    sVar9 = DAT_803de51c;
    if (DAT_803de52c == '\0') {
      cVar5 = FUN_80014bf0(0);
      sVar9 = (short)cVar5;
    }
    if (((sVar9 < -9) && (-10 < DAT_803de410)) || (sVar9 < -0x3c)) {
      iVar6 = (int)DAT_803de416;
      if (iVar6 < 0) {
        iVar6 = -iVar6;
      }
      if (((7 < iVar6) || (DAT_803de438 != '\0')) || (DAT_803de41a != 0)) goto LAB_8012e69c;
      if (DAT_803dc6cd == '\0') {
        FUN_8000bb38(0,0xfc);
      }
      DAT_803de436 = 1;
    }
    else {
LAB_8012e69c:
      if (((9 < sVar9) && (DAT_803de410 < 10)) || (0x3c < sVar9)) {
        iVar6 = (int)DAT_803de416;
        if (iVar6 < 0) {
          iVar6 = -iVar6;
        }
        if (((iVar6 < 8) && (DAT_803de438 == '\0')) && (DAT_803de41a == 0)) {
          if (DAT_803dc6cd == '\0') {
            FUN_8000bb38(0,0xfc);
          }
          DAT_803de436 = -1;
        }
      }
    }
    if (0xff < DAT_803de436) {
      DAT_803de436 = 0xff;
    }
    if (DAT_803de436 < -0xff) {
      DAT_803de436 = -0xff;
    }
    if (DAT_803de514 != -1) {
      DAT_803de534 = DAT_803de514;
    }
    DAT_803de410 = sVar9;
    if ((DAT_803de436 == 0) || (DAT_803de416 != 0)) {
      if ((DAT_803de524 & 0x200) == 0) {
        if ((uVar7 & 0x900) != 0) {
          if (DAT_803de415 == '\0') {
            bVar1 = false;
          }
          else if (DAT_803de556 == DAT_803dc6ce) {
            bVar1 = true;
          }
          else {
            bVar1 = false;
          }
          if (bVar1) {
            bVar1 = false;
            if ((uVar7 & 0x800) != 0) {
              if ((DAT_803de504 == 0) || ((uint)DAT_803de50a != (int)(short)DAT_803de540)) {
                FUN_8000bb38(0,0x408);
                DAT_803de4f4 = (&DAT_803a9d98)[DAT_803de534];
                DAT_803de50a = DAT_803de540;
                DAT_803de508 = DAT_803de53e;
                DAT_803de506 = DAT_803de53c;
                FLOAT_803de4f8 = FLOAT_803dc6ec;
                if (iVar3 == 2) {
                  DAT_803de504 = 2;
                }
                else {
                  DAT_803de500 = uVar8;
                  if (DAT_803de454 == '\x04') {
                    DAT_803de504 = 1;
                  }
                  else {
                    DAT_803de504 = 3;
                  }
                }
              }
              else {
                bVar1 = true;
              }
            }
            uVar10 = FUN_80014b68(0,0x900);
            if (iVar3 == 2) {
              if ((&DAT_803a98d8)[DAT_803de534] == '\0') {
                DAT_803de542 = 0xffff;
                DAT_803de538 = '\0';
                FUN_8000bb38(0,0xfd);
              }
              else if (((uVar7 & 0x100) != 0) || (bVar1)) {
                DAT_803de415 = '\0';
                DAT_803de542 = DAT_803de540;
                FUN_8011dbfc(uVar2);
                DAT_803de538 = '\0';
              }
            }
            else if ((&DAT_803a98d8)[DAT_803de534] == '\0') {
              DAT_803de542 = 0xffff;
              DAT_803de538 = '\0';
              FUN_8000bb38(0,0xfd);
            }
            else {
              if (((uVar7 & 0x100) != 0) || (bVar1)) {
                FUN_800379bc(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,
                             uVar8,0,(int)(short)DAT_803de540,in_r7,in_r8,in_r9,in_r10);
                DAT_803de542 = DAT_803de540;
                DAT_803de538 = (&DAT_803a9918)[DAT_803de534];
                DAT_803de415 = '\0';
              }
              FUN_8000bb38(0,0xf7);
            }
          }
        }
      }
      else {
        FUN_8000bb38(0,0x37c);
        DAT_803de415 = '\0';
      }
    }
    else if (DAT_803de436 < 1) {
      DAT_803de436 = DAT_803de436 + 1;
      if (1 < DAT_803de530) {
        if ((DAT_803de530 == 2) && (DAT_803de534 == 0)) {
          DAT_803de416 = -100;
        }
        else {
          DAT_803de416 = -0x32;
        }
        DAT_803dc6cd = -3;
        DAT_803de438 = '\0';
        DAT_803de534 = DAT_803de534 + -1;
        if (DAT_803de534 < 0) {
          DAT_803de534 = (short)DAT_803de530 + -1;
        }
      }
    }
    else {
      DAT_803de436 = DAT_803de436 + -1;
      if (1 < DAT_803de530) {
        if ((DAT_803de530 == 2) && (DAT_803de534 == 1)) {
          DAT_803de416 = 100;
        }
        else {
          DAT_803de416 = 0x32;
        }
        DAT_803dc6cd = '\x03';
        DAT_803de438 = '\0';
        DAT_803de534 = DAT_803de534 + 1;
        if (DAT_803de530 <= DAT_803de534) {
          DAT_803de534 = 0;
        }
      }
    }
  }
  else if ((uVar7 & 0x800) != 0) {
    if ((DAT_803de504 == 3) && (DAT_803de4fc == '\0')) {
      FUN_800379bc(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar2,DAT_803de500
                   ,0,(uint)DAT_803de50a,in_r7,in_r8,in_r9,in_r10);
      DAT_803de542 = DAT_803de50a;
      FUN_80014b68(0,0x900);
    }
    else if ((DAT_803de504 == 2) && ((DAT_803de3b8 & 1 << (uint)DAT_803de50a) != 0)) {
      DAT_803de542 = DAT_803de50a;
      FUN_8011dbfc(uVar2);
      FUN_80014b68(0,0x900);
    }
  }
  if (DAT_803de413 != '\0') {
    FUN_80125064();
  }
  if (DAT_803de415 == '\0') {
    if (DAT_803de556 == 0) {
      bVar1 = true;
    }
    else {
      bVar1 = false;
    }
  }
  else {
    bVar1 = false;
  }
  if (bVar1) {
    DAT_803de454 = '\0';
    DAT_803de528 = 0;
    DAT_803de436 = 0;
  }
  if (DAT_803de415 != '\0') {
    FUN_80014b68(0,0x300);
  }
  (&DAT_8031c22c)[iVar3 * 8] = DAT_803de534;
LAB_8012eba4:
  FUN_80286884();
  return;
}

