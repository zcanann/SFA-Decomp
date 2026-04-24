// Function: FUN_8012f298
// Entry: 8012f298
// Size: 2676 bytes

void FUN_8012f298(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  bool bVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  char cVar8;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar9;
  short sVar10;
  undefined unaff_r29;
  undefined8 uVar11;
  double dVar12;
  
  uVar11 = FUN_80286838();
  uVar9 = extraout_r4;
  iVar4 = FUN_8002bac4();
  iVar5 = FUN_8002ba84();
  bVar2 = false;
  bVar1 = true;
  DAT_803de524 = FUN_80014e9c(0);
  uVar6 = FUN_80014f14(0);
  sVar10 = DAT_803de51e;
  DAT_803de518 = uVar6;
  if (DAT_803de52c == '\0') {
    cVar8 = FUN_80014c44(0);
    uVar11 = FUN_80014b68(0,0xf0000);
    uVar6 = 0xfff0fff7;
    DAT_803de524 = DAT_803de524 & 0xfff0fff7;
    uVar9 = extraout_r4_00;
    sVar10 = (short)cVar8;
    DAT_803de518 = DAT_803de518 & 0xfff0fff7;
  }
  FUN_8012a21c(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar6,uVar9,param_11,
               param_12,param_13,param_14,param_15,param_16);
  if ((-1 < DAT_803dc6f8) && (uVar6 = FUN_80014e9c(0), (uVar6 & 0x100) != 0)) {
    FUN_80014b68(0,0x100);
    DAT_803dc6f8 = -1;
    FUN_800207ac(0);
    FUN_8000a538((int *)0x23,0);
  }
  if (iVar4 == 0) goto LAB_8012fca8;
  if (DAT_803de3db != '\0') {
    FUN_8012c1c0();
  }
  iVar7 = FUN_80297a08(iVar4);
  if ((((iVar7 == 0) && (iVar7 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar7 != 0x44)) &&
      ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) && (DAT_803de400 == '\0')) {
    if ((int)DAT_803de434 != 0) {
      FUN_80014b68(0,(int)DAT_803de434);
      DAT_803de524 = DAT_803de524 & ~(int)DAT_803de434;
      DAT_803de518 = DAT_803de518 & ~(int)DAT_803de434;
    }
  }
  else {
    FUN_80014b68(0,0xf0000);
    DAT_803de524 = DAT_803de524 & 0xfff0fff7;
    DAT_803de518 = DAT_803de518 & 0xfff0fff7;
  }
  iVar7 = FUN_80297a08(iVar4);
  if (((((iVar7 == 0) && (iVar7 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar7 != 0x44)) &&
       (((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0 &&
        ((DAT_803de434 == '\0' && (DAT_803de400 == '\0')))))) &&
      (iVar7 = FUN_80020800(), iVar7 == 0)) && (DAT_803de3db == '\0')) {
    if (DAT_803de52c != '\0') {
      DAT_803de518 = DAT_803de520;
      DAT_803de524 = DAT_803de520;
    }
  }
  else {
    bVar1 = false;
    DAT_803de524 = DAT_803de524 & 0xfff0ffff | 0x200;
  }
  sVar3 = DAT_803de41c - DAT_803de41e;
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  uVar6 = FUN_80020078(0x9d5);
  if (uVar6 != 0) {
    uVar6 = FUN_800ea540();
    if ((int)DAT_803de3b0 < (int)(uVar6 & 0xffff)) {
      DAT_803de3f2 = 1;
      DAT_803dc6cc = 3;
      DAT_803de3b0 = uVar6 & 0xffff;
    }
    FUN_800201ac(0x9d5,0);
  }
  if (bVar1) {
    cVar8 = FUN_80014c44(0);
    if (cVar8 < '\0') {
      cVar8 = FUN_80014c44(0);
      iVar7 = -(int)cVar8;
    }
    else {
      cVar8 = FUN_80014c44(0);
      iVar7 = (int)cVar8;
    }
    if (iVar7 < 6) {
      cVar8 = FUN_80014bf0(0);
      if (cVar8 < '\0') {
        cVar8 = FUN_80014bf0(0);
        iVar7 = -(int)cVar8;
      }
      else {
        cVar8 = FUN_80014bf0(0);
        iVar7 = (int)cVar8;
      }
      if (iVar7 < 6) goto LAB_8012f7ec;
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
      FUN_80014b68(0,0xf0000);
      DAT_803de524 = 0;
      iVar7 = FUN_80100d2c();
      if (iVar7 == 4) {
        DAT_803de524 = DAT_803de524 | 0x80000;
      }
      else {
        iVar7 = FUN_80100d2c();
        if (iVar7 == 9) {
          DAT_803de524 = DAT_803de524 | 0x40000;
        }
        else if ((((iVar5 == 0) || (DAT_803a9f84 == 0)) || (3 < DAT_803a9fa4)) ||
                (dVar12 = FUN_80021794((float *)(iVar4 + 0x18),(float *)(iVar5 + 0x18)),
                (double)FLOAT_803e2e60 <= dVar12)) {
          if (((iVar5 == 0) || (uVar6 = FUN_80020078(0x4e4), uVar6 == 0)) ||
             (iVar4 = FUN_80100d2c(), iVar4 != 8)) {
            if (DAT_803de536 == '\x01') {
LAB_8012f798:
              iVar4 = FUN_801244b0((short *)PTR_DAT_8031c238,'\0');
              if ((iVar4 == 0) && (iVar4 = FUN_801244b0((short *)PTR_DAT_8031c228,'\0'), iVar4 != 0)
                 ) {
                DAT_803de524 = DAT_803de524 | 0x80000;
              }
              else {
                DAT_803de524 = DAT_803de524 | 0x40000;
              }
            }
            else if (DAT_803de536 < '\x01') {
              if (-1 < DAT_803de536) {
LAB_8012f750:
                iVar4 = FUN_801244b0((short *)PTR_DAT_8031c228,'\0');
                if ((iVar4 == 0) &&
                   (iVar4 = FUN_801244b0((short *)PTR_DAT_8031c238,'\0'), iVar4 != 0))
                goto LAB_8012f798;
                DAT_803de524 = DAT_803de524 | 0x80000;
              }
            }
            else if (DAT_803de536 < '\x03') {
              if (iVar5 == 0) goto LAB_8012f750;
              DAT_803de524 = DAT_803de524 | 0x20000;
            }
          }
          else {
            DAT_803de524 = DAT_803de524 | 0x20000;
          }
        }
        else {
          DAT_803de524 = DAT_803de524 | 0x80000;
          bVar2 = true;
        }
      }
    }
  }
LAB_8012f7ec:
  if ((((DAT_803de524 & 0x20000) == 0) || (iVar5 == 0)) || (DAT_803de454 == 2)) {
LAB_8012f884:
    if (((DAT_803de524 & 0x80000) != 0) && (DAT_803de454 != 3)) {
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
        uVar11 = FUN_80014b68(0,0x80000);
        DAT_803de41c = -0x5556;
        DAT_803de41e = -0x5556;
        DAT_803de455 = 3;
        DAT_803de537 = 0;
        DAT_803de536 = '\0';
        uVar11 = FUN_8012fdc8(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
        if (bVar2) {
          FUN_8012fd0c(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0xc1);
        }
        goto LAB_8012fb2c;
      }
    }
    if (((DAT_803de524 & 0x40000) != 0) && (DAT_803de454 != 4)) {
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
        uVar11 = FUN_80014b68(0,0x40000);
        DAT_803de41c = 0x5555;
        DAT_803de41e = 0x5555;
        DAT_803de455 = 4;
        DAT_803de537 = 1;
        DAT_803de536 = '\x01';
        FUN_8012fdc8(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,1);
        goto LAB_8012fb2c;
      }
    }
    iVar4 = (int)sVar10;
    if (iVar4 < 0) {
      iVar4 = -iVar4;
    }
    if (0xe < iVar4) {
      iVar4 = (int)DAT_803de40e;
      if (iVar4 < 0) {
        iVar4 = -iVar4;
      }
      if ((iVar4 < 0xf) && (DAT_803de416 == 0)) {
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
          iVar4 = (int)sVar3;
          if (iVar4 < 0) {
            iVar4 = -iVar4;
          }
          if (iVar4 < 10000) {
            iVar4 = 1;
            DAT_803de41a = 0xffff;
            if (sVar10 < 0) {
              iVar4 = -1;
              DAT_803de41a = 1;
            }
            uVar6 = (uint)DAT_803de454 + iVar4 & 0xff;
            if (4 < uVar6) {
              uVar6 = 2;
            }
            if (uVar6 < 2) {
              uVar6 = 4;
            }
            if (uVar6 == 3) {
              DAT_803de41e = -0x5556;
              unaff_r29 = 0;
            }
            else if (uVar6 < 3) {
              if (1 < uVar6) {
                DAT_803de41e = 0;
                unaff_r29 = 2;
              }
            }
            else if (uVar6 < 5) {
              DAT_803de41e = 0x5555;
              unaff_r29 = 1;
            }
            if (uVar6 != (int)(char)DAT_803de454) {
              DAT_803de455 = (byte)uVar6;
              DAT_803de537 = unaff_r29;
            }
            goto LAB_8012fb2c;
          }
        }
      }
    }
    iVar4 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar4 == 0x4e) {
      DAT_803de415 = '\0';
    }
  }
  else {
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
    if (!bVar1) goto LAB_8012f884;
    uVar11 = FUN_80014b68(0,0x20000);
    DAT_803de41c = 0;
    DAT_803de41e = 0;
    DAT_803de455 = 2;
    DAT_803de537 = 2;
    DAT_803de536 = '\x02';
    FUN_8012fdc8(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,2);
  }
LAB_8012fb2c:
  if (DAT_803de455 != 0) {
    if (DAT_803de415 == '\0') {
      FUN_8000bb38(0,0xf5);
    }
    else {
      FUN_8000bb38(0,0x37b);
    }
    DAT_803de415 = '\x01';
    DAT_803de454 = DAT_803de455;
    DAT_803de524 = 0;
    DAT_803de436 = 0;
    DAT_803de455 = 0;
  }
  DAT_803de40e = sVar10;
  FUN_80122be0();
  if (DAT_803de413 != '\0') {
    FUN_8012434c();
  }
  FUN_801233f0();
  DAT_803de528 = DAT_803de528 + 1;
  if (2 < DAT_803de528) {
    DAT_803de528 = 2;
  }
  DAT_803dc6d6 = (**(code **)(*DAT_803dd6d0 + 100))();
  if (DAT_803de512 < 0) {
    if (DAT_803de420 == '\0') {
      if (DAT_803de552 == 0) {
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
      DAT_803dc6d4 = 0x140;
      DAT_803dc6d2 = 0x154;
    }
  }
  else {
    DAT_803dc6d2 = DAT_803de50e;
    DAT_803dc6d4 = DAT_803de510;
    DAT_803dc6d6 = DAT_803de512;
  }
  DAT_803de512 = -1;
  DAT_803de43a = DAT_803de439;
  if (DAT_803de439 != '\0') {
    DAT_803de439 = '\0';
    DAT_803dc6d6 = DAT_803de50c;
  }
  bVar1 = DAT_803dc6d6 < 0;
  if (bVar1) {
    DAT_803dc6d6 = -1;
  }
  DAT_803de420 = !bVar1;
  FUN_80014b68(0,0xe0000);
  DAT_803de434 = '\0';
LAB_8012fca8:
  if (DAT_803de414 != '\0') {
    DAT_803de414 = '\0';
    FUN_800207ac(0);
    uVar9 = 1;
    FUN_80043604(0,0,1);
    DAT_803dc084 = 0xff;
    uVar11 = FUN_80014974(4);
    uVar11 = FUN_80055464(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x12,'\0',
                          uVar9,param_12,param_13,param_14,param_15,param_16);
    FUN_8002e38c(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  FUN_80286884();
  return;
}

