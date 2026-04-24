// Function: FUN_8012ef40
// Entry: 8012ef40
// Size: 2676 bytes

void FUN_8012ef40(void)

{
  bool bVar1;
  bool bVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  char cVar8;
  short sVar9;
  undefined unaff_r29;
  double dVar10;
  
  FUN_802860d4();
  iVar4 = FUN_8002b9ec();
  iVar5 = FUN_8002b9ac();
  bVar2 = false;
  bVar1 = true;
  DAT_803dd8a4 = FUN_80014e70(0);
  DAT_803dd898 = FUN_80014ee8(0);
  sVar9 = DAT_803dd89e;
  if (DAT_803dd8ac == '\0') {
    cVar8 = FUN_80014c18(0);
    FUN_80014b3c(0,0xf0000);
    DAT_803dd8a4 = DAT_803dd8a4 & 0xfff0fff7;
    DAT_803dd898 = DAT_803dd898 & 0xfff0fff7;
    sVar9 = (short)cVar8;
  }
  FUN_80129ee0();
  if ((-1 < DAT_803dba90) && (uVar6 = FUN_80014e70(0), (uVar6 & 0x100) != 0)) {
    FUN_80014b3c(0,0x100);
    DAT_803dba90 = -1;
    FUN_800206e8(0);
    FUN_8000a518(0x23,0);
  }
  if (iVar4 == 0) goto LAB_8012f950;
  if (DAT_803dd75b != '\0') {
    FUN_8012be84();
  }
  iVar7 = FUN_802972a8(iVar4);
  if ((((iVar7 == 0) && (iVar7 = (**(code **)(*DAT_803dca50 + 0x10))(), iVar7 != 0x44)) &&
      ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0)) && (DAT_803dd780 == '\0')) {
    if (DAT_803dd7b4 != '\0') {
      FUN_80014b3c(0);
      DAT_803dd8a4 = DAT_803dd8a4 & ~(int)DAT_803dd7b4;
      DAT_803dd898 = DAT_803dd898 & ~(int)DAT_803dd7b4;
    }
  }
  else {
    FUN_80014b3c(0,0xf0000);
    DAT_803dd8a4 = DAT_803dd8a4 & 0xfff0fff7;
    DAT_803dd898 = DAT_803dd898 & 0xfff0fff7;
  }
  iVar7 = FUN_802972a8(iVar4);
  if (((((iVar7 == 0) && (iVar7 = (**(code **)(*DAT_803dca50 + 0x10))(), iVar7 != 0x44)) &&
       (((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0 &&
        ((DAT_803dd7b4 == '\0' && (DAT_803dd780 == '\0')))))) &&
      (iVar7 = FUN_8002073c(), iVar7 == 0)) && (DAT_803dd75b == '\0')) {
    if (DAT_803dd8ac != '\0') {
      DAT_803dd898 = DAT_803dd8a0;
      DAT_803dd8a4 = DAT_803dd8a0;
    }
  }
  else {
    bVar1 = false;
    DAT_803dd8a4 = DAT_803dd8a4 & 0xfff0ffff | 0x200;
  }
  sVar3 = DAT_803dd79c - DAT_803dd79e;
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  iVar7 = FUN_8001ffb4(0x9d5);
  if (iVar7 != 0) {
    uVar6 = FUN_800ea2bc();
    if ((int)DAT_803dd730 < (int)(uVar6 & 0xffff)) {
      DAT_803dd772 = 1;
      DAT_803dba64 = 3;
      DAT_803dd730 = uVar6 & 0xffff;
    }
    FUN_800200e8(0x9d5,0);
  }
  if (bVar1) {
    cVar8 = FUN_80014c18(0);
    if (cVar8 < '\0') {
      cVar8 = FUN_80014c18(0);
      iVar7 = -(int)cVar8;
    }
    else {
      cVar8 = FUN_80014c18(0);
      iVar7 = (int)cVar8;
    }
    if (iVar7 < 6) {
      cVar8 = FUN_80014bc4(0);
      if (cVar8 < '\0') {
        cVar8 = FUN_80014bc4(0);
        iVar7 = -(int)cVar8;
      }
      else {
        cVar8 = FUN_80014bc4(0);
        iVar7 = (int)cVar8;
      }
      if (iVar7 < 6) goto LAB_8012f494;
    }
    if (DAT_803dd795 == '\0') {
      if (DAT_803dd8d6 == 0) {
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
      FUN_80014b3c(0,0xf0000);
      DAT_803dd8a4 = 0;
      iVar7 = FUN_80100a90();
      if (iVar7 == 4) {
        DAT_803dd8a4 = DAT_803dd8a4 | 0x80000;
      }
      else {
        iVar7 = FUN_80100a90();
        if (iVar7 == 9) {
          DAT_803dd8a4 = DAT_803dd8a4 | 0x40000;
        }
        else if ((((iVar5 == 0) || (DAT_803a9324 == 0)) || (3 < DAT_803a9344)) ||
                (dVar10 = (double)FUN_800216d0(iVar4 + 0x18,iVar5 + 0x18),
                (double)FLOAT_803e21d0 <= dVar10)) {
          if (((iVar5 == 0) || (iVar4 = FUN_8001ffb4(0x4e4), iVar4 == 0)) ||
             (iVar4 = FUN_80100a90(), iVar4 != 8)) {
            if (DAT_803dd8b6 == '\x01') {
LAB_8012f440:
              iVar4 = FUN_801241cc(PTR_DAT_8031b5e8,0);
              if ((iVar4 == 0) && (iVar4 = FUN_801241cc(PTR_DAT_8031b5d8,0), iVar4 != 0)) {
                DAT_803dd8a4 = DAT_803dd8a4 | 0x80000;
              }
              else {
                DAT_803dd8a4 = DAT_803dd8a4 | 0x40000;
              }
            }
            else if (DAT_803dd8b6 < '\x01') {
              if (-1 < DAT_803dd8b6) {
LAB_8012f3f8:
                iVar4 = FUN_801241cc(PTR_DAT_8031b5d8,0);
                if ((iVar4 == 0) && (iVar4 = FUN_801241cc(PTR_DAT_8031b5e8,0), iVar4 != 0))
                goto LAB_8012f440;
                DAT_803dd8a4 = DAT_803dd8a4 | 0x80000;
              }
            }
            else if (DAT_803dd8b6 < '\x03') {
              if (iVar5 == 0) goto LAB_8012f3f8;
              DAT_803dd8a4 = DAT_803dd8a4 | 0x20000;
            }
          }
          else {
            DAT_803dd8a4 = DAT_803dd8a4 | 0x20000;
          }
        }
        else {
          DAT_803dd8a4 = DAT_803dd8a4 | 0x80000;
          bVar2 = true;
        }
      }
    }
  }
LAB_8012f494:
  if ((((DAT_803dd8a4 & 0x20000) == 0) || (iVar5 == 0)) || (DAT_803dd7d4 == 2)) {
LAB_8012f52c:
    if (((DAT_803dd8a4 & 0x80000) != 0) && (DAT_803dd7d4 != 3)) {
      if (DAT_803dd795 == '\0') {
        if (DAT_803dd8d6 == 0) {
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
        FUN_80014b3c(0,0x80000);
        DAT_803dd79c = -0x5556;
        DAT_803dd79e = -0x5556;
        DAT_803dd7d5 = 3;
        DAT_803dd8b7 = 0;
        DAT_803dd8b6 = '\0';
        FUN_8012fa70(0,0);
        if (bVar2) {
          FUN_8012f9b4(0,0xc1,0);
        }
        goto LAB_8012f7d4;
      }
    }
    if (((DAT_803dd8a4 & 0x40000) != 0) && (DAT_803dd7d4 != 4)) {
      if (DAT_803dd795 == '\0') {
        if (DAT_803dd8d6 == 0) {
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
        FUN_80014b3c(0,0x40000);
        DAT_803dd79c = 0x5555;
        DAT_803dd79e = 0x5555;
        DAT_803dd7d5 = 4;
        DAT_803dd8b7 = 1;
        DAT_803dd8b6 = '\x01';
        FUN_8012fa70(1,0);
        goto LAB_8012f7d4;
      }
    }
    iVar4 = (int)sVar9;
    if (iVar4 < 0) {
      iVar4 = -iVar4;
    }
    if (0xe < iVar4) {
      iVar4 = (int)DAT_803dd78e;
      if (iVar4 < 0) {
        iVar4 = -iVar4;
      }
      if ((iVar4 < 0xf) && (DAT_803dd796 == 0)) {
        if (DAT_803dd795 == '\0') {
          bVar1 = false;
        }
        else if (DAT_803dd8d6 == DAT_803dba66) {
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
            DAT_803dd79a = 0xffff;
            if (sVar9 < 0) {
              iVar4 = -1;
              DAT_803dd79a = 1;
            }
            uVar6 = (uint)DAT_803dd7d4 + iVar4 & 0xff;
            if (4 < uVar6) {
              uVar6 = 2;
            }
            if (uVar6 < 2) {
              uVar6 = 4;
            }
            if (uVar6 == 3) {
              DAT_803dd79e = -0x5556;
              unaff_r29 = 0;
            }
            else if (uVar6 < 3) {
              if (1 < uVar6) {
                DAT_803dd79e = 0;
                unaff_r29 = 2;
              }
            }
            else if (uVar6 < 5) {
              DAT_803dd79e = 0x5555;
              unaff_r29 = 1;
            }
            if (uVar6 != (int)(char)DAT_803dd7d4) {
              DAT_803dd7d5 = (byte)uVar6;
              DAT_803dd8b7 = unaff_r29;
            }
            goto LAB_8012f7d4;
          }
        }
      }
    }
    iVar4 = (**(code **)(*DAT_803dca50 + 0x10))();
    if (iVar4 == 0x4e) {
      DAT_803dd795 = '\0';
    }
  }
  else {
    if (DAT_803dd795 == '\0') {
      if (DAT_803dd8d6 == 0) {
        bVar1 = true;
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
    if (!bVar1) goto LAB_8012f52c;
    FUN_80014b3c(0,0x20000);
    DAT_803dd79c = 0;
    DAT_803dd79e = 0;
    DAT_803dd7d5 = 2;
    DAT_803dd8b7 = 2;
    DAT_803dd8b6 = '\x02';
    FUN_8012fa70(2,1);
  }
LAB_8012f7d4:
  if (DAT_803dd7d5 != 0) {
    if (DAT_803dd795 == '\0') {
      FUN_8000bb18(0,0xf5);
    }
    else {
      FUN_8000bb18(0,0x37b);
    }
    DAT_803dd795 = '\x01';
    DAT_803dd7d4 = DAT_803dd7d5;
    DAT_803dd8a4 = 0;
    DAT_803dd7b6 = 0;
    DAT_803dd7d5 = 0;
  }
  DAT_803dd78e = sVar9;
  FUN_801228fc();
  if (DAT_803dd793 != '\0') {
    FUN_80124068();
  }
  FUN_8012310c();
  DAT_803dd8a8 = DAT_803dd8a8 + 1;
  if (2 < DAT_803dd8a8) {
    DAT_803dd8a8 = 2;
  }
  DAT_803dba6e = (**(code **)(*DAT_803dca50 + 100))();
  if (DAT_803dd892 < 0) {
    if (DAT_803dd7a0 == '\0') {
      if (DAT_803dd8d2 == 0) {
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
      DAT_803dba6c = 0x140;
      DAT_803dba6a = 0x154;
    }
  }
  else {
    DAT_803dba6a = DAT_803dd88e;
    DAT_803dba6c = DAT_803dd890;
    DAT_803dba6e = DAT_803dd892;
  }
  DAT_803dd892 = -1;
  DAT_803dd7ba = DAT_803dd7b9;
  if (DAT_803dd7b9 != '\0') {
    DAT_803dd7b9 = '\0';
    DAT_803dba6e = DAT_803dd88c;
  }
  bVar1 = DAT_803dba6e < 0;
  if (bVar1) {
    DAT_803dba6e = -1;
  }
  DAT_803dd7a0 = !bVar1;
  FUN_80014b3c(0,0xe0000);
  DAT_803dd7b4 = '\0';
LAB_8012f950:
  if (DAT_803dd794 != '\0') {
    DAT_803dd794 = '\0';
    FUN_800206e8(0);
    FUN_8004350c(0,0,1);
    DAT_803db424 = 0xff;
    FUN_80014948(4);
    FUN_800552e8(0x12,0);
    FUN_8002e294();
  }
  FUN_80286120();
  return;
}

