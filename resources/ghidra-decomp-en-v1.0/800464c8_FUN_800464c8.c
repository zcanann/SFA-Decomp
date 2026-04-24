// Function: FUN_800464c8
// Entry: 800464c8
// Size: 7400 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_800464c8(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint *param_5,
                 int param_6,uint param_7)

{
  bool bVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  int *piVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  ulonglong uVar12;
  undefined4 local_78;
  undefined auStack116 [116];
  
  uVar12 = FUN_802860bc();
  iVar11 = (int)(uVar12 >> 0x20);
  uVar7 = (undefined4)uVar12;
  iVar10 = 0;
  iVar9 = 0;
  bVar2 = false;
  if (iVar11 == 0x25) {
    FUN_8024377c();
    uVar3 = DAT_803dcc80;
    FUN_802437a4();
    if (((uVar3 & 0x20000) == 0) && ((uVar3 & 0x10000) == 0)) {
      iVar10 = DAT_8035f480;
    }
    if (((uVar3 & 0x80000) == 0) && ((uVar3 & 0x40000) == 0)) {
      iVar9 = DAT_8035f508;
    }
    if (((param_3 & 0x20000000) == 0) || (iVar9 == 0)) {
      if (((param_3 & 0x10000000) == 0) || (iVar10 == 0)) {
        if (iVar10 == 0) {
          if (iVar9 != 0) {
            iVar11 = 0x47;
          }
        }
        else {
          iVar11 = 0x25;
        }
      }
      else {
        iVar11 = 0x25;
      }
    }
    else {
      iVar11 = 0x47;
    }
    param_3 = param_3 & 0xfffffff;
  }
  else if ((longlong)uVar12 < 0x2500000000) {
    if (iVar11 == 0x20) {
      FUN_8024377c();
      uVar3 = DAT_803dcc80;
      FUN_802437a4();
      if (((uVar3 & 0x4000) == 0) && ((uVar3 & 0x1000) == 0)) {
        iVar10 = DAT_8035f46c;
      }
      if (((uVar3 & 0x8000) == 0) && ((uVar3 & 0x2000) == 0)) {
        iVar9 = DAT_8035f518;
      }
      iVar5 = iVar9;
      iVar4 = iVar10;
      if (((param_3 & 0x40000000) == 0) || (iVar10 != 0)) {
        if (((param_3 & 0x80000000) != 0) && (iVar9 == 0)) {
          while( true ) {
            FUN_8024377c();
            uVar3 = DAT_803dcc80;
            FUN_802437a4();
            iVar5 = iVar9;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x8000) == 0 && (iVar5 = DAT_8035f518, (uVar3 & 0x2000) == 0)))) break;
            FUN_80014f40();
            FUN_800202cc();
            if (bVar2) {
              FUN_8004a868();
            }
            FUN_800481d4(0);
            FUN_80015624();
            if (bVar2) {
              FUN_800234ec(0);
              FUN_80019c24();
              FUN_8004a43c(1,0);
            }
            if (DAT_803dc950 != '\0') {
              bVar2 = true;
            }
          }
        }
      }
      else {
        while( true ) {
          FUN_8024377c();
          uVar3 = DAT_803dcc80;
          FUN_802437a4();
          iVar4 = iVar10;
          if ((uVar3 == 0) ||
             ((bVar1 = (uVar3 & 0x1000) == 0, bVar1 && (iVar4 = DAT_8035f46c, bVar1)))) break;
          FUN_80014f40();
          FUN_800202cc();
          if (bVar2) {
            FUN_8004a868();
          }
          FUN_800481d4(0);
          FUN_80015624();
          if (bVar2) {
            FUN_800234ec(0);
            FUN_80019c24();
            FUN_8004a43c(1,0);
          }
          if (DAT_803dc950 != '\0') {
            bVar2 = true;
          }
        }
      }
      if ((iVar5 == 0) || ((*(uint *)(&DAT_80352010 + param_6 * 4) & 0x80000000) == 0)) {
        if ((iVar4 == 0) || ((*(uint *)(&DAT_80352010 + param_6 * 4) & 0x40000000) == 0)) {
          if (iVar5 == 0) {
            if ((iVar4 != 0) && (iVar11 = 0x20, param_5 != (uint *)0x0)) {
              param_3 = *(uint *)(iVar4 + param_6 * 4) & 0xffffff;
              if (param_3 == 0) {
                iVar9 = 0;
                do {
                  iVar5 = iVar9 + 1;
                  iVar10 = iVar9 * 4;
                  iVar9 = iVar5;
                } while ((*(uint *)(iVar4 + iVar10) & 0xffffff) == 0);
                *param_5 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
              }
              else {
                do {
                  iVar10 = param_6 + 1;
                  iVar9 = param_6 * 4;
                  param_6 = iVar10;
                } while ((*(uint *)(iVar4 + iVar9) & 0xffffff) <= param_3);
                *param_5 = (*(uint *)(iVar4 + iVar10 * 4 + -4) & 0xffffff) - param_3;
              }
            }
          }
          else {
            iVar11 = 0x4b;
            if (param_5 != (uint *)0x0) {
              param_3 = *(uint *)(iVar5 + param_6 * 4) & 0xffffff;
              if (param_3 == 0) {
                iVar9 = 0;
                do {
                  iVar4 = iVar9 + 1;
                  iVar10 = iVar9 * 4;
                  iVar9 = iVar4;
                } while ((*(uint *)(iVar5 + iVar10) & 0xffffff) == 0);
                *param_5 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
              }
              else {
                do {
                  iVar10 = param_6 + 1;
                  iVar9 = param_6 * 4;
                  param_6 = iVar10;
                } while ((*(uint *)(iVar5 + iVar9) & 0xffffff) <= param_3);
                *param_5 = (*(uint *)(iVar5 + iVar10 * 4 + -4) & 0xffffff) - param_3;
              }
            }
          }
        }
        else {
          iVar11 = 0x20;
          if (param_5 != (uint *)0x0) {
            param_3 = *(uint *)(iVar4 + param_6 * 4) & 0xffffff;
            if (param_3 == 0) {
              iVar9 = 0;
              do {
                iVar5 = iVar9 + 1;
                iVar10 = iVar9 * 4;
                iVar9 = iVar5;
              } while ((*(uint *)(iVar4 + iVar10) & 0xffffff) == 0);
              *param_5 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
            }
            else {
              do {
                iVar10 = param_6 + 1;
                iVar9 = param_6 * 4;
                param_6 = iVar10;
              } while ((*(uint *)(iVar4 + iVar9) & 0xffffff) <= param_3);
              *param_5 = (*(uint *)(iVar4 + iVar10 * 4 + -4) & 0xffffff) - param_3;
            }
          }
        }
      }
      else {
        iVar11 = 0x4b;
        if (param_5 != (uint *)0x0) {
          param_3 = *(uint *)(iVar5 + param_6 * 4) & 0xffffff;
          if (param_3 == 0) {
            iVar9 = 0;
            do {
              iVar4 = iVar9 + 1;
              iVar10 = iVar9 * 4;
              iVar9 = iVar4;
            } while ((*(uint *)(iVar5 + iVar10) & 0xffffff) == 0);
            *param_5 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
          }
          else {
            do {
              iVar10 = param_6 + 1;
              iVar9 = param_6 * 4;
              param_6 = iVar10;
            } while ((*(uint *)(iVar5 + iVar9) & 0xffffff) <= param_3);
            *param_5 = (*(uint *)(iVar5 + iVar10 * 4 + -4) & 0xffffff) - param_3;
          }
        }
      }
      param_3 = param_3 & 0xfffffff;
    }
    else if ((longlong)uVar12 < 0x2000000000) {
      if (iVar11 == 0x1b) {
        FUN_8024377c();
        uVar3 = DAT_803dcc80;
        FUN_802437a4();
        if (((uVar3 & 0x2000000) == 0) && ((uVar3 & 0x1000000) == 0)) {
          iVar10 = DAT_8035f450;
        }
        if (((uVar3 & 0x8000000) == 0) && ((uVar3 & 0x4000000) == 0)) {
          iVar9 = DAT_8035f534;
        }
        iVar5 = iVar9;
        iVar4 = iVar10;
        if (((param_3 & 0x80000000) == 0) || (iVar10 != 0)) {
          if (((param_3 & 0x20000000) != 0) && (iVar9 == 0)) {
            while( true ) {
              FUN_8024377c();
              uVar3 = DAT_803dcc80;
              FUN_802437a4();
              iVar5 = iVar9;
              if ((uVar3 == 0) ||
                 (((uVar3 & 0x8000000) == 0 && (iVar5 = DAT_8035f534, (uVar3 & 0x4000000) == 0))))
              break;
              FUN_80014f40();
              FUN_800202cc();
              if (bVar2) {
                FUN_8004a868();
              }
              FUN_800481d4(0);
              FUN_80015624();
              if (bVar2) {
                FUN_800234ec(0);
                FUN_80019c24();
                FUN_8004a43c(1,0);
              }
              if (DAT_803dc950 != '\0') {
                bVar2 = true;
              }
            }
          }
        }
        else {
          while( true ) {
            FUN_8024377c();
            uVar3 = DAT_803dcc80;
            FUN_802437a4();
            iVar4 = iVar10;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x2000000) == 0 && (iVar4 = DAT_8035f450, (uVar3 & 0x1000000) == 0))))
            break;
            FUN_80014f40();
            FUN_800202cc();
            if (bVar2) {
              FUN_8004a868();
            }
            FUN_800481d4(0);
            FUN_80015624();
            if (bVar2) {
              FUN_800234ec(0);
              FUN_80019c24();
              FUN_8004a43c(1,0);
            }
            if (DAT_803dc950 != '\0') {
              bVar2 = true;
            }
          }
        }
        if (((param_3 & 0x20000000) == 0) || (iVar5 == 0)) {
          if (((param_3 & 0x80000000) == 0) || (iVar4 == 0)) {
            if (iVar4 == 0) {
              if (iVar5 != 0) {
                iVar11 = 0x54;
              }
            }
            else {
              iVar11 = 0x1b;
            }
          }
          else {
            iVar11 = 0x1b;
          }
        }
        else {
          iVar11 = 0x54;
        }
        param_3 = param_3 & 0xfffffff;
      }
      else if (((longlong)uVar12 < 0x1b00000000) && (iVar11 == 0xd)) {
        FUN_8024377c();
        uVar3 = DAT_803dcc80;
        FUN_802437a4();
        if (((uVar3 & 0x20000000) == 0) && ((uVar3 & 0x10000000) == 0)) {
          iVar10 = DAT_8035f420;
        }
        if (((uVar3 & 0x80000000) == 0) && ((uVar3 & 0x40000000) == 0)) {
          iVar9 = DAT_8035f540;
        }
        iVar5 = iVar9;
        iVar4 = iVar10;
        if (((param_3 & 0x80000000) == 0) || (iVar10 != 0)) {
          if (((param_3 & 0x20000000) != 0) && (iVar9 == 0)) {
            while( true ) {
              FUN_8024377c();
              uVar3 = DAT_803dcc80;
              FUN_802437a4();
              iVar5 = iVar9;
              if ((uVar3 == 0) ||
                 (((uVar3 & 0x80000000) == 0 && (iVar5 = DAT_8035f3e8, (uVar3 & 0x40000000) == 0))))
              break;
              FUN_80014f40();
              FUN_800202cc();
              if (bVar2) {
                FUN_8004a868();
              }
              FUN_800481d4(0);
              FUN_80015624();
              if (bVar2) {
                FUN_800234ec(0);
                FUN_80019c24();
                FUN_8004a43c(1,0);
              }
              if (DAT_803dc950 != '\0') {
                bVar2 = true;
              }
            }
          }
        }
        else {
          while( true ) {
            FUN_8024377c();
            uVar3 = DAT_803dcc80;
            FUN_802437a4();
            iVar4 = iVar10;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x20000000) == 0 && (iVar4 = _DAT_0035f3e8, (uVar3 & 0x10000000) == 0))))
            break;
            FUN_80014f40();
            FUN_800202cc();
            if (bVar2) {
              FUN_8004a868();
            }
            FUN_800481d4(0);
            FUN_80015624();
            if (bVar2) {
              FUN_800234ec(0);
              FUN_80019c24();
              FUN_8004a43c(1,0);
            }
            if (DAT_803dc950 != '\0') {
              bVar2 = true;
            }
          }
        }
        if (((param_3 & 0x20000000) == 0) || (iVar5 == 0)) {
          if (((param_3 & 0x80000000) == 0) || (iVar4 == 0)) {
            if (iVar4 == 0) {
              if (iVar5 != 0) {
                iVar11 = 0x55;
              }
            }
            else {
              iVar11 = 0xd;
            }
          }
          else {
            iVar11 = 0xd;
          }
        }
        else {
          iVar11 = 0x55;
        }
        param_3 = param_3 & 0xfffffff;
      }
    }
    else if (iVar11 == 0x23) {
      FUN_8024377c();
      uVar3 = DAT_803dcc80;
      FUN_802437a4();
      bVar1 = (uVar3 & 0x100) == 0;
      if ((bVar1) && (bVar1)) {
        iVar10 = DAT_8035f478;
      }
      if (((uVar3 & 0x800) == 0) && ((uVar3 & 0x200) == 0)) {
        iVar9 = DAT_8035f520;
      }
      iVar5 = iVar9;
      iVar4 = iVar10;
      if (((param_3 & 0x40000000) == 0) || (iVar10 != 0)) {
        if (((param_3 & 0x80000000) != 0) && (iVar9 == 0)) {
          while( true ) {
            FUN_8024377c();
            uVar3 = DAT_803dcc80;
            FUN_802437a4();
            iVar5 = iVar9;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x800) == 0 && (iVar5 = DAT_8035f520, (uVar3 & 0x200) == 0)))) break;
            FUN_80014f40();
            FUN_800202cc();
            if (bVar2) {
              FUN_8004a868();
            }
            FUN_800481d4(0);
            FUN_80015624();
            if (bVar2) {
              FUN_800234ec(0);
              FUN_80019c24();
              FUN_8004a43c(1,0);
            }
            if (DAT_803dc950 != '\0') {
              bVar2 = true;
            }
          }
        }
      }
      else {
        while( true ) {
          FUN_8024377c();
          uVar3 = DAT_803dcc80;
          FUN_802437a4();
          iVar4 = iVar10;
          if ((uVar3 == 0) ||
             ((bVar1 = (uVar3 & 0x100) == 0, bVar1 && (iVar4 = DAT_8035f478, bVar1)))) break;
          FUN_80014f40();
          FUN_800202cc();
          if (bVar2) {
            FUN_8004a868();
          }
          FUN_800481d4(0);
          FUN_80015624();
          if (bVar2) {
            FUN_800234ec(0);
            FUN_80019c24();
            FUN_8004a43c(1,0);
          }
          if (DAT_803dc950 != '\0') {
            bVar2 = true;
          }
        }
      }
      if ((iVar5 == 0) || ((*(uint *)(&DAT_80356010 + param_6 * 4) & 0x80000000) == 0)) {
        if ((iVar4 == 0) || ((*(uint *)(&DAT_80356010 + param_6 * 4) & 0x40000000) == 0)) {
          if (iVar5 == 0) {
            if ((iVar4 != 0) && (iVar11 = 0x23, param_5 != (uint *)0x0)) {
              param_3 = *(uint *)(iVar4 + param_6 * 4) & 0xffffff;
              if (param_3 == 0) {
                iVar9 = 0;
                do {
                  iVar5 = iVar9 + 1;
                  iVar10 = iVar9 * 4;
                  iVar9 = iVar5;
                } while ((*(uint *)(iVar4 + iVar10) & 0xffffff) == 0);
                *param_5 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
              }
              else {
                do {
                  iVar10 = param_6 + 1;
                  iVar9 = param_6 * 4;
                  param_6 = iVar10;
                } while ((*(uint *)(iVar4 + iVar9) & 0xffffff) <= param_3);
                *param_5 = (*(uint *)(iVar4 + iVar10 * 4 + -4) & 0xffffff) - param_3;
              }
            }
          }
          else {
            iVar11 = 0x4d;
            if (param_5 != (uint *)0x0) {
              param_3 = *(uint *)(iVar5 + param_6 * 4) & 0xffffff;
              if (param_3 == 0) {
                iVar9 = 0;
                do {
                  iVar4 = iVar9 + 1;
                  iVar10 = iVar9 * 4;
                  iVar9 = iVar4;
                } while ((*(uint *)(iVar5 + iVar10) & 0xffffff) == 0);
                *param_5 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
              }
              else {
                do {
                  iVar10 = param_6 + 1;
                  iVar9 = param_6 * 4;
                  param_6 = iVar10;
                } while ((*(uint *)(iVar5 + iVar9) & 0xffffff) <= param_3);
                *param_5 = (*(uint *)(iVar5 + iVar10 * 4 + -4) & 0xffffff) - param_3;
              }
            }
          }
        }
        else {
          iVar11 = 0x23;
          if (param_5 != (uint *)0x0) {
            param_3 = *(uint *)(iVar4 + param_6 * 4) & 0xffffff;
            if (param_3 == 0) {
              iVar9 = 0;
              do {
                iVar5 = iVar9 + 1;
                iVar10 = iVar9 * 4;
                iVar9 = iVar5;
              } while ((*(uint *)(iVar4 + iVar10) & 0xffffff) == 0);
              *param_5 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
            }
            else {
              do {
                iVar10 = param_6 + 1;
                iVar9 = param_6 * 4;
                param_6 = iVar10;
              } while ((*(uint *)(iVar4 + iVar9) & 0xffffff) <= param_3);
              *param_5 = (*(uint *)(iVar4 + iVar10 * 4 + -4) & 0xffffff) - param_3;
            }
          }
        }
      }
      else {
        iVar11 = 0x4d;
        if (param_5 != (uint *)0x0) {
          param_3 = *(uint *)(iVar5 + param_6 * 4) & 0xffffff;
          if (param_3 == 0) {
            iVar9 = 0;
            do {
              iVar4 = iVar9 + 1;
              iVar10 = iVar9 * 4;
              iVar9 = iVar4;
            } while ((*(uint *)(iVar5 + iVar10) & 0xffffff) == 0);
            *param_5 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
          }
          else {
            do {
              iVar10 = param_6 + 1;
              iVar9 = param_6 * 4;
              param_6 = iVar10;
            } while ((*(uint *)(iVar5 + iVar9) & 0xffffff) <= param_3);
            *param_5 = (*(uint *)(iVar5 + iVar10 * 4 + -4) & 0xffffff) - param_3;
          }
        }
      }
      param_3 = param_3 & 0xfffffff;
    }
  }
  else if (iVar11 == 0x4f) {
    if ((DAT_8035f528 != 0) && (iVar11 = 0x4f, param_5 != (uint *)0x0)) {
      param_3 = *(uint *)(DAT_8035f528 + param_6 * 4) & 0xffffff;
      if (param_3 == 0) {
        do {
          iVar5 = iVar10 + 1;
          iVar9 = iVar10 * 4;
          iVar10 = iVar5;
        } while ((*(uint *)(DAT_8035f528 + iVar9) & 0xffffff) == 0);
        *param_5 = *(uint *)(DAT_8035f528 + iVar5 * 4 + -4) & 0xffffff;
      }
      else {
        do {
          iVar10 = param_6 + 1;
          iVar9 = param_6 * 4;
          param_6 = iVar10;
        } while ((*(uint *)(DAT_8035f528 + iVar9) & 0xffffff) <= param_3);
        *param_5 = (*(uint *)(DAT_8035f528 + iVar10 * 4 + -4) & 0xffffff) - param_3;
      }
    }
    param_3 = param_3 & 0xfffffff;
  }
  else if ((longlong)uVar12 < 0x4f00000000) {
    if (iVar11 == 0x30) {
      FUN_8024377c();
      uVar3 = DAT_803dcc80;
      FUN_802437a4();
      if (((uVar3 & 0x40) == 0) && ((uVar3 & 0x10) == 0)) {
        iVar10 = DAT_8035f4a4;
      }
      if (((uVar3 & 0x80) == 0) && ((uVar3 & 0x20) == 0)) {
        iVar9 = DAT_8035f50c;
      }
      iVar5 = iVar9;
      iVar4 = iVar10;
      if (((param_3 & 0x10000000) == 0) || (iVar10 != 0)) {
        if (((param_3 & 0x20000000) != 0) && (iVar9 == 0)) {
          while( true ) {
            FUN_8024377c();
            uVar3 = DAT_803dcc80;
            FUN_802437a4();
            iVar5 = iVar9;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x80) == 0 && (iVar5 = DAT_8035f50c, (uVar3 & 0x20) == 0)))) break;
            FUN_80014f40();
            FUN_800202cc();
            if (bVar2) {
              FUN_8004a868();
            }
            FUN_800481d4(0);
            FUN_80015624();
            if (bVar2) {
              FUN_800234ec(0);
              FUN_80019c24();
              FUN_8004a43c(1,0);
            }
            if (DAT_803dc950 != '\0') {
              bVar2 = true;
            }
          }
        }
      }
      else {
        while( true ) {
          FUN_8024377c();
          uVar3 = DAT_803dcc80;
          FUN_802437a4();
          iVar4 = iVar10;
          if ((uVar3 == 0) || (((uVar3 & 0x40) == 0 && (iVar4 = DAT_8035f4a4, (uVar3 & 0x10) == 0)))
             ) break;
          FUN_80014f40();
          FUN_800202cc();
          if (bVar2) {
            FUN_8004a868();
          }
          FUN_800481d4(0);
          FUN_80015624();
          if (bVar2) {
            FUN_800234ec(0);
            FUN_80019c24();
            FUN_8004a43c(1,0);
          }
          if (DAT_803dc950 != '\0') {
            bVar2 = true;
          }
        }
      }
      if ((param_3 & 0x20000000) == 0) {
        if ((param_3 & 0x10000000) == 0) {
          if (iVar4 == 0) {
            if ((iVar5 != 0) && (iVar11 = 0x4a, param_5 != (uint *)0x0)) {
              *param_5 = (*(uint *)(iVar5 + param_6 * 4 + 4) & 0xfffffff) -
                         (*(uint *)(iVar5 + param_6 * 4) & 0xfffffff);
            }
          }
          else {
            iVar11 = 0x30;
            if (param_5 != (uint *)0x0) {
              *param_5 = (*(uint *)(iVar4 + param_6 * 4 + 4) & 0xfffffff) -
                         (*(uint *)(iVar4 + param_6 * 4) & 0xfffffff);
            }
          }
        }
        else {
          iVar11 = 0x30;
          if (param_5 != (uint *)0x0) {
            *param_5 = (*(uint *)(iVar4 + param_6 * 4 + 4) & 0xfffffff) -
                       (*(uint *)(iVar4 + param_6 * 4) & 0xfffffff);
          }
        }
      }
      else {
        iVar11 = 0x4a;
        if (param_5 != (uint *)0x0) {
          *param_5 = (*(uint *)(iVar5 + param_6 * 4 + 4) & 0xfffffff) -
                     (*(uint *)(iVar5 + param_6 * 4) & 0xfffffff);
        }
      }
      param_3 = param_3 & 0xfffffff;
      if ((param_7 & 1) != 0) {
        iVar9 = (&DAT_8035f3e8)[iVar11];
        iVar10 = FUN_8002a5b8(iVar9 + param_3);
        if (iVar10 != 0) {
          uVar3 = FUN_8002a5c0(iVar9 + param_3,*param_5);
          *param_5 = uVar3;
        }
      }
    }
    else if (((longlong)uVar12 < 0x3000000000) && (iVar11 == 0x2b)) {
      FUN_8024377c();
      uVar3 = DAT_803dcc80;
      FUN_802437a4();
      if (((uVar3 & 4) == 0) && ((uVar3 & 1) == 0)) {
        iVar10 = DAT_8035f490;
      }
      if (((uVar3 & 8) == 0) && ((uVar3 & 2) == 0)) {
        iVar9 = DAT_8035f4fc;
      }
      iVar5 = iVar9;
      iVar4 = iVar10;
      if (((param_3 & 0x10000000) == 0) || (iVar10 != 0)) {
        if (((param_3 & 0x20000000) != 0) && (iVar9 == 0)) {
          while( true ) {
            FUN_8024377c();
            uVar3 = DAT_803dcc80;
            FUN_802437a4();
            iVar5 = iVar9;
            if ((uVar3 == 0) || (((uVar3 & 8) == 0 && (iVar5 = DAT_8035f4fc, (uVar3 & 2) == 0))))
            break;
            FUN_80014f40();
            FUN_800202cc();
            if (bVar2) {
              FUN_8004a868();
            }
            FUN_800481d4(0);
            FUN_80015624();
            if (bVar2) {
              FUN_800234ec(0);
              FUN_80019c24();
              FUN_8004a43c(1,0);
            }
            if (DAT_803dc950 != '\0') {
              bVar2 = true;
            }
          }
        }
      }
      else {
        while( true ) {
          FUN_8024377c();
          uVar3 = DAT_803dcc80;
          FUN_802437a4();
          iVar4 = iVar10;
          if ((uVar3 == 0) || (((uVar3 & 4) == 0 && (iVar4 = DAT_8035f490, (uVar3 & 1) == 0))))
          break;
          FUN_80014f40();
          FUN_800202cc();
          if (bVar2) {
            FUN_8004a868();
          }
          FUN_800481d4(0);
          FUN_80015624();
          if (bVar2) {
            FUN_800234ec(0);
            FUN_80019c24();
            FUN_8004a43c(1,0);
          }
          if (DAT_803dc950 != '\0') {
            bVar2 = true;
          }
        }
      }
      if ((iVar5 == 0) || ((param_3 & 0x20000000) == 0)) {
        if ((iVar4 == 0) || ((param_3 & 0x10000000) == 0)) {
          if (iVar4 == 0) {
            if ((iVar5 != 0) && (iVar11 = 0x46, param_5 != (uint *)0x0)) {
              uVar3 = *(uint *)(iVar5 + param_6 * 4) & 0xffffff;
              iVar9 = 0;
              if (uVar3 == 0) {
                do {
                  iVar4 = iVar9 + 1;
                  iVar10 = iVar9 * 4;
                  iVar9 = iVar4;
                } while ((*(uint *)(iVar5 + iVar10) & 0xffffff) == 0);
                *param_5 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
              }
              else if (uVar3 < (*(uint *)(iVar5 + param_6 * 4 + -4) & 0xffffff)) {
                do {
                  iVar10 = iVar9 * 4;
                  iVar4 = iVar9 + 1;
                  iVar9 = iVar9 + 1;
                } while (uVar3 != (*(uint *)(iVar5 + iVar10) & 0xffffff));
                do {
                  iVar10 = iVar4 + 1;
                  iVar9 = iVar4 * 4;
                  iVar4 = iVar10;
                } while ((*(uint *)(iVar5 + iVar9) & 0xffffff) <= uVar3);
                *param_5 = (*(uint *)(iVar5 + iVar10 * 4 + -4) & 0xffffff) - uVar3;
              }
              else {
                do {
                  iVar10 = param_6 + 1;
                  iVar9 = param_6 * 4;
                  param_6 = iVar10;
                } while ((*(uint *)(iVar5 + iVar9) & 0xffffff) <= uVar3);
                *param_5 = (*(uint *)(iVar5 + iVar10 * 4 + -4) & 0xffffff) - uVar3;
              }
            }
          }
          else {
            iVar11 = 0x2b;
            if (param_5 != (uint *)0x0) {
              uVar3 = *(uint *)(iVar4 + param_6 * 4) & 0xffffff;
              iVar9 = 0;
              if (uVar3 == 0) {
                do {
                  iVar5 = iVar9 + 1;
                  iVar10 = iVar9 * 4;
                  iVar9 = iVar5;
                } while ((*(uint *)(iVar4 + iVar10) & 0xffffff) == 0);
                *param_5 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
              }
              else if (uVar3 < (*(uint *)(iVar4 + param_6 * 4 + -4) & 0xffffff)) {
                do {
                  iVar10 = iVar9 * 4;
                  iVar5 = iVar9 + 1;
                  iVar9 = iVar9 + 1;
                } while (uVar3 != (*(uint *)(iVar4 + iVar10) & 0xffffff));
                do {
                  iVar10 = iVar5 + 1;
                  iVar9 = iVar5 * 4;
                  iVar5 = iVar10;
                } while ((*(uint *)(iVar4 + iVar9) & 0xffffff) <= uVar3);
                *param_5 = (*(uint *)(iVar4 + iVar10 * 4 + -4) & 0xffffff) - uVar3;
              }
              else {
                do {
                  iVar10 = param_6 + 1;
                  iVar9 = param_6 * 4;
                  param_6 = iVar10;
                } while ((*(uint *)(iVar4 + iVar9) & 0xffffff) <= uVar3);
                *param_5 = (*(uint *)(iVar4 + iVar10 * 4 + -4) & 0xffffff) - uVar3;
              }
            }
          }
        }
        else {
          iVar11 = 0x2b;
          if (param_5 != (uint *)0x0) {
            uVar3 = *(uint *)(iVar4 + param_6 * 4) & 0xffffff;
            iVar9 = 0;
            if (uVar3 == 0) {
              do {
                iVar5 = iVar9 + 1;
                iVar10 = iVar9 * 4;
                iVar9 = iVar5;
              } while ((*(uint *)(iVar4 + iVar10) & 0xffffff) == 0);
              *param_5 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
            }
            else if (uVar3 < (*(uint *)(iVar4 + param_6 * 4 + -4) & 0xffffff)) {
              do {
                iVar10 = iVar9 * 4;
                iVar5 = iVar9 + 1;
                iVar9 = iVar9 + 1;
              } while (uVar3 != (*(uint *)(iVar4 + iVar10) & 0xffffff));
              do {
                iVar10 = iVar5 + 1;
                iVar9 = iVar5 * 4;
                iVar5 = iVar10;
              } while ((*(uint *)(iVar4 + iVar9) & 0xffffff) <= uVar3);
              *param_5 = (*(uint *)(iVar4 + iVar10 * 4 + -4) & 0xffffff) - uVar3;
            }
            else {
              do {
                iVar10 = param_6 + 1;
                iVar9 = param_6 * 4;
                param_6 = iVar10;
              } while ((*(uint *)(iVar4 + iVar9) & 0xffffff) <= uVar3);
              *param_5 = (*(uint *)(iVar4 + iVar10 * 4 + -4) & 0xffffff) - uVar3;
            }
          }
        }
      }
      else {
        iVar11 = 0x46;
        if (param_5 != (uint *)0x0) {
          uVar3 = *(uint *)(iVar5 + param_6 * 4) & 0xffffff;
          iVar9 = 0;
          if (uVar3 == 0) {
            do {
              iVar4 = iVar9 + 1;
              iVar10 = iVar9 * 4;
              iVar9 = iVar4;
            } while ((*(uint *)(iVar5 + iVar10) & 0xffffff) == 0);
            *param_5 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
          }
          else if (uVar3 < (*(uint *)(iVar5 + param_6 * 4 + -4) & 0xffffff)) {
            iVar9 = 0;
            do {
              iVar10 = iVar9 * 4;
              iVar4 = iVar9 + 1;
              iVar9 = iVar9 + 1;
            } while (uVar3 != (*(uint *)(iVar5 + iVar10) & 0xffffff));
            do {
              iVar10 = iVar4 + 1;
              iVar9 = iVar4 * 4;
              iVar4 = iVar10;
            } while ((*(uint *)(iVar5 + iVar9) & 0xffffff) <= uVar3);
            *param_5 = (*(uint *)(iVar5 + iVar10 * 4 + -4) & 0xffffff) - uVar3;
          }
          else {
            do {
              iVar10 = param_6 + 1;
              iVar9 = param_6 * 4;
              param_6 = iVar10;
            } while ((*(uint *)(iVar5 + iVar9) & 0xffffff) <= uVar3);
            *param_5 = (*(uint *)(iVar5 + iVar10 * 4 + -4) & 0xffffff) - uVar3;
          }
        }
      }
      param_3 = param_3 & 0xfffffff;
    }
  }
  else if (iVar11 == 0x51) {
    if ((DAT_8035f530 != 0) && (iVar11 = 0x51, param_5 != (uint *)0x0)) {
      *param_5 = (*(uint *)(DAT_8035f530 + param_6 * 4 + 4) & 0xfffffff) -
                 (*(uint *)(DAT_8035f530 + param_6 * 4) & 0xfffffff);
    }
    param_3 = param_3 & 0xfffffff;
    if ((param_7 & 1) != 0) {
      iVar9 = (&DAT_8035f3e8)[iVar11];
      iVar10 = FUN_8002a5b8(iVar9 + param_3);
      if (iVar10 != 0) {
        uVar3 = FUN_8002a5c0(iVar9 + param_3,*param_5);
        *param_5 = uVar3;
      }
    }
  }
  if ((param_7 & 1) != 0) {
    iVar9 = 0;
    goto LAB_80048198;
  }
  iVar9 = (&DAT_8035f3e8)[iVar11];
  if (iVar9 == 0) {
    if ((iVar11 == 0x20) || (iVar11 == 0x4b)) {
      FUN_80248b9c((&PTR_s_AUDIO_tab_802cb2f4)[iVar11],auStack116);
      uVar3 = param_4 + 0x1f & 0xffffffe0;
      iVar9 = FUN_80023cc8(uVar3,0x7f7f7fff,0);
      FUN_80015850(auStack116,iVar9,uVar3,param_3 & 0xffffff);
      FUN_80248c64(auStack116);
      FUN_80241a1c(iVar9,param_4);
      iVar10 = FUN_80291614(&DAT_803db5c4,iVar9,3);
      if (iVar10 == 0) {
        do {
                    /* WARNING: Do nothing block with infinite loop */
        } while( true );
      }
      iVar10 = FUN_80291614(iVar9,&DAT_803db5c0,3);
      if (iVar10 == 0) {
        local_78 = *(undefined4 *)(iVar9 + 8);
        FUN_8004b658(iVar9 + 0x10,*(undefined4 *)(iVar9 + 0xc),uVar7,&local_78);
      }
      FUN_80023800(iVar9);
    }
    else {
      FUN_80248b9c((&PTR_s_AUDIO_tab_802cb2f4)[iVar11],auStack116);
      if (((uVar12 & 0x1f) == 0) && ((param_4 & 0x1f) == 0)) {
        FUN_80015850(auStack116,uVar7,param_4,param_3);
      }
      else {
        uVar3 = param_4 + 0x1f & 0xffffffe0;
        uVar6 = FUN_80023cc8(uVar3,0x7f7f7fff,0);
        FUN_80015850(auStack116,uVar6,uVar3,param_3);
        FUN_80003494(uVar7,uVar6,param_4);
        FUN_80023800(uVar6);
      }
      FUN_80241a1c(uVar7,param_4);
      FUN_80248c64(auStack116);
    }
  }
  else if ((iVar11 == 0xd) || (iVar11 == 0x55)) {
    if (iVar9 == 0) {
      iVar9 = 0;
      goto LAB_80048198;
    }
    FUN_80003494(uVar7,iVar9 + param_3,param_4);
  }
  else if ((iVar11 == 0x1b) || (iVar11 == 0x54)) {
    if (iVar9 == 0) {
      iVar9 = 0;
      goto LAB_80048198;
    }
    iVar9 = iVar9 + param_3;
    iVar10 = FUN_80291614(iVar9,&DAT_803db5c0,3);
    if (iVar10 != 0) {
      iVar9 = 0;
      goto LAB_80048198;
    }
    local_78 = *(undefined4 *)(iVar9 + 8);
    FUN_8004b658((&DAT_8035f3e8)[iVar11] + param_3 + 0x10,*(undefined4 *)(iVar9 + 0xc),uVar7,
                 &local_78);
    FUN_80241a1c(uVar7,local_78);
  }
  else if ((iVar11 == 0x25) || (iVar11 == 0x47)) {
    if (iVar9 == 0) {
      iVar9 = 0;
      goto LAB_80048198;
    }
    iVar9 = iVar9 + param_3;
    iVar10 = FUN_80291614(iVar9,&DAT_803db5c0,3);
    if (iVar10 != 0) {
      iVar9 = 0;
      goto LAB_80048198;
    }
    local_78 = *(undefined4 *)(iVar9 + 8);
    FUN_8004b658((&DAT_8035f3e8)[iVar11] + param_3 + 0x10,*(undefined4 *)(iVar9 + 0xc),uVar7,
                 &local_78);
    FUN_80241a1c(uVar7,local_78);
  }
  else if ((iVar11 == 0x2b) || (iVar11 == 0x46)) {
    piVar8 = (int *)(iVar9 + param_3);
    if (*piVar8 == -0x1f1f1f20) {
      FUN_80003494(uVar7,(int)piVar8 + piVar8[2] + 0x18,piVar8[1]);
    }
    else if (*piVar8 == -0x5310113) {
      FUN_8004b658((int)piVar8 + piVar8[2] + 0x28,piVar8[3] + -0x10,uVar7,piVar8 + 1);
      FUN_80241a1c(uVar7,piVar8[1]);
    }
  }
  else if ((iVar11 == 0x23) || (iVar11 == 0x4d)) {
    iVar9 = iVar9 + (param_3 & 0xffffff);
    local_78 = *(undefined4 *)(iVar9 + 8);
    FUN_8004b658(iVar9 + 0x10,*(undefined4 *)(iVar9 + 0xc),uVar7,&local_78);
    FUN_80241a1c(uVar7,local_78);
  }
  else if ((iVar11 == 0x20) || (iVar11 == 0x4b)) {
    param_3 = param_3 & 0xffffff;
    iVar9 = iVar9 + param_3;
    iVar10 = FUN_80291614(&DAT_803db5c4,iVar9,3);
    if (iVar10 == 0) {
      iVar9 = (&DAT_8035f3e8)[iVar11] + param_3 + 0x20;
      goto LAB_80048198;
    }
    iVar10 = FUN_80291614(iVar9,&DAT_803db5c0,3);
    if (iVar10 == 0) {
      local_78 = *(undefined4 *)(iVar9 + 8);
      FUN_8004b658((&DAT_8035f3e8)[iVar11] + param_3 + 0x10,*(undefined4 *)(iVar9 + 0xc),uVar7,
                   &local_78);
      FUN_80241a1c(uVar7,local_78);
    }
  }
  else if (iVar11 == 0x4f) {
    param_3 = param_3 & 0xffffff;
    iVar9 = iVar9 + param_3;
    iVar10 = FUN_80291614(&DAT_803db5c4,iVar9,3);
    if (iVar10 == 0) {
      iVar9 = (&DAT_8035f3e8)[0x4f] + param_3 + 0x20;
      goto LAB_80048198;
    }
    iVar10 = FUN_80291614(iVar9,&DAT_803db5c0,3);
    if (iVar10 == 0) {
      local_78 = *(undefined4 *)(iVar9 + 8);
      FUN_8004b658((&DAT_8035f3e8)[0x4f] + param_3 + 0x10,*(undefined4 *)(iVar9 + 0xc),uVar7,
                   &local_78);
      FUN_80241a1c(uVar7,local_78);
    }
  }
  else if (((iVar11 == 0x30) || (iVar11 == 0x51)) || (iVar11 == 0x4a)) {
    iVar9 = iVar9 + param_3;
    iVar10 = FUN_8002a5b8(iVar9);
    if (iVar10 == 0) {
      FUN_80003494(uVar7,(&DAT_8035f3e8)[iVar11] + param_3,param_4);
    }
    else {
      uVar6 = FUN_8002a5c0(iVar9,*param_5);
      FUN_8002a444(iVar9,*param_5,uVar7,uVar6);
    }
  }
  else {
    FUN_80003494(uVar7,iVar9 + param_3,param_4);
  }
  iVar9 = 0;
LAB_80048198:
  FUN_80286108(iVar9);
  return;
}

