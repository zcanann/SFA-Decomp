// Function: FUN_80046644
// Entry: 80046644
// Size: 7400 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80046644(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint *param_13,
                 int param_14,uint param_15,undefined4 param_16)

{
  bool bVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  ushort *puVar7;
  uint *puVar8;
  uint uVar9;
  int *piVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined8 extraout_f1;
  undefined8 uVar15;
  ulonglong uVar16;
  int aiStack_74 [29];
  
  uVar16 = FUN_80286820();
  iVar14 = (int)(uVar16 >> 0x20);
  puVar7 = (ushort *)uVar16;
  iVar12 = 0;
  iVar11 = 0;
  bVar2 = false;
  puVar8 = param_13;
  uVar9 = param_15;
  uVar15 = extraout_f1;
  if (iVar14 == 0x25) {
    FUN_80243e74();
    uVar3 = DAT_803dd900;
    FUN_80243e9c();
    if (((uVar3 & 0x20000) == 0) && ((uVar3 & 0x10000) == 0)) {
      iVar12 = DAT_803600e0;
    }
    if (((uVar3 & 0x80000) == 0) && ((uVar3 & 0x40000) == 0)) {
      iVar11 = DAT_80360168;
    }
    if (((param_11 & 0x20000000) == 0) || (iVar11 == 0)) {
      if (((param_11 & 0x10000000) == 0) || (iVar12 == 0)) {
        if (iVar12 == 0) {
          if (iVar11 != 0) {
            iVar14 = 0x47;
          }
        }
        else {
          iVar14 = 0x25;
        }
      }
      else {
        iVar14 = 0x25;
      }
    }
    else {
      iVar14 = 0x47;
    }
    param_11 = param_11 & 0xfffffff;
  }
  else if ((longlong)uVar16 < 0x2500000000) {
    if (iVar14 == 0x20) {
      iVar13 = param_14;
      FUN_80243e74();
      uVar3 = DAT_803dd900;
      FUN_80243e9c();
      if (((uVar3 & 0x4000) == 0) && ((uVar3 & 0x1000) == 0)) {
        iVar12 = DAT_803600cc;
      }
      if (((uVar3 & 0x8000) == 0) && ((uVar3 & 0x2000) == 0)) {
        iVar11 = DAT_80360178;
      }
      iVar5 = iVar11;
      iVar4 = iVar12;
      if (((param_11 & 0x40000000) == 0) || (iVar12 != 0)) {
        if (((param_11 & 0x80000000) != 0) && (iVar11 == 0)) {
          while( true ) {
            FUN_80243e74();
            uVar3 = DAT_803dd900;
            FUN_80243e9c();
            iVar5 = iVar11;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x8000) == 0 && (iVar5 = DAT_80360178, (uVar3 & 0x2000) == 0)))) break;
            uVar15 = FUN_80014f6c();
            FUN_80020390();
            if (bVar2) {
              uVar15 = FUN_8004a9e4();
            }
            uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if (bVar2) {
              uVar15 = FUN_800235b0();
              uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_8004a5b8('\x01');
            }
            if (DAT_803dd5d0 != '\0') {
              bVar2 = true;
            }
          }
        }
      }
      else {
        while( true ) {
          FUN_80243e74();
          uVar3 = DAT_803dd900;
          FUN_80243e9c();
          iVar4 = iVar12;
          if ((uVar3 == 0) ||
             ((bVar1 = (uVar3 & 0x1000) == 0, bVar1 && (iVar4 = DAT_803600cc, bVar1)))) break;
          uVar15 = FUN_80014f6c();
          FUN_80020390();
          if (bVar2) {
            uVar15 = FUN_8004a9e4();
          }
          uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          if (bVar2) {
            uVar15 = FUN_800235b0();
            uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_8004a5b8('\x01');
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
      }
      if ((iVar5 == 0) || ((*(uint *)(&DAT_80352c70 + param_14 * 4) & 0x80000000) == 0)) {
        if ((iVar4 == 0) || ((*(uint *)(&DAT_80352c70 + param_14 * 4) & 0x40000000) == 0)) {
          if (iVar5 == 0) {
            if ((iVar4 != 0) && (iVar14 = 0x20, param_13 != (uint *)0x0)) {
              param_11 = *(uint *)(iVar4 + param_14 * 4) & 0xffffff;
              if (param_11 == 0) {
                iVar11 = 0;
                do {
                  iVar5 = iVar11 + 1;
                  iVar12 = iVar11 * 4;
                  iVar11 = iVar5;
                } while ((*(uint *)(iVar4 + iVar12) & 0xffffff) == 0);
                *param_13 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
              }
              else {
                do {
                  iVar12 = param_14 + 1;
                  iVar11 = param_14 * 4;
                  param_14 = iVar12;
                } while ((*(uint *)(iVar4 + iVar11) & 0xffffff) <= param_11);
                *param_13 = (*(uint *)(iVar4 + iVar12 * 4 + -4) & 0xffffff) - param_11;
              }
            }
          }
          else {
            iVar14 = 0x4b;
            if (param_13 != (uint *)0x0) {
              param_11 = *(uint *)(iVar5 + param_14 * 4) & 0xffffff;
              if (param_11 == 0) {
                iVar11 = 0;
                do {
                  iVar4 = iVar11 + 1;
                  iVar12 = iVar11 * 4;
                  iVar11 = iVar4;
                } while ((*(uint *)(iVar5 + iVar12) & 0xffffff) == 0);
                *param_13 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
              }
              else {
                do {
                  iVar12 = param_14 + 1;
                  iVar11 = param_14 * 4;
                  param_14 = iVar12;
                } while ((*(uint *)(iVar5 + iVar11) & 0xffffff) <= param_11);
                *param_13 = (*(uint *)(iVar5 + iVar12 * 4 + -4) & 0xffffff) - param_11;
              }
            }
          }
        }
        else {
          iVar14 = 0x20;
          if (param_13 != (uint *)0x0) {
            param_11 = *(uint *)(iVar4 + param_14 * 4) & 0xffffff;
            if (param_11 == 0) {
              iVar11 = 0;
              do {
                iVar5 = iVar11 + 1;
                iVar12 = iVar11 * 4;
                iVar11 = iVar5;
              } while ((*(uint *)(iVar4 + iVar12) & 0xffffff) == 0);
              *param_13 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
            }
            else {
              do {
                iVar12 = param_14 + 1;
                iVar11 = param_14 * 4;
                param_14 = iVar12;
              } while ((*(uint *)(iVar4 + iVar11) & 0xffffff) <= param_11);
              *param_13 = (*(uint *)(iVar4 + iVar12 * 4 + -4) & 0xffffff) - param_11;
            }
          }
        }
      }
      else {
        iVar14 = 0x4b;
        if (param_13 != (uint *)0x0) {
          param_11 = *(uint *)(iVar5 + param_14 * 4) & 0xffffff;
          if (param_11 == 0) {
            iVar11 = 0;
            do {
              iVar4 = iVar11 + 1;
              iVar12 = iVar11 * 4;
              iVar11 = iVar4;
            } while ((*(uint *)(iVar5 + iVar12) & 0xffffff) == 0);
            *param_13 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
          }
          else {
            do {
              iVar12 = param_14 + 1;
              iVar11 = param_14 * 4;
              param_14 = iVar12;
            } while ((*(uint *)(iVar5 + iVar11) & 0xffffff) <= param_11);
            *param_13 = (*(uint *)(iVar5 + iVar12 * 4 + -4) & 0xffffff) - param_11;
          }
        }
      }
      param_11 = param_11 & 0xfffffff;
      param_14 = iVar13;
    }
    else if ((longlong)uVar16 < 0x2000000000) {
      if (iVar14 == 0x1b) {
        FUN_80243e74();
        uVar3 = DAT_803dd900;
        FUN_80243e9c();
        if (((uVar3 & 0x2000000) == 0) && ((uVar3 & 0x1000000) == 0)) {
          iVar12 = DAT_803600b0;
        }
        if (((uVar3 & 0x8000000) == 0) && ((uVar3 & 0x4000000) == 0)) {
          iVar11 = DAT_80360194;
        }
        iVar13 = iVar11;
        iVar5 = iVar12;
        if (((param_11 & 0x80000000) == 0) || (iVar12 != 0)) {
          if (((param_11 & 0x20000000) != 0) && (iVar11 == 0)) {
            while( true ) {
              FUN_80243e74();
              uVar3 = DAT_803dd900;
              FUN_80243e9c();
              iVar13 = iVar11;
              if ((uVar3 == 0) ||
                 (((uVar3 & 0x8000000) == 0 && (iVar13 = DAT_80360194, (uVar3 & 0x4000000) == 0))))
              break;
              uVar15 = FUN_80014f6c();
              FUN_80020390();
              if (bVar2) {
                uVar15 = FUN_8004a9e4();
              }
              uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              if (bVar2) {
                uVar15 = FUN_800235b0();
                uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                     );
                FUN_8004a5b8('\x01');
              }
              if (DAT_803dd5d0 != '\0') {
                bVar2 = true;
              }
            }
          }
        }
        else {
          while( true ) {
            FUN_80243e74();
            uVar3 = DAT_803dd900;
            FUN_80243e9c();
            iVar5 = iVar12;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x2000000) == 0 && (iVar5 = DAT_803600b0, (uVar3 & 0x1000000) == 0))))
            break;
            uVar15 = FUN_80014f6c();
            FUN_80020390();
            if (bVar2) {
              uVar15 = FUN_8004a9e4();
            }
            uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if (bVar2) {
              uVar15 = FUN_800235b0();
              uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_8004a5b8('\x01');
            }
            if (DAT_803dd5d0 != '\0') {
              bVar2 = true;
            }
          }
        }
        if (((param_11 & 0x20000000) == 0) || (iVar13 == 0)) {
          if (((param_11 & 0x80000000) == 0) || (iVar5 == 0)) {
            if (iVar5 == 0) {
              if (iVar13 != 0) {
                iVar14 = 0x54;
              }
            }
            else {
              iVar14 = 0x1b;
            }
          }
          else {
            iVar14 = 0x1b;
          }
        }
        else {
          iVar14 = 0x54;
        }
        param_11 = param_11 & 0xfffffff;
      }
      else if (((longlong)uVar16 < 0x1b00000000) && (iVar14 == 0xd)) {
        FUN_80243e74();
        uVar3 = DAT_803dd900;
        FUN_80243e9c();
        if (((uVar3 & 0x20000000) == 0) && ((uVar3 & 0x10000000) == 0)) {
          iVar12 = DAT_80360080;
        }
        if (((uVar3 & 0x80000000) == 0) && ((uVar3 & 0x40000000) == 0)) {
          iVar11 = DAT_803601a0;
        }
        iVar13 = iVar11;
        iVar5 = iVar12;
        if (((param_11 & 0x80000000) == 0) || (iVar12 != 0)) {
          if (((param_11 & 0x20000000) != 0) && (iVar11 == 0)) {
            while( true ) {
              FUN_80243e74();
              uVar3 = DAT_803dd900;
              FUN_80243e9c();
              iVar13 = iVar11;
              if ((uVar3 == 0) ||
                 (((uVar3 & 0x80000000) == 0 && (iVar13 = DAT_80360048, (uVar3 & 0x40000000) == 0)))
                 ) break;
              uVar15 = FUN_80014f6c();
              FUN_80020390();
              if (bVar2) {
                uVar15 = FUN_8004a9e4();
              }
              uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              if (bVar2) {
                uVar15 = FUN_800235b0();
                uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                     );
                FUN_8004a5b8('\x01');
              }
              if (DAT_803dd5d0 != '\0') {
                bVar2 = true;
              }
            }
          }
        }
        else {
          while( true ) {
            FUN_80243e74();
            uVar3 = DAT_803dd900;
            FUN_80243e9c();
            iVar5 = iVar12;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x20000000) == 0 && (iVar5 = _DAT_00360048, (uVar3 & 0x10000000) == 0))))
            break;
            uVar15 = FUN_80014f6c();
            FUN_80020390();
            if (bVar2) {
              uVar15 = FUN_8004a9e4();
            }
            uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if (bVar2) {
              uVar15 = FUN_800235b0();
              uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_8004a5b8('\x01');
            }
            if (DAT_803dd5d0 != '\0') {
              bVar2 = true;
            }
          }
        }
        if (((param_11 & 0x20000000) == 0) || (iVar13 == 0)) {
          if (((param_11 & 0x80000000) == 0) || (iVar5 == 0)) {
            if (iVar5 == 0) {
              if (iVar13 != 0) {
                iVar14 = 0x55;
              }
            }
            else {
              iVar14 = 0xd;
            }
          }
          else {
            iVar14 = 0xd;
          }
        }
        else {
          iVar14 = 0x55;
        }
        param_11 = param_11 & 0xfffffff;
      }
    }
    else if (iVar14 == 0x23) {
      iVar13 = param_14;
      FUN_80243e74();
      uVar3 = DAT_803dd900;
      FUN_80243e9c();
      bVar1 = (uVar3 & 0x100) == 0;
      if ((bVar1) && (bVar1)) {
        iVar12 = DAT_803600d8;
      }
      if (((uVar3 & 0x800) == 0) && ((uVar3 & 0x200) == 0)) {
        iVar11 = DAT_80360180;
      }
      iVar5 = iVar11;
      iVar4 = iVar12;
      if (((param_11 & 0x40000000) == 0) || (iVar12 != 0)) {
        if (((param_11 & 0x80000000) != 0) && (iVar11 == 0)) {
          while( true ) {
            FUN_80243e74();
            uVar3 = DAT_803dd900;
            FUN_80243e9c();
            iVar5 = iVar11;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x800) == 0 && (iVar5 = DAT_80360180, (uVar3 & 0x200) == 0)))) break;
            uVar15 = FUN_80014f6c();
            FUN_80020390();
            if (bVar2) {
              uVar15 = FUN_8004a9e4();
            }
            uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if (bVar2) {
              uVar15 = FUN_800235b0();
              uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_8004a5b8('\x01');
            }
            if (DAT_803dd5d0 != '\0') {
              bVar2 = true;
            }
          }
        }
      }
      else {
        while( true ) {
          FUN_80243e74();
          uVar3 = DAT_803dd900;
          FUN_80243e9c();
          iVar4 = iVar12;
          if ((uVar3 == 0) ||
             ((bVar1 = (uVar3 & 0x100) == 0, bVar1 && (iVar4 = DAT_803600d8, bVar1)))) break;
          uVar15 = FUN_80014f6c();
          FUN_80020390();
          if (bVar2) {
            uVar15 = FUN_8004a9e4();
          }
          uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          if (bVar2) {
            uVar15 = FUN_800235b0();
            uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_8004a5b8('\x01');
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
      }
      if ((iVar5 == 0) || ((*(uint *)(&DAT_80356c70 + param_14 * 4) & 0x80000000) == 0)) {
        if ((iVar4 == 0) || ((*(uint *)(&DAT_80356c70 + param_14 * 4) & 0x40000000) == 0)) {
          if (iVar5 == 0) {
            if ((iVar4 != 0) && (iVar14 = 0x23, param_13 != (uint *)0x0)) {
              param_11 = *(uint *)(iVar4 + param_14 * 4) & 0xffffff;
              if (param_11 == 0) {
                iVar11 = 0;
                do {
                  iVar5 = iVar11 + 1;
                  iVar12 = iVar11 * 4;
                  iVar11 = iVar5;
                } while ((*(uint *)(iVar4 + iVar12) & 0xffffff) == 0);
                *param_13 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
              }
              else {
                do {
                  iVar12 = param_14 + 1;
                  iVar11 = param_14 * 4;
                  param_14 = iVar12;
                } while ((*(uint *)(iVar4 + iVar11) & 0xffffff) <= param_11);
                *param_13 = (*(uint *)(iVar4 + iVar12 * 4 + -4) & 0xffffff) - param_11;
              }
            }
          }
          else {
            iVar14 = 0x4d;
            if (param_13 != (uint *)0x0) {
              param_11 = *(uint *)(iVar5 + param_14 * 4) & 0xffffff;
              if (param_11 == 0) {
                iVar11 = 0;
                do {
                  iVar4 = iVar11 + 1;
                  iVar12 = iVar11 * 4;
                  iVar11 = iVar4;
                } while ((*(uint *)(iVar5 + iVar12) & 0xffffff) == 0);
                *param_13 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
              }
              else {
                do {
                  iVar12 = param_14 + 1;
                  iVar11 = param_14 * 4;
                  param_14 = iVar12;
                } while ((*(uint *)(iVar5 + iVar11) & 0xffffff) <= param_11);
                *param_13 = (*(uint *)(iVar5 + iVar12 * 4 + -4) & 0xffffff) - param_11;
              }
            }
          }
        }
        else {
          iVar14 = 0x23;
          if (param_13 != (uint *)0x0) {
            param_11 = *(uint *)(iVar4 + param_14 * 4) & 0xffffff;
            if (param_11 == 0) {
              iVar11 = 0;
              do {
                iVar5 = iVar11 + 1;
                iVar12 = iVar11 * 4;
                iVar11 = iVar5;
              } while ((*(uint *)(iVar4 + iVar12) & 0xffffff) == 0);
              *param_13 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
            }
            else {
              do {
                iVar12 = param_14 + 1;
                iVar11 = param_14 * 4;
                param_14 = iVar12;
              } while ((*(uint *)(iVar4 + iVar11) & 0xffffff) <= param_11);
              *param_13 = (*(uint *)(iVar4 + iVar12 * 4 + -4) & 0xffffff) - param_11;
            }
          }
        }
      }
      else {
        iVar14 = 0x4d;
        if (param_13 != (uint *)0x0) {
          param_11 = *(uint *)(iVar5 + param_14 * 4) & 0xffffff;
          if (param_11 == 0) {
            iVar11 = 0;
            do {
              iVar4 = iVar11 + 1;
              iVar12 = iVar11 * 4;
              iVar11 = iVar4;
            } while ((*(uint *)(iVar5 + iVar12) & 0xffffff) == 0);
            *param_13 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
          }
          else {
            do {
              iVar12 = param_14 + 1;
              iVar11 = param_14 * 4;
              param_14 = iVar12;
            } while ((*(uint *)(iVar5 + iVar11) & 0xffffff) <= param_11);
            *param_13 = (*(uint *)(iVar5 + iVar12 * 4 + -4) & 0xffffff) - param_11;
          }
        }
      }
      param_11 = param_11 & 0xfffffff;
      param_14 = iVar13;
    }
  }
  else if (iVar14 == 0x4f) {
    if ((DAT_80360188 != 0) && (iVar14 = 0x4f, param_13 != (uint *)0x0)) {
      param_11 = *(uint *)(DAT_80360188 + param_14 * 4) & 0xffffff;
      iVar11 = param_14;
      if (param_11 == 0) {
        do {
          iVar13 = iVar12 + 1;
          iVar11 = iVar12 * 4;
          iVar12 = iVar13;
        } while ((*(uint *)(DAT_80360188 + iVar11) & 0xffffff) == 0);
        *param_13 = *(uint *)(DAT_80360188 + iVar13 * 4 + -4) & 0xffffff;
      }
      else {
        do {
          iVar13 = iVar11 + 1;
          iVar12 = iVar11 * 4;
          iVar11 = iVar13;
        } while ((*(uint *)(DAT_80360188 + iVar12) & 0xffffff) <= param_11);
        *param_13 = (*(uint *)(DAT_80360188 + iVar13 * 4 + -4) & 0xffffff) - param_11;
      }
    }
    param_11 = param_11 & 0xfffffff;
  }
  else if ((longlong)uVar16 < 0x4f00000000) {
    if (iVar14 == 0x30) {
      iVar13 = param_14;
      FUN_80243e74();
      uVar3 = DAT_803dd900;
      FUN_80243e9c();
      if (((uVar3 & 0x40) == 0) && ((uVar3 & 0x10) == 0)) {
        iVar12 = DAT_80360104;
      }
      if (((uVar3 & 0x80) == 0) && ((uVar3 & 0x20) == 0)) {
        iVar11 = DAT_8036016c;
      }
      iVar5 = iVar11;
      iVar4 = iVar12;
      if (((param_11 & 0x10000000) == 0) || (iVar12 != 0)) {
        if (((param_11 & 0x20000000) != 0) && (iVar11 == 0)) {
          while( true ) {
            FUN_80243e74();
            uVar3 = DAT_803dd900;
            FUN_80243e9c();
            iVar5 = iVar11;
            if ((uVar3 == 0) ||
               (((uVar3 & 0x80) == 0 && (iVar5 = DAT_8036016c, (uVar3 & 0x20) == 0)))) break;
            uVar15 = FUN_80014f6c();
            FUN_80020390();
            if (bVar2) {
              uVar15 = FUN_8004a9e4();
            }
            uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if (bVar2) {
              uVar15 = FUN_800235b0();
              uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_8004a5b8('\x01');
            }
            if (DAT_803dd5d0 != '\0') {
              bVar2 = true;
            }
          }
        }
      }
      else {
        while( true ) {
          FUN_80243e74();
          uVar3 = DAT_803dd900;
          FUN_80243e9c();
          iVar4 = iVar12;
          if ((uVar3 == 0) || (((uVar3 & 0x40) == 0 && (iVar4 = DAT_80360104, (uVar3 & 0x10) == 0)))
             ) break;
          uVar15 = FUN_80014f6c();
          FUN_80020390();
          if (bVar2) {
            uVar15 = FUN_8004a9e4();
          }
          uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          if (bVar2) {
            uVar15 = FUN_800235b0();
            uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_8004a5b8('\x01');
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
      }
      if ((param_11 & 0x20000000) == 0) {
        if ((param_11 & 0x10000000) == 0) {
          if (iVar4 == 0) {
            if ((iVar5 != 0) && (iVar14 = 0x4a, param_13 != (uint *)0x0)) {
              *param_13 = (*(uint *)(iVar5 + param_14 * 4 + 4) & 0xfffffff) -
                          (*(uint *)(iVar5 + param_14 * 4) & 0xfffffff);
            }
          }
          else {
            iVar14 = 0x30;
            if (param_13 != (uint *)0x0) {
              *param_13 = (*(uint *)(iVar4 + param_14 * 4 + 4) & 0xfffffff) -
                          (*(uint *)(iVar4 + param_14 * 4) & 0xfffffff);
            }
          }
        }
        else {
          iVar14 = 0x30;
          if (param_13 != (uint *)0x0) {
            *param_13 = (*(uint *)(iVar4 + param_14 * 4 + 4) & 0xfffffff) -
                        (*(uint *)(iVar4 + param_14 * 4) & 0xfffffff);
          }
        }
      }
      else {
        iVar14 = 0x4a;
        if (param_13 != (uint *)0x0) {
          *param_13 = (*(uint *)(iVar5 + param_14 * 4 + 4) & 0xfffffff) -
                      (*(uint *)(iVar5 + param_14 * 4) & 0xfffffff);
        }
      }
      param_11 = param_11 & 0xfffffff;
      param_14 = iVar13;
      if ((param_15 & 1) != 0) {
        iVar11 = (&DAT_80360048)[iVar14];
        iVar12 = FUN_8002a690();
        param_14 = iVar13;
        if (iVar12 != 0) {
          uVar3 = FUN_8002a698(iVar11 + param_11,*param_13);
          *param_13 = uVar3;
          param_14 = iVar13;
        }
      }
    }
    else if (((longlong)uVar16 < 0x3000000000) && (iVar14 == 0x2b)) {
      iVar13 = param_14;
      FUN_80243e74();
      uVar3 = DAT_803dd900;
      FUN_80243e9c();
      if (((uVar3 & 4) == 0) && ((uVar3 & 1) == 0)) {
        iVar12 = DAT_803600f0;
      }
      if (((uVar3 & 8) == 0) && ((uVar3 & 2) == 0)) {
        iVar11 = DAT_8036015c;
      }
      iVar5 = iVar11;
      iVar4 = iVar12;
      if (((param_11 & 0x10000000) == 0) || (iVar12 != 0)) {
        if (((param_11 & 0x20000000) != 0) && (iVar11 == 0)) {
          while( true ) {
            FUN_80243e74();
            uVar3 = DAT_803dd900;
            FUN_80243e9c();
            iVar5 = iVar11;
            if ((uVar3 == 0) || (((uVar3 & 8) == 0 && (iVar5 = DAT_8036015c, (uVar3 & 2) == 0))))
            break;
            uVar15 = FUN_80014f6c();
            FUN_80020390();
            if (bVar2) {
              uVar15 = FUN_8004a9e4();
            }
            uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if (bVar2) {
              uVar15 = FUN_800235b0();
              uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              FUN_8004a5b8('\x01');
            }
            if (DAT_803dd5d0 != '\0') {
              bVar2 = true;
            }
          }
        }
      }
      else {
        while( true ) {
          FUN_80243e74();
          uVar3 = DAT_803dd900;
          FUN_80243e9c();
          iVar4 = iVar12;
          if ((uVar3 == 0) || (((uVar3 & 4) == 0 && (iVar4 = DAT_803600f0, (uVar3 & 1) == 0))))
          break;
          uVar15 = FUN_80014f6c();
          FUN_80020390();
          if (bVar2) {
            uVar15 = FUN_8004a9e4();
          }
          uVar15 = FUN_80048350(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          FUN_80015650(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          if (bVar2) {
            uVar15 = FUN_800235b0();
            uVar15 = FUN_80019c5c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_8004a5b8('\x01');
          }
          if (DAT_803dd5d0 != '\0') {
            bVar2 = true;
          }
        }
      }
      if ((iVar5 == 0) || ((param_11 & 0x20000000) == 0)) {
        if ((iVar4 == 0) || ((param_11 & 0x10000000) == 0)) {
          if (iVar4 == 0) {
            if ((iVar5 != 0) && (iVar14 = 0x46, param_13 != (uint *)0x0)) {
              uVar3 = *(uint *)(iVar5 + param_14 * 4) & 0xffffff;
              iVar11 = 0;
              if (uVar3 == 0) {
                do {
                  iVar4 = iVar11 + 1;
                  iVar12 = iVar11 * 4;
                  iVar11 = iVar4;
                } while ((*(uint *)(iVar5 + iVar12) & 0xffffff) == 0);
                *param_13 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
              }
              else if (uVar3 < (*(uint *)(iVar5 + param_14 * 4 + -4) & 0xffffff)) {
                do {
                  iVar12 = iVar11 * 4;
                  iVar4 = iVar11 + 1;
                  iVar11 = iVar11 + 1;
                } while (uVar3 != (*(uint *)(iVar5 + iVar12) & 0xffffff));
                do {
                  iVar12 = iVar4 + 1;
                  iVar11 = iVar4 * 4;
                  iVar4 = iVar12;
                } while ((*(uint *)(iVar5 + iVar11) & 0xffffff) <= uVar3);
                *param_13 = (*(uint *)(iVar5 + iVar12 * 4 + -4) & 0xffffff) - uVar3;
              }
              else {
                do {
                  iVar12 = param_14 + 1;
                  iVar11 = param_14 * 4;
                  param_14 = iVar12;
                } while ((*(uint *)(iVar5 + iVar11) & 0xffffff) <= uVar3);
                *param_13 = (*(uint *)(iVar5 + iVar12 * 4 + -4) & 0xffffff) - uVar3;
              }
            }
          }
          else {
            iVar14 = 0x2b;
            if (param_13 != (uint *)0x0) {
              uVar3 = *(uint *)(iVar4 + param_14 * 4) & 0xffffff;
              iVar11 = 0;
              if (uVar3 == 0) {
                do {
                  iVar5 = iVar11 + 1;
                  iVar12 = iVar11 * 4;
                  iVar11 = iVar5;
                } while ((*(uint *)(iVar4 + iVar12) & 0xffffff) == 0);
                *param_13 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
              }
              else if (uVar3 < (*(uint *)(iVar4 + param_14 * 4 + -4) & 0xffffff)) {
                do {
                  iVar12 = iVar11 * 4;
                  iVar5 = iVar11 + 1;
                  iVar11 = iVar11 + 1;
                } while (uVar3 != (*(uint *)(iVar4 + iVar12) & 0xffffff));
                do {
                  iVar12 = iVar5 + 1;
                  iVar11 = iVar5 * 4;
                  iVar5 = iVar12;
                } while ((*(uint *)(iVar4 + iVar11) & 0xffffff) <= uVar3);
                *param_13 = (*(uint *)(iVar4 + iVar12 * 4 + -4) & 0xffffff) - uVar3;
              }
              else {
                do {
                  iVar12 = param_14 + 1;
                  iVar11 = param_14 * 4;
                  param_14 = iVar12;
                } while ((*(uint *)(iVar4 + iVar11) & 0xffffff) <= uVar3);
                *param_13 = (*(uint *)(iVar4 + iVar12 * 4 + -4) & 0xffffff) - uVar3;
              }
            }
          }
        }
        else {
          iVar14 = 0x2b;
          if (param_13 != (uint *)0x0) {
            uVar3 = *(uint *)(iVar4 + param_14 * 4) & 0xffffff;
            iVar11 = 0;
            if (uVar3 == 0) {
              do {
                iVar5 = iVar11 + 1;
                iVar12 = iVar11 * 4;
                iVar11 = iVar5;
              } while ((*(uint *)(iVar4 + iVar12) & 0xffffff) == 0);
              *param_13 = *(uint *)(iVar4 + iVar5 * 4 + -4) & 0xffffff;
            }
            else if (uVar3 < (*(uint *)(iVar4 + param_14 * 4 + -4) & 0xffffff)) {
              do {
                iVar12 = iVar11 * 4;
                iVar5 = iVar11 + 1;
                iVar11 = iVar11 + 1;
              } while (uVar3 != (*(uint *)(iVar4 + iVar12) & 0xffffff));
              do {
                iVar12 = iVar5 + 1;
                iVar11 = iVar5 * 4;
                iVar5 = iVar12;
              } while ((*(uint *)(iVar4 + iVar11) & 0xffffff) <= uVar3);
              *param_13 = (*(uint *)(iVar4 + iVar12 * 4 + -4) & 0xffffff) - uVar3;
            }
            else {
              do {
                iVar12 = param_14 + 1;
                iVar11 = param_14 * 4;
                param_14 = iVar12;
              } while ((*(uint *)(iVar4 + iVar11) & 0xffffff) <= uVar3);
              *param_13 = (*(uint *)(iVar4 + iVar12 * 4 + -4) & 0xffffff) - uVar3;
            }
          }
        }
      }
      else {
        iVar14 = 0x46;
        if (param_13 != (uint *)0x0) {
          uVar3 = *(uint *)(iVar5 + param_14 * 4) & 0xffffff;
          iVar11 = 0;
          if (uVar3 == 0) {
            do {
              iVar4 = iVar11 + 1;
              iVar12 = iVar11 * 4;
              iVar11 = iVar4;
            } while ((*(uint *)(iVar5 + iVar12) & 0xffffff) == 0);
            *param_13 = *(uint *)(iVar5 + iVar4 * 4 + -4) & 0xffffff;
          }
          else if (uVar3 < (*(uint *)(iVar5 + param_14 * 4 + -4) & 0xffffff)) {
            iVar11 = 0;
            do {
              iVar12 = iVar11 * 4;
              iVar4 = iVar11 + 1;
              iVar11 = iVar11 + 1;
            } while (uVar3 != (*(uint *)(iVar5 + iVar12) & 0xffffff));
            do {
              iVar12 = iVar4 + 1;
              iVar11 = iVar4 * 4;
              iVar4 = iVar12;
            } while ((*(uint *)(iVar5 + iVar11) & 0xffffff) <= uVar3);
            *param_13 = (*(uint *)(iVar5 + iVar12 * 4 + -4) & 0xffffff) - uVar3;
          }
          else {
            do {
              iVar12 = param_14 + 1;
              iVar11 = param_14 * 4;
              param_14 = iVar12;
            } while ((*(uint *)(iVar5 + iVar11) & 0xffffff) <= uVar3);
            *param_13 = (*(uint *)(iVar5 + iVar12 * 4 + -4) & 0xffffff) - uVar3;
          }
        }
      }
      param_11 = param_11 & 0xfffffff;
      param_14 = iVar13;
    }
  }
  else if (iVar14 == 0x51) {
    if ((DAT_80360190 != 0) && (iVar14 = 0x51, param_13 != (uint *)0x0)) {
      *param_13 = (*(uint *)(DAT_80360190 + param_14 * 4 + 4) & 0xfffffff) -
                  (*(uint *)(DAT_80360190 + param_14 * 4) & 0xfffffff);
    }
    param_11 = param_11 & 0xfffffff;
    if ((param_15 & 1) != 0) {
      iVar11 = (&DAT_80360048)[iVar14];
      iVar12 = FUN_8002a690();
      if (iVar12 != 0) {
        uVar3 = FUN_8002a698(iVar11 + param_11,*param_13);
        *param_13 = uVar3;
      }
    }
  }
  if ((param_15 & 1) == 0) {
    iVar11 = (&DAT_80360048)[iVar14];
    if (iVar11 == 0) {
      if ((iVar14 == 0x20) || (iVar14 == 0x4b)) {
        FUN_80249300(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (&PTR_s_AUDIO_tab_802cbecc)[iVar14],(int)aiStack_74);
        uVar3 = param_12 + 0x1f & 0xffffffe0;
        uVar6 = FUN_80023d8c(uVar3,0x7f7f7fff);
        FUN_80015888(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_74,uVar6
                     ,uVar3,param_11 & 0xffffff,puVar8,param_14,uVar9,param_16);
        FUN_802493c8(aiStack_74);
        FUN_80242114(uVar6,param_12);
        iVar11 = FUN_80291d74(-0x7fc23ddc,uVar6,3);
        if (iVar11 == 0) {
          do {
                    /* WARNING: Do nothing block with infinite loop */
          } while( true );
        }
        iVar11 = FUN_80291d74(uVar6,-0x7fc23de0,3);
        if (iVar11 == 0) {
          FUN_8004b7d4(uVar6 + 0x10,*(undefined4 *)(uVar6 + 0xc),(int)puVar7);
        }
        FUN_800238c4(uVar6);
      }
      else {
        FUN_80249300(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (&PTR_s_AUDIO_tab_802cbecc)[iVar14],(int)aiStack_74);
        if (((uVar16 & 0x1f) == 0) && ((param_12 & 0x1f) == 0)) {
          FUN_80015888(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_74,
                       puVar7,param_12,param_11,puVar8,param_14,uVar9,param_16);
        }
        else {
          uVar3 = param_12 + 0x1f & 0xffffffe0;
          uVar6 = FUN_80023d8c(uVar3,0x7f7f7fff);
          FUN_80015888(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_74,
                       uVar6,uVar3,param_11,puVar8,param_14,uVar9,param_16);
          FUN_80003494((uint)puVar7,uVar6,param_12);
          FUN_800238c4(uVar6);
        }
        FUN_80242114((uint)puVar7,param_12);
        FUN_802493c8(aiStack_74);
      }
    }
    else if ((iVar14 == 0xd) || (iVar14 == 0x55)) {
      if (iVar11 != 0) {
        FUN_80003494((uint)puVar7,iVar11 + param_11,param_12);
      }
    }
    else if ((iVar14 == 0x1b) || (iVar14 == 0x54)) {
      if (iVar11 != 0) {
        iVar11 = iVar11 + param_11;
        iVar12 = FUN_80291d74(iVar11,-0x7fc23de0,3);
        if (iVar12 == 0) {
          iVar12 = *(int *)(iVar11 + 8);
          FUN_8004b7d4((&DAT_80360048)[iVar14] + param_11 + 0x10,*(undefined4 *)(iVar11 + 0xc),
                       (int)puVar7);
          FUN_80242114((uint)puVar7,iVar12);
        }
      }
    }
    else if ((iVar14 == 0x25) || (iVar14 == 0x47)) {
      if (iVar11 != 0) {
        iVar11 = iVar11 + param_11;
        iVar12 = FUN_80291d74(iVar11,-0x7fc23de0,3);
        if (iVar12 == 0) {
          iVar12 = *(int *)(iVar11 + 8);
          FUN_8004b7d4((&DAT_80360048)[iVar14] + param_11 + 0x10,*(undefined4 *)(iVar11 + 0xc),
                       (int)puVar7);
          FUN_80242114((uint)puVar7,iVar12);
        }
      }
    }
    else if ((iVar14 == 0x2b) || (iVar14 == 0x46)) {
      piVar10 = (int *)(iVar11 + param_11);
      if (*piVar10 == -0x1f1f1f20) {
        FUN_80003494((uint)puVar7,(int)piVar10 + piVar10[2] + 0x18,piVar10[1]);
      }
      else if (*piVar10 == -0x5310113) {
        FUN_8004b7d4((int)piVar10 + piVar10[2] + 0x28,piVar10[3] + -0x10,(int)puVar7);
        FUN_80242114((uint)puVar7,piVar10[1]);
      }
    }
    else if ((iVar14 == 0x23) || (iVar14 == 0x4d)) {
      iVar11 = iVar11 + (param_11 & 0xffffff);
      iVar12 = *(int *)(iVar11 + 8);
      FUN_8004b7d4(iVar11 + 0x10,*(undefined4 *)(iVar11 + 0xc),(int)puVar7);
      FUN_80242114((uint)puVar7,iVar12);
    }
    else if ((iVar14 == 0x20) || (iVar14 == 0x4b)) {
      iVar11 = iVar11 + (param_11 & 0xffffff);
      iVar12 = FUN_80291d74(-0x7fc23ddc,iVar11,3);
      if ((iVar12 != 0) && (iVar12 = FUN_80291d74(iVar11,-0x7fc23de0,3), iVar12 == 0)) {
        iVar12 = *(int *)(iVar11 + 8);
        FUN_8004b7d4((&DAT_80360048)[iVar14] + (param_11 & 0xffffff) + 0x10,
                     *(undefined4 *)(iVar11 + 0xc),(int)puVar7);
        FUN_80242114((uint)puVar7,iVar12);
      }
    }
    else if (iVar14 == 0x4f) {
      iVar11 = iVar11 + (param_11 & 0xffffff);
      iVar12 = FUN_80291d74(-0x7fc23ddc,iVar11,3);
      if ((iVar12 != 0) && (iVar12 = FUN_80291d74(iVar11,-0x7fc23de0,3), iVar12 == 0)) {
        iVar12 = *(int *)(iVar11 + 8);
        FUN_8004b7d4(DAT_80360184 + (param_11 & 0xffffff) + 0x10,*(undefined4 *)(iVar11 + 0xc),
                     (int)puVar7);
        FUN_80242114((uint)puVar7,iVar12);
      }
    }
    else if (((iVar14 == 0x30) || (iVar14 == 0x51)) || (iVar14 == 0x4a)) {
      iVar12 = FUN_8002a690();
      if (iVar12 == 0) {
        FUN_80003494((uint)puVar7,(&DAT_80360048)[iVar14] + param_11,param_12);
      }
      else {
        iVar12 = FUN_8002a698(iVar11 + param_11,*param_13);
        FUN_8002a51c(iVar11 + param_11,*param_13,puVar7,iVar12);
      }
    }
    else {
      FUN_80003494((uint)puVar7,iVar11 + param_11,param_12);
    }
  }
  FUN_8028686c();
  return;
}

