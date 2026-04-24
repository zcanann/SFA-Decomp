// Function: FUN_80058094
// Entry: 80058094
// Size: 3144 bytes

/* WARNING: Removing unreachable block (ram,0x80058cbc) */

void FUN_80058094(void)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  short *psVar5;
  undefined4 uVar6;
  short *psVar7;
  int *piVar8;
  char *pcVar9;
  int iVar10;
  char **ppcVar11;
  int *piVar12;
  short *psVar13;
  short sVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  undefined4 *puVar18;
  int iVar19;
  undefined2 *puVar20;
  char cVar22;
  int iVar21;
  int *piVar23;
  uint uVar24;
  short *psVar25;
  int *piVar26;
  char **ppcVar27;
  int iVar28;
  int iVar29;
  undefined4 uVar30;
  double dVar31;
  undefined8 in_f31;
  double dVar32;
  undefined auStack4104 [1512];
  int local_a10;
  int local_a0c;
  int local_a08;
  int local_a04;
  int local_a00;
  int local_9fc;
  int local_9f8;
  int local_9f4;
  int local_9f0;
  int local_9ec;
  int local_9e8;
  int local_9e4;
  int local_9e0;
  int local_9dc;
  int local_9d8;
  int local_9d4;
  short local_9d0 [2];
  short local_9cc [1198];
  double local_70;
  double local_68;
  longlong local_60;
  longlong local_58;
  
  uVar30 = 0;
  __psq_st0(auStack4104,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack4104,(int)in_f31,0);
  FUN_802860b8();
  bVar1 = false;
  if ((DAT_803dcde8 & 0x1000) == 0) {
    FLOAT_803dced0 = FLOAT_803dcdd8;
    FLOAT_803dcecc = FLOAT_803dcddc;
    if ((((DAT_803dcec8 != -1) && (DAT_803dcec8 != DAT_803dcec4)) &&
        (DAT_803dcec4 = DAT_803dcec8, DAT_803dcec8 < 0x76)) && ((&DAT_8030e55c)[DAT_803dcec8] != -1)
       ) {
      FUN_80019970();
    }
    if (((DAT_803dcde8 & 2) == 0) && ((iVar2 = FUN_800430ac(0), iVar2 != 0 || (DAT_803dce1c == 0))))
    {
      DAT_803dce1c = FUN_800430ac(0);
    }
    else {
      DAT_803dcde8 = DAT_803dcde8 & 0xfffffffd;
      dVar32 = (double)(FLOAT_803dce5c - FLOAT_803dcddc);
      dVar31 = (double)FUN_80291e40((double)((FLOAT_803dce64 - FLOAT_803dcdd8) / FLOAT_803debb4));
      iVar2 = (int)dVar31;
      local_70 = (double)(longlong)iVar2;
      dVar31 = (double)FUN_80291e40((double)(float)(dVar32 / (double)FLOAT_803debb4));
      iVar19 = (int)dVar31;
      local_68 = (double)(longlong)iVar19;
      uVar24 = DAT_803dcde8 & 0x800;
      DAT_803dcde8 = DAT_803dcde8 & 0xfffff7ff;
      uVar3 = FUN_800430ac(0);
      if ((uVar3 & 0xffefffff) == 0) {
        if (DAT_803dce04 != '\0') {
          DAT_803dce04 = '\0';
          uVar24 = 1;
        }
      }
      else if ((((DAT_803dcec8 != 0x26) && (DAT_803dcec8 != 0x3a)) &&
               ((DAT_803dcec8 != 0x3b &&
                (((DAT_803dcec8 != 0x3c && (DAT_803dcec8 != 0x3d)) && (DAT_803dcec8 != 0x3e)))))) &&
              (DAT_803dcec8 != 0x1c)) {
        DAT_803dce04 = '\x01';
      }
      if (((iVar2 != 7) || (iVar19 != 7)) || ((uVar24 != 0 || ((DAT_803dcde8 & 0x4000) != 0)))) {
        FUN_800628d8(1);
        FUN_8001f678(1,0);
        iVar28 = 0;
        iVar17 = 0;
        piVar23 = &DAT_803822a0;
        ppcVar27 = (char **)&DAT_803822b4;
        piVar26 = &DAT_8038228c;
        psVar25 = local_9d0;
        piVar8 = piVar23;
        ppcVar11 = ppcVar27;
        piVar12 = piVar26;
        psVar13 = psVar25;
        do {
          puVar20 = (undefined2 *)*piVar8;
          pcVar4 = *ppcVar11;
          DAT_803dce88 = *piVar12;
          iVar16 = 0;
          iVar15 = 0;
          psVar5 = psVar13;
          do {
            sVar14 = 0;
            iVar29 = 8;
            psVar7 = psVar5;
            do {
              cVar22 = *pcVar4;
              if (-1 < cVar22) {
                *psVar5 = (short)DAT_803dcdd0 + sVar14;
                psVar5[1] = (short)DAT_803dcdd4 + (short)iVar15;
                psVar5[3] = (short)iVar17;
                psVar5[2] = (short)cVar22;
                psVar5 = psVar5 + 4;
                psVar7 = psVar7 + 4;
                psVar13 = psVar13 + 4;
                iVar28 = iVar28 + 1;
              }
              *pcVar4 = -2;
              *(undefined *)(DAT_803dce88 + iVar16) = 0xff;
              puVar20[3] = 0xfffd;
              *puVar20 = 0xffff;
              puVar20[1] = 0xffff;
              puVar20[2] = 0xffff;
              cVar22 = pcVar4[1];
              if (-1 < cVar22) {
                *psVar5 = (short)DAT_803dcdd0 + sVar14 + 1;
                psVar5[1] = (short)DAT_803dcdd4 + (short)iVar15;
                psVar5[3] = (short)iVar17;
                psVar5[2] = (short)cVar22;
                psVar5 = psVar5 + 4;
                psVar7 = psVar7 + 4;
                psVar13 = psVar13 + 4;
                iVar28 = iVar28 + 1;
              }
              pcVar4[1] = -2;
              *(undefined *)(DAT_803dce88 + iVar16 + 1) = 0xff;
              puVar20[9] = 0xfffd;
              puVar20[6] = 0xffff;
              puVar20[7] = 0xffff;
              puVar20[8] = 0xffff;
              puVar20 = puVar20 + 0xc;
              iVar16 = iVar16 + 2;
              pcVar4 = pcVar4 + 2;
              sVar14 = sVar14 + 2;
              iVar29 = iVar29 + -1;
            } while (iVar29 != 0);
            iVar15 = iVar15 + 1;
            psVar5 = psVar7;
          } while (iVar15 < 0x10);
          piVar8 = piVar8 + 1;
          ppcVar11 = ppcVar11 + 1;
          piVar12 = piVar12 + 1;
          iVar17 = iVar17 + 1;
        } while (iVar17 < 5);
        DAT_803dcdd0 = (iVar2 + DAT_803dcdd0) - 7;
        DAT_803dcdd4 = (iVar19 + DAT_803dcdd4) - 7;
        local_68 = (double)CONCAT44(0x43300000,DAT_803dcdd0 ^ 0x80000000);
        FLOAT_803dcdd8 = FLOAT_803debb4 * (float)(local_68 - DOUBLE_803debc0);
        local_70 = (double)CONCAT44(0x43300000,DAT_803dcdd4 ^ 0x80000000);
        FLOAT_803dcddc = FLOAT_803debb4 * (float)(local_70 - DOUBLE_803debc0);
        DAT_803dcdc8 = (int)FLOAT_803dcdd8;
        local_60 = (longlong)DAT_803dcdc8;
        DAT_803dcdcc = (int)FLOAT_803dcddc;
        local_58 = (longlong)DAT_803dcdcc;
        iVar19 = 0;
        iVar2 = (int)DAT_803dcdec;
        if (0 < iVar2) {
          if (8 < iVar2) {
            puVar18 = &DAT_8038224c;
            uVar3 = iVar2 - 1U >> 3;
            if (0 < iVar2 + -8) {
              do {
                *(undefined *)((int)puVar18 + 6) = 0;
                *(undefined *)((int)puVar18 + 0xe) = 0;
                *(undefined *)((int)puVar18 + 0x16) = 0;
                *(undefined *)((int)puVar18 + 0x1e) = 0;
                *(undefined *)((int)puVar18 + 0x26) = 0;
                *(undefined *)((int)puVar18 + 0x2e) = 0;
                *(undefined *)((int)puVar18 + 0x36) = 0;
                *(undefined *)((int)puVar18 + 0x3e) = 0;
                puVar18 = puVar18 + 0x10;
                iVar19 = iVar19 + 8;
                uVar3 = uVar3 - 1;
              } while (uVar3 != 0);
            }
          }
          puVar18 = &DAT_8038224c + iVar19 * 2;
          iVar2 = DAT_803dcdec - iVar19;
          if (iVar19 < DAT_803dcdec) {
            do {
              *(undefined *)((int)puVar18 + 6) = 0;
              puVar18 = puVar18 + 2;
              iVar2 = iVar2 + -1;
            } while (iVar2 != 0);
          }
        }
        DAT_803dcec8 = FUN_80059ac0(DAT_803dcdd0 + 7,DAT_803dcdd4 + 7,0);
        DAT_803dcec0 = -1;
        if (DAT_803dcec8 != -1) {
          if (DAT_803dcec8 != -1) {
            FUN_80041e30();
            iVar19 = 0;
            piVar8 = &DAT_8038224c;
            iVar2 = (int)DAT_803dcdec;
            if (0 < iVar2) {
              do {
                if ((*piVar8 != 0) && (DAT_803dcec8 == *(short *)(piVar8 + 1))) goto LAB_800586b0;
                piVar8 = piVar8 + 2;
                iVar19 = iVar19 + 1;
                iVar2 = iVar2 + -1;
              } while (iVar2 != 0);
            }
            iVar19 = -1;
LAB_800586b0:
            if (iVar19 == -1) {
              iVar19 = FUN_80059cb0();
            }
            iVar17 = DAT_803dcec8;
            uVar3 = FUN_80048f10(0x1f);
            iVar2 = DAT_803dce78;
            if ((iVar17 < 0) || ((int)(uVar3 >> 5) <= iVar17)) {
              DAT_803dcea4 = 0;
            }
            else {
              FUN_8001f71c(DAT_803dce78,0x1f,iVar17 << 5,0x20);
              DAT_803dcea4 = *(undefined *)(iVar2 + 0x1c);
            }
            (&DAT_80382252)[iVar19 * 8] = 1;
            DAT_803dcec0 = iVar19;
            FUN_800481b0(DAT_803dcec8);
            FUN_80044394();
            uVar6 = FUN_800481b0(DAT_803dcec8);
            FUN_800443cc(uVar6,0x26);
            uVar6 = FUN_800481b0(DAT_803dcec8);
            FUN_800443cc(uVar6,0x25);
            uVar6 = FUN_800481b0(DAT_803dcec8);
            FUN_800443cc(uVar6,0x1a);
            uVar6 = FUN_800481b0(DAT_803dcec8);
            FUN_800443cc(uVar6,0x1b);
            DAT_803dcde4 = (int *)FUN_800436e4(0x26);
            DAT_803dceb0 = 0;
            for (piVar8 = DAT_803dcde4; (DAT_803dcde4 != (int *)0x0 && (*piVar8 != -1));
                piVar8 = piVar8 + 1) {
              DAT_803dceb0 = DAT_803dceb0 + 1;
            }
            DAT_803dceb0 = DAT_803dceb0 + -1;
            iVar2 = 0;
            do {
              iVar19 = *piVar23;
              iVar17 = 0;
              iVar15 = 2;
              do {
                iVar19 = iVar19 + 0x540;
                iVar17 = iVar17 + 7;
                iVar15 = iVar15 + -1;
              } while (iVar15 != 0);
              piVar23 = piVar23 + 1;
              iVar2 = iVar2 + 1;
            } while (iVar2 < 5);
            uVar6 = FUN_800481b0(DAT_803dcec8,iVar19,iVar17);
            FUN_800443cc(uVar6,0x20);
            FUN_800443cc(uVar6,0x23);
            FUN_800443cc(uVar6,0x30);
            FUN_800443cc(uVar6,0x2b);
            FUN_800443cc(uVar6,0xd);
            FUN_800443cc(uVar6,0x21);
            FUN_800443cc(uVar6,0x2a);
            FUN_800443cc(uVar6,0x2f);
            FUN_800443cc(uVar6,0x24);
            FUN_800443cc(uVar6,0xe);
            FUN_80026ef4();
            iVar2 = 0;
            do {
              FUN_80057d24(DAT_803dcdd0 + 7,DAT_803dcdd4 + 7,&local_9e0,&local_9f0,&local_a00,
                           &local_a10,iVar2,0);
              pcVar4 = *ppcVar27;
              DAT_803dce88 = *piVar26;
              for (iVar19 = local_9d8; iVar17 = local_9e8, iVar19 <= local_9d4; iVar19 = iVar19 + 1)
              {
                pcVar9 = pcVar4 + (iVar19 + 7) * 0x10 + local_9e0;
                for (iVar17 = local_9e0; iVar17 <= local_9dc; iVar17 = iVar17 + 1) {
                  pcVar9[7] = -3;
                  pcVar9 = pcVar9 + 1;
                }
              }
              for (; iVar19 = local_9f8, iVar17 <= local_9e4; iVar17 = iVar17 + 1) {
                pcVar9 = pcVar4 + (iVar17 + 7) * 0x10 + local_9f0;
                for (iVar19 = local_9f0; iVar19 <= local_9ec; iVar19 = iVar19 + 1) {
                  pcVar9[7] = -3;
                  pcVar9 = pcVar9 + 1;
                }
              }
              for (; iVar17 = local_a08, iVar19 <= local_9f4; iVar19 = iVar19 + 1) {
                pcVar9 = pcVar4 + (iVar19 + 7) * 0x10 + local_a00;
                for (iVar17 = local_a00; iVar17 <= local_9fc; iVar17 = iVar17 + 1) {
                  pcVar9[7] = -3;
                  pcVar9 = pcVar9 + 1;
                }
              }
              for (; iVar17 <= local_a04; iVar17 = iVar17 + 1) {
                pcVar9 = pcVar4 + (iVar17 + 7) * 0x10 + local_a10;
                for (iVar19 = local_a10; iVar19 <= local_a0c; iVar19 = iVar19 + 1) {
                  pcVar9[7] = -3;
                  pcVar9 = pcVar9 + 1;
                }
              }
              cVar22 = '\0';
              iVar17 = 0;
              iVar19 = 0;
              do {
                iVar15 = 0;
                do {
                  if (*pcVar4 == -3) {
                    iVar16 = FUN_80056dcc(iVar15,iVar19,DAT_803dcdd0 + iVar15,DAT_803dcdd4 + iVar19,
                                          iVar2);
                    if (iVar16 == 0) {
                      *pcVar4 = -2;
                    }
                    else {
                      *(char *)(DAT_803dce88 + iVar17) = cVar22;
                      cVar22 = cVar22 + '\x01';
                    }
                  }
                  iVar17 = iVar17 + 1;
                  pcVar4 = pcVar4 + 1;
                  iVar15 = iVar15 + 1;
                } while (iVar15 < 0x10);
                iVar19 = iVar19 + 1;
              } while (iVar19 < 0x10);
              ppcVar27 = ppcVar27 + 1;
              piVar26 = piVar26 + 1;
              iVar2 = iVar2 + 1;
            } while (iVar2 < 5);
            FUN_80041e24();
          }
        }
        else {
          uVar6 = FUN_800481b0(0x29);
          FUN_80041e30();
          FUN_800443cc(uVar6,0x20);
          FUN_800443cc(uVar6,0x23);
          FUN_800443cc(uVar6,0x30);
          FUN_800443cc(uVar6,0x2b);
          FUN_800443cc(uVar6,0x21);
          FUN_800443cc(uVar6,0x2a);
          FUN_800443cc(uVar6,0x2f);
          FUN_800443cc(uVar6,0x24);
          FUN_80041e24();
          while (iVar2 = FUN_800430ac(0), iVar2 != 0) {
            uVar6 = FUN_800430ac(0);
            FUN_8007d6dc(s_track_piLocked__x_8030e790,uVar6);
            FUN_80014f40();
            FUN_800202cc();
            if (bVar1) {
              FUN_8004a868();
            }
            FUN_800481d4();
            FUN_80015624();
            if (bVar1) {
              FUN_800234ec(0);
              FUN_80019c24();
              FUN_8004a43c(1,0);
            }
            if (DAT_803dc950 != '\0') {
              bVar1 = true;
            }
          }
        }
        bVar1 = true;
        iVar2 = DAT_803dcdec + -1;
        piVar8 = &DAT_8038224c + iVar2 * 2;
        for (; -1 < iVar2; iVar2 = iVar2 + -1) {
          if (*(char *)((int)piVar8 + 6) == '\0') {
            if (*piVar8 != 0) {
              iVar19 = (int)*(short *)(piVar8 + 1);
              FUN_8005972c(*piVar8,iVar19 * 0x8c + -0x7fc7dd38,iVar19,1);
              FUN_80023800(*piVar8);
              (&DAT_80386468)[iVar19] = 0;
            }
            *piVar8 = 0;
            *(undefined2 *)(piVar8 + 1) = 0xffff;
          }
          if (bVar1) {
            if (*piVar8 == 0) {
              DAT_803dcdec = DAT_803dcdec + -1;
            }
            else {
              bVar1 = false;
            }
          }
          piVar8 = piVar8 + -2;
        }
        for (iVar2 = 0; iVar2 < iVar28; iVar2 = iVar2 + 1) {
          iVar19 = (int)psVar25[2];
          if ((-1 < iVar19) &&
             (*(char *)(DAT_803dce8c + iVar19) = *(char *)(DAT_803dce8c + iVar19) + -1,
             *(char *)(DAT_803dce8c + iVar19) == '\0')) {
            iVar17 = *(int *)(DAT_803dce9c + iVar19 * 4);
            *(undefined2 *)(DAT_803dce94 + iVar19 * 2) = 0xffff;
            *(undefined4 *)(DAT_803dce9c + iVar19 * 4) = 0;
            iVar15 = 0;
            for (iVar19 = 0; iVar19 < (int)(uint)*(byte *)(iVar17 + 0xa2); iVar19 = iVar19 + 1) {
              iVar21 = *(int *)(iVar17 + 100) + iVar15;
              iVar16 = iVar21;
              for (iVar29 = 0; iVar29 < (int)(uint)*(byte *)(iVar21 + 0x41); iVar29 = iVar29 + 1) {
                if (*(byte *)(iVar16 + 0x2a) != 0xff) {
                  iVar10 = (uint)*(byte *)(iVar16 + 0x2a) * 0x10 + 0xc;
                  cVar22 = *(char *)(DAT_803dce68 + iVar10);
                  if (cVar22 != '\0') {
                    *(char *)(DAT_803dce68 + iVar10) = cVar22 + -1;
                  }
                }
                if (*(char *)(iVar16 + 0x29) != '\0') {
                  FUN_800566a4(*(undefined4 *)(iVar16 + 0x24));
                }
                iVar16 = iVar16 + 8;
              }
              iVar15 = iVar15 + 0x44;
            }
            iVar15 = 0;
            for (iVar19 = 0; iVar19 < (int)(uint)*(byte *)(iVar17 + 0xa0); iVar19 = iVar19 + 1) {
              FUN_80054308(*(undefined4 *)(*(int *)(iVar17 + 0x54) + iVar15));
              iVar15 = iVar15 + 4;
            }
            if (*(int *)(iVar17 + 0x74) != 0) {
              FUN_80023800();
            }
            if (*(int *)(iVar17 + 0x70) != 0) {
              FUN_80023800();
            }
            FUN_80065678();
            FUN_80023800(iVar17);
          }
          psVar25 = psVar25 + 4;
        }
        DAT_803dce70 = 0;
        DAT_803dcded = 0;
      }
      FUN_80055d24(uVar24);
      DAT_803dce1c = FUN_800430ac(0);
      DAT_803dcde8 = DAT_803dcde8 & 0xffffbfff;
    }
  }
  __psq_l0(auStack4104,uVar30);
  __psq_l1(auStack4104,uVar30);
  FUN_80286104();
  return;
}

