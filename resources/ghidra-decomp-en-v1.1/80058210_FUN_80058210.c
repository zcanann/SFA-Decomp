// Function: FUN_80058210
// Entry: 80058210
// Size: 3144 bytes

/* WARNING: Removing unreachable block (ram,0x80058e38) */
/* WARNING: Removing unreachable block (ram,0x80058220) */

void FUN_80058210(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  double dVar1;
  double dVar2;
  short sVar3;
  bool bVar4;
  int iVar5;
  uint uVar6;
  char *pcVar7;
  short *psVar8;
  short *psVar9;
  int *piVar10;
  char *pcVar11;
  int *piVar12;
  short *psVar13;
  int iVar14;
  int iVar15;
  undefined4 uVar16;
  int iVar17;
  int iVar18;
  undefined4 *puVar19;
  int iVar20;
  undefined2 *puVar21;
  char cVar22;
  undefined4 *puVar23;
  uint *puVar24;
  short *psVar25;
  int *piVar26;
  undefined4 *puVar27;
  int iVar28;
  int iVar29;
  uint uVar30;
  undefined8 uVar31;
  double dVar32;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
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
  undefined8 local_70;
  undefined8 local_68;
  longlong local_60;
  longlong local_58;
  
  uVar31 = FUN_8028681c();
  bVar4 = false;
  if ((DAT_803dda68 & 0x1000) == 0) {
    FLOAT_803ddb50 = FLOAT_803dda58;
    FLOAT_803ddb4c = FLOAT_803dda5c;
    if ((((DAT_803ddb48 != -1) && (DAT_803ddb48 != DAT_803ddb44)) &&
        (DAT_803ddb44 = DAT_803ddb48, DAT_803ddb48 < 0x76)) &&
       ((char)(&DAT_8030f11c)[DAT_803ddb48] != -1)) {
      FUN_800199a8(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)(char)(&DAT_8030f11c)[DAT_803ddb48]);
    }
    if (((DAT_803dda68 & 2) == 0) && ((iVar5 = FUN_800431a4(), iVar5 != 0 || (DAT_803dda9c == 0))))
    {
      DAT_803dda9c = FUN_800431a4();
    }
    else {
      DAT_803dda68 = DAT_803dda68 & 0xfffffffd;
      dVar32 = (double)FUN_802925a0();
      iVar5 = (int)dVar32;
      local_70 = (double)(longlong)iVar5;
      dVar32 = (double)FUN_802925a0();
      iVar20 = (int)dVar32;
      local_68 = (double)(longlong)iVar20;
      uVar30 = DAT_803dda68 & 0x800;
      DAT_803dda68 = DAT_803dda68 & 0xfffff7ff;
      uVar6 = FUN_800431a4();
      if ((uVar6 & 0xffefffff) == 0) {
        if (DAT_803dda84 != '\0') {
          DAT_803dda84 = '\0';
          uVar30 = 1;
        }
      }
      else if ((((DAT_803ddb48 != 0x26) && (DAT_803ddb48 != 0x3a)) &&
               ((DAT_803ddb48 != 0x3b &&
                (((DAT_803ddb48 != 0x3c && (DAT_803ddb48 != 0x3d)) && (DAT_803ddb48 != 0x3e)))))) &&
              (DAT_803ddb48 != 0x1c)) {
        DAT_803dda84 = '\x01';
      }
      if (((iVar5 != 7) || (iVar20 != 7)) || ((uVar30 != 0 || ((DAT_803dda68 & 0x4000) != 0)))) {
        FUN_80062a54(1);
        FUN_8001f73c();
        iVar28 = 0;
        iVar18 = 0;
        puVar23 = &DAT_80382f00;
        puVar27 = &DAT_80382f14;
        piVar26 = &DAT_80382eec;
        psVar25 = local_9d0;
        puVar19 = puVar27;
        piVar12 = piVar26;
        psVar13 = psVar25;
        do {
          puVar21 = (undefined2 *)*puVar23;
          pcVar7 = (char *)*puVar19;
          DAT_803ddb08 = *piVar12;
          iVar17 = 0;
          iVar15 = 0;
          psVar8 = psVar13;
          do {
            iVar14 = 0;
            iVar29 = 8;
            psVar9 = psVar8;
            do {
              cVar22 = *pcVar7;
              if (-1 < cVar22) {
                *psVar8 = (short)DAT_803dda50 + (short)iVar14;
                psVar8[1] = (short)DAT_803dda54 + (short)iVar15;
                psVar8[3] = (short)iVar18;
                psVar8[2] = (short)cVar22;
                psVar8 = psVar8 + 4;
                psVar9 = psVar9 + 4;
                psVar13 = psVar13 + 4;
                iVar28 = iVar28 + 1;
              }
              *pcVar7 = -2;
              *(undefined *)(DAT_803ddb08 + iVar17) = 0xff;
              puVar21[3] = 0xfffd;
              *puVar21 = 0xffff;
              puVar21[1] = 0xffff;
              puVar21[2] = 0xffff;
              cVar22 = pcVar7[1];
              if (-1 < cVar22) {
                *psVar8 = (short)DAT_803dda50 + (short)iVar14 + 1;
                psVar8[1] = (short)DAT_803dda54 + (short)iVar15;
                psVar8[3] = (short)iVar18;
                psVar8[2] = (short)cVar22;
                psVar8 = psVar8 + 4;
                psVar9 = psVar9 + 4;
                psVar13 = psVar13 + 4;
                iVar28 = iVar28 + 1;
              }
              pcVar7[1] = -2;
              *(undefined *)(DAT_803ddb08 + iVar17 + 1) = 0xff;
              puVar21[9] = 0xfffd;
              puVar21[6] = 0xffff;
              puVar21[7] = 0xffff;
              puVar21[8] = 0xffff;
              puVar21 = puVar21 + 0xc;
              iVar17 = iVar17 + 2;
              pcVar7 = pcVar7 + 2;
              iVar14 = iVar14 + 2;
              iVar29 = iVar29 + -1;
            } while (iVar29 != 0);
            iVar15 = iVar15 + 1;
            psVar8 = psVar9;
          } while (iVar15 < 0x10);
          puVar23 = puVar23 + 1;
          puVar19 = puVar19 + 1;
          piVar12 = piVar12 + 1;
          iVar18 = iVar18 + 1;
        } while (iVar18 < 5);
        DAT_803dda50 = (iVar5 + DAT_803dda50) - 7;
        DAT_803dda54 = (iVar20 + DAT_803dda54) - 7;
        param_3 = (double)FLOAT_803df834;
        local_68 = (double)CONCAT44(0x43300000,DAT_803dda50 ^ 0x80000000);
        dVar1 = param_3 * (double)(float)(local_68 - DOUBLE_803df840);
        FLOAT_803dda58 = (float)dVar1;
        param_2 = (double)FLOAT_803dda58;
        local_70 = (double)CONCAT44(0x43300000,DAT_803dda54 ^ 0x80000000);
        dVar2 = param_3 * (double)(float)(local_70 - DOUBLE_803df840);
        FLOAT_803dda5c = (float)dVar2;
        dVar32 = (double)FLOAT_803dda5c;
        DAT_803dda48 = (int)dVar1;
        local_60 = (longlong)DAT_803dda48;
        DAT_803dda4c = (int)dVar2;
        local_58 = (longlong)DAT_803dda4c;
        iVar20 = 0;
        iVar5 = (int)DAT_803dda6c;
        if (0 < iVar5) {
          if (8 < iVar5) {
            puVar19 = &DAT_80382eac;
            iVar15 = 0;
            iVar14 = 0;
            psVar13 = (short *)0x0;
            piVar12 = (int *)0x0;
            uVar30 = iVar5 - 1U >> 3;
            if (0 < iVar5 + -8) {
              do {
                *(undefined *)((int)puVar19 + 6) = 0;
                *(undefined *)((int)puVar19 + 0xe) = 0;
                *(undefined *)((int)puVar19 + 0x16) = 0;
                *(undefined *)((int)puVar19 + 0x1e) = 0;
                *(undefined *)((int)puVar19 + 0x26) = 0;
                *(undefined *)((int)puVar19 + 0x2e) = 0;
                *(undefined *)((int)puVar19 + 0x36) = 0;
                *(undefined *)((int)puVar19 + 0x3e) = 0;
                puVar19 = puVar19 + 0x10;
                iVar20 = iVar20 + 8;
                uVar30 = uVar30 - 1;
              } while (uVar30 != 0);
            }
          }
          puVar19 = &DAT_80382eac + iVar20 * 2;
          iVar5 = DAT_803dda6c - iVar20;
          if (iVar20 < DAT_803dda6c) {
            do {
              *(undefined *)((int)puVar19 + 6) = 0;
              puVar19 = puVar19 + 2;
              iVar5 = iVar5 + -1;
            } while (iVar5 != 0);
          }
        }
        DAT_803ddb48 = FUN_80059c3c(DAT_803dda50 + 7,DAT_803dda54 + 7,0);
        DAT_803ddb40 = -1;
        if (DAT_803ddb48 != -1) {
          if (DAT_803ddb48 != -1) {
            uVar31 = FUN_80041f28();
            iVar20 = 0;
            piVar10 = &DAT_80382eac;
            iVar5 = (int)DAT_803dda6c;
            if (0 < iVar5) {
              do {
                if ((*piVar10 != 0) && (DAT_803ddb48 == *(short *)(piVar10 + 1))) goto LAB_8005882c;
                piVar10 = piVar10 + 2;
                iVar20 = iVar20 + 1;
                iVar5 = iVar5 + -1;
              } while (iVar5 != 0);
            }
            iVar20 = -1;
LAB_8005882c:
            if (iVar20 == -1) {
              iVar20 = FUN_80059e2c(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
              uVar31 = extraout_f1;
            }
            iVar18 = DAT_803ddb48;
            uVar30 = FUN_8004908c(0x1f);
            iVar5 = DAT_803ddaf8;
            if ((iVar18 < 0) || ((int)(uVar30 >> 5) <= iVar18)) {
              DAT_803ddb24 = 0;
            }
            else {
              uVar31 = FUN_8001f7e0(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                    DAT_803ddaf8,0x1f,iVar18 << 5,0x20,piVar12,psVar13,iVar14,iVar15
                                   );
              DAT_803ddb24 = *(undefined *)(iVar5 + 0x1c);
            }
            (&DAT_80382eb2)[iVar20 * 8] = 1;
            DAT_803ddb40 = iVar20;
            iVar5 = FUN_8004832c(DAT_803ddb48);
            FUN_80044510(iVar5);
            FUN_8004832c(DAT_803ddb48);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_8004832c(DAT_803ddb48);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_8004832c(DAT_803ddb48);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_8004832c(DAT_803ddb48);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            DAT_803dda64 = (int *)FUN_80043860(0x26);
            DAT_803ddb30 = 0;
            for (piVar12 = DAT_803dda64; (DAT_803dda64 != (int *)0x0 && (*piVar12 != -1));
                piVar12 = piVar12 + 1) {
              DAT_803ddb30 = DAT_803ddb30 + 1;
            }
            DAT_803ddb30 = DAT_803ddb30 + -1;
            iVar5 = 0;
            do {
              iVar18 = 2;
              do {
                iVar18 = iVar18 + -1;
              } while (iVar18 != 0);
              iVar5 = iVar5 + 1;
            } while (iVar5 < 5);
            FUN_8004832c(DAT_803ddb48);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            FUN_80026fb8();
            iVar5 = 0;
            do {
              piVar12 = &local_a10;
              uVar16 = 0;
              iVar15 = iVar5;
              uVar31 = FUN_80057ea0(DAT_803dda50 + 7,DAT_803dda54 + 7,&local_9e0,&local_9f0,
                                    &local_a00,piVar12,iVar5,0,iVar20);
              pcVar7 = (char *)*puVar27;
              DAT_803ddb08 = *piVar26;
              for (iVar18 = local_9d8; iVar17 = local_9e8, iVar18 <= local_9d4; iVar18 = iVar18 + 1)
              {
                pcVar11 = pcVar7 + (iVar18 + 7) * 0x10 + local_9e0;
                for (iVar17 = local_9e0; iVar17 <= local_9dc; iVar17 = iVar17 + 1) {
                  pcVar11[7] = -3;
                  pcVar11 = pcVar11 + 1;
                }
              }
              for (; iVar18 = local_9f8, iVar17 <= local_9e4; iVar17 = iVar17 + 1) {
                pcVar11 = pcVar7 + (iVar17 + 7) * 0x10 + local_9f0;
                for (iVar18 = local_9f0; iVar18 <= local_9ec; iVar18 = iVar18 + 1) {
                  pcVar11[7] = -3;
                  pcVar11 = pcVar11 + 1;
                }
              }
              for (; iVar17 = local_a08, iVar18 <= local_9f4; iVar18 = iVar18 + 1) {
                pcVar11 = pcVar7 + (iVar18 + 7) * 0x10 + local_a00;
                for (iVar17 = local_a00; iVar17 <= local_9fc; iVar17 = iVar17 + 1) {
                  pcVar11[7] = -3;
                  pcVar11 = pcVar11 + 1;
                }
              }
              for (; iVar17 <= local_a04; iVar17 = iVar17 + 1) {
                pcVar11 = pcVar7 + (iVar17 + 7) * 0x10 + local_a10;
                for (iVar18 = local_a10; iVar18 <= local_a0c; iVar18 = iVar18 + 1) {
                  pcVar11[7] = -3;
                  pcVar11 = pcVar11 + 1;
                }
              }
              cVar22 = '\0';
              iVar17 = 0;
              iVar18 = 0;
              do {
                iVar14 = 0;
                do {
                  if (*pcVar7 == -3) {
                    iVar29 = FUN_80056f48(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,
                                          param_8,iVar14,iVar18,DAT_803dda50 + iVar14,
                                          DAT_803dda54 + iVar18,iVar5,piVar12,iVar15,uVar16);
                    uVar31 = extraout_f1_00;
                    if (iVar29 == 0) {
                      *pcVar7 = -2;
                    }
                    else {
                      *(char *)(DAT_803ddb08 + iVar17) = cVar22;
                      cVar22 = cVar22 + '\x01';
                    }
                  }
                  iVar17 = iVar17 + 1;
                  pcVar7 = pcVar7 + 1;
                  iVar14 = iVar14 + 1;
                } while (iVar14 < 0x10);
                iVar18 = iVar18 + 1;
              } while (iVar18 < 0x10);
              puVar27 = puVar27 + 1;
              piVar26 = piVar26 + 1;
              iVar5 = iVar5 + 1;
            } while (iVar5 < 5);
            dVar32 = (double)FUN_80041f1c();
          }
        }
        else {
          FUN_8004832c(0x29);
          uVar31 = FUN_80041f28();
          uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          uVar31 = FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          FUN_80044548(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          dVar32 = (double)FUN_80041f1c();
          while (iVar5 = FUN_800431a4(), iVar5 != 0) {
            FUN_800431a4();
            FUN_8007d858();
            uVar31 = FUN_80014f6c();
            FUN_80020390();
            if (bVar4) {
              uVar31 = FUN_8004a9e4();
            }
            dVar32 = (double)FUN_80048350(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,
                                          param_8);
            FUN_80015650(dVar32,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            if (bVar4) {
              uVar31 = FUN_800235b0();
              dVar32 = (double)FUN_80019c5c(uVar31,param_2,param_3,param_4,param_5,param_6,param_7,
                                            param_8);
              FUN_8004a5b8('\x01');
            }
            if (DAT_803dd5d0 != '\0') {
              bVar4 = true;
            }
          }
        }
        bVar4 = true;
        iVar5 = DAT_803dda6c + -1;
        puVar24 = &DAT_80382eac + iVar5 * 2;
        for (; -1 < iVar5; iVar5 = iVar5 + -1) {
          if (*(char *)((int)puVar24 + 6) == '\0') {
            if (*puVar24 != 0) {
              sVar3 = *(short *)(puVar24 + 1);
              FUN_800598a8();
              dVar32 = (double)FUN_800238c4(*puVar24);
              (&DAT_803870c8)[sVar3] = 0;
            }
            *puVar24 = 0;
            *(undefined2 *)(puVar24 + 1) = 0xffff;
          }
          if (bVar4) {
            if (*puVar24 == 0) {
              DAT_803dda6c = DAT_803dda6c + -1;
            }
            else {
              bVar4 = false;
            }
          }
          puVar24 = puVar24 + -2;
        }
        for (iVar5 = 0; iVar5 < iVar28; iVar5 = iVar5 + 1) {
          iVar20 = (int)psVar25[2];
          if ((-1 < iVar20) &&
             (*(char *)(DAT_803ddb0c + iVar20) = *(char *)(DAT_803ddb0c + iVar20) + -1,
             *(char *)(DAT_803ddb0c + iVar20) == '\0')) {
            uVar30 = *(uint *)(DAT_803ddb1c + iVar20 * 4);
            *(undefined2 *)(DAT_803ddb14 + iVar20 * 2) = 0xffff;
            *(undefined4 *)(DAT_803ddb1c + iVar20 * 4) = 0;
            iVar18 = 0;
            for (iVar20 = 0; iVar20 < (int)(uint)*(byte *)(uVar30 + 0xa2); iVar20 = iVar20 + 1) {
              iVar14 = *(int *)(uVar30 + 100) + iVar18;
              iVar15 = iVar14;
              for (iVar17 = 0; iVar17 < (int)(uint)*(byte *)(iVar14 + 0x41); iVar17 = iVar17 + 1) {
                if (*(byte *)(iVar15 + 0x2a) != 0xff) {
                  iVar29 = (uint)*(byte *)(iVar15 + 0x2a) * 0x10 + 0xc;
                  cVar22 = *(char *)(DAT_803ddae8 + iVar29);
                  if (cVar22 != '\0') {
                    *(char *)(DAT_803ddae8 + iVar29) = cVar22 + -1;
                  }
                }
                if (*(byte *)(iVar15 + 0x29) != 0) {
                  FUN_80056820(*(int *)(iVar15 + 0x24),(uint)*(byte *)(iVar15 + 0x29));
                }
                iVar15 = iVar15 + 8;
              }
              iVar18 = iVar18 + 0x44;
            }
            for (iVar20 = 0; iVar20 < (int)(uint)*(byte *)(uVar30 + 0xa0); iVar20 = iVar20 + 1) {
              FUN_80054484();
            }
            if (*(uint *)(uVar30 + 0x74) != 0) {
              FUN_800238c4(*(uint *)(uVar30 + 0x74));
            }
            if (*(uint *)(uVar30 + 0x70) != 0) {
              FUN_800238c4(*(uint *)(uVar30 + 0x70));
            }
            FUN_800657f4();
            dVar32 = (double)FUN_800238c4(uVar30);
          }
          psVar25 = psVar25 + 4;
        }
        DAT_803ddaf0 = 0;
        DAT_803dda6d = 0;
      }
      FUN_80055ea0(dVar32,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      DAT_803dda9c = FUN_800431a4();
      DAT_803dda68 = DAT_803dda68 & 0xffffbfff;
    }
  }
  FUN_80286868();
  return;
}

