// Function: FUN_80178338
// Entry: 80178338
// Size: 3212 bytes

/* WARNING: Removing unreachable block (ram,0x80178f9c) */
/* WARNING: Removing unreachable block (ram,0x80178f94) */
/* WARNING: Removing unreachable block (ram,0x80178fa4) */

void FUN_80178338(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  short sVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  ushort uVar11;
  undefined4 uVar10;
  int *piVar12;
  int unaff_r25;
  float *pfVar13;
  int iVar14;
  undefined4 uVar15;
  double dVar16;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  int local_78;
  int local_74;
  int local_70 [2];
  undefined4 local_68;
  uint uStack100;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar5 = FUN_802860cc();
  iVar14 = *(int *)(iVar5 + 0x4c);
  pfVar13 = *(float **)(iVar5 + 0xb8);
  dVar18 = (double)FLOAT_803e3648;
  iVar6 = FUN_8002e0fc(&local_78,&local_74);
  *(undefined *)(param_3 + 0x56) = 0;
  iVar7 = FUN_8002b9ec();
  fVar3 = *(float *)(iVar7 + 0xc) - *(float *)(iVar14 + 8);
  fVar4 = *(float *)(iVar7 + 0x14) - *(float *)(iVar14 + 0x10);
  dVar16 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar4 * fVar4));
  if (pfVar13[4] == -NAN) {
    iVar8 = 1;
  }
  else {
    iVar8 = FUN_8001ffb4();
  }
  iVar9 = FUN_80037484(iVar5,local_70,0,0);
  if (iVar9 != 0) {
    if (local_70[0] == 0x30003) {
      *(undefined *)(pfVar13 + 8) = 0;
    }
    else if ((local_70[0] < 0x30003) && (0x30001 < local_70[0])) {
      *(undefined *)(pfVar13 + 8) = 1;
    }
  }
  iVar9 = (int)*(char *)(pfVar13 + 8);
  switch(*(undefined *)(iVar14 + 0x19)) {
  case 0:
    uStack100 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar17 = (double)((FLOAT_803e364c *
                      (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e3678)) /
                     FLOAT_803e3650);
    dVar18 = (double)FUN_80293e80(dVar17);
    dVar17 = (double)FUN_80294204(dVar17);
    dVar18 = (double)(-(float)((double)*(float *)(iVar14 + 8) * dVar18 +
                              (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar17)) +
                     (float)(dVar18 * (double)*(float *)(iVar7 + 0xc) +
                            (double)(float)(dVar17 * (double)*(float *)(iVar7 + 0x14))));
    dVar17 = (double)pfVar13[3];
    if ((((dVar16 < dVar17) && (iVar8 != 0)) && (dVar18 < dVar17)) && (-dVar17 < dVar18)) {
      iVar9 = 1;
    }
    if ((iVar9 == 0) || (*(char *)((int)pfVar13 + 0x22) != '\0')) {
      if ((iVar9 == 0) && (*(char *)((int)pfVar13 + 0x22) == '\x01')) {
        if ((*(short *)(iVar5 + 0x46) == 200) && (dVar18 <= (double)FLOAT_803e3648)) {
          FUN_80008cbc(0,0,0xe,0);
        }
        *(undefined *)((int)pfVar13 + 0x22) = 0;
      }
    }
    else {
      if (*(short *)(iVar5 + 0x46) == 200) {
        iVar6 = FUN_8001ffb4(0x57);
        if (iVar6 == 0) {
          FUN_80008cbc(0,0,0x7c,0);
        }
        else {
          FUN_80008cbc(0,0,0x7f,0);
        }
      }
      *(undefined *)((int)pfVar13 + 0x22) = 1;
    }
    break;
  case 1:
    if ((dVar16 < (double)FLOAT_803e3654) && (iVar8 != 0)) {
      uStack100 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
      local_68 = 0x43300000;
      dVar18 = (double)((FLOAT_803e364c *
                        (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e3678)) /
                       FLOAT_803e3650);
      dVar16 = (double)FUN_80293e80(dVar18);
      dVar18 = (double)FUN_80294204(dVar18);
      dVar18 = (double)(-(float)((double)*(float *)(iVar14 + 8) * dVar16 +
                                (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar18)) +
                       (float)(dVar16 * (double)*(float *)(iVar7 + 0xc) +
                              (double)(float)(dVar18 * (double)*(float *)(iVar7 + 0x14))));
      if (*(int *)(iVar5 + 0xf8) == 0) {
        if ((dVar18 < (double)FLOAT_803e3648) && ((double)FLOAT_803e3658 < dVar18)) {
          iVar9 = 1;
        }
      }
      else if ((dVar18 < (double)FLOAT_803e365c) && ((double)FLOAT_803e3658 < dVar18)) {
        iVar9 = 1;
      }
    }
    break;
  case 2:
    if (iVar8 != 0) {
      if (iVar8 != 0) {
        iVar9 = 1;
      }
    }
    else {
      if (((*(byte *)(iVar5 + 0xaf) & 8) != 0) && (iVar6 = FUN_8001ffb4(0x2c), iVar6 != 0)) {
        *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7;
      }
      if ((*(byte *)(iVar5 + 0xaf) & 1) != 0) {
        *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
        FUN_800200e8(pfVar13[4],1);
      }
    }
    break;
  case 3:
    if ((dVar16 < (double)FLOAT_803e3654) && (iVar8 != 0)) {
      uStack100 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
      local_68 = 0x43300000;
      dVar18 = (double)((FLOAT_803e364c *
                        (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e3678)) /
                       FLOAT_803e3650);
      dVar16 = (double)FUN_80293e80(dVar18);
      dVar18 = (double)FUN_80294204(dVar18);
      dVar18 = (double)(-(float)((double)*(float *)(iVar14 + 8) * dVar16 +
                                (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar18)) +
                       (float)(dVar16 * (double)*(float *)(iVar7 + 0xc) +
                              (double)(float)(dVar18 * (double)*(float *)(iVar7 + 0x14))));
      if ((dVar18 < (double)FLOAT_803e366c) && ((double)FLOAT_803e3670 < dVar18)) {
        iVar9 = 1;
      }
    }
    break;
  case 4:
    *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7;
    if (iVar8 != 0) {
      piVar12 = (int *)(iVar6 + local_78 * 4);
      while ((local_78 < local_74 && (iVar9 == 0))) {
        unaff_r25 = *piVar12;
        if ((*(short *)(unaff_r25 + 0x46) == 0x7c) &&
           (fVar3 = *(float *)(unaff_r25 + 0xc) - *(float *)(iVar14 + 8),
           fVar4 = *(float *)(unaff_r25 + 0x14) - *(float *)(iVar14 + 0x10),
           dVar16 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar4 * fVar4)),
           dVar16 < (double)FLOAT_803e3660)) {
          uStack100 = (int)*(char *)(iVar14 + 0x18) << 8 ^ 0x80000000;
          local_68 = 0x43300000;
          dVar18 = (double)((FLOAT_803e364c *
                            (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e3678)) /
                           FLOAT_803e3650);
          dVar16 = (double)FUN_80293e80(dVar18);
          dVar18 = (double)FUN_80294204(dVar18);
          dVar18 = (double)(-(float)((double)*(float *)(iVar14 + 8) * dVar16 +
                                    (double)(float)((double)*(float *)(iVar14 + 0x10) * dVar18)) +
                           (float)(dVar16 * (double)*(float *)(unaff_r25 + 0xc) +
                                  (double)(float)(dVar18 * (double)*(float *)(unaff_r25 + 0x14))));
          if ((dVar18 < (double)FLOAT_803e3664) && ((double)FLOAT_803e3668 < dVar18)) {
            iVar9 = 1;
          }
        }
        piVar12 = piVar12 + 1;
        local_78 = local_78 + 1;
      }
      if (iVar9 == 0) {
        if (*(int *)(iVar5 + 0xf8) == 1) {
          *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 8;
        }
      }
      else {
        iVar6 = FUN_800374ec(iVar5,local_70,0,0);
        if (((iVar6 != 0) && (local_70[0] < 10)) && (7 < local_70[0])) {
          FUN_800378c4(unaff_r25,local_70[0],iVar5,0);
        }
        if ((dVar18 < (double)FLOAT_803e3648) && (*(int *)(iVar5 + 0xf8) == 0)) {
          *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 0x14;
        }
      }
    }
    break;
  case 5:
    iVar6 = FUN_8001ffb4(pfVar13[5]);
    if ((iVar6 != 0) && (iVar8 == 0)) {
      *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) & 0xf7;
      if ((*(byte *)(iVar5 + 0xaf) & 1) != 0) {
        *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
        FUN_800200e8(pfVar13[4],1);
        (**(code **)(*DAT_803dca54 + 0x48))(1,iVar5,0xffffffff);
        iVar8 = 1;
      }
    }
    if (iVar8 != 0) {
      iVar9 = 1;
      *(byte *)(iVar5 + 0xaf) = *(byte *)(iVar5 + 0xaf) | 8;
    }
    break;
  case 6:
    if (iVar8 != 0) {
      iVar9 = 1;
    }
  }
  if (*(int *)(iVar5 + 0xf8) == 0) {
    if (iVar9 != 0) {
      *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 1;
    }
  }
  else if (iVar9 == 0) {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 2;
  }
  *(int *)(iVar5 + 0xf8) = iVar9;
  if (((*(short *)(iVar5 + 0x46) == 0x13e) || (*(short *)(iVar5 + 0x46) == 0x151)) &&
     (*(char *)((int)pfVar13 + 0x21) != '\0')) {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 1;
  }
  do {
    iVar6 = FUN_800374ec(iVar5,local_70,0,0);
  } while (iVar6 != 0);
  iVar6 = 0;
  do {
    if ((int)(uint)*(byte *)(param_3 + 0x8b) <= iVar6) {
      if (*(int *)(iVar5 + 0xf4) == 0) {
        uVar10 = 0;
      }
      else {
        *(undefined4 *)(iVar5 + 0xf4) = 0;
        uVar10 = 3;
      }
      __psq_l0(auStack8,uVar15);
      __psq_l1(auStack8,uVar15);
      __psq_l0(auStack24,uVar15);
      __psq_l1(auStack24,uVar15);
      __psq_l0(auStack40,uVar15);
      __psq_l1(auStack40,uVar15);
      FUN_80286118(uVar10);
      return;
    }
    bVar1 = *(byte *)(param_3 + iVar6 + 0x81);
    if (bVar1 != 0) {
      if (bVar1 == 3) {
LAB_80178cdc:
        if (*(short *)(pfVar13 + 7) != 0) {
          FUN_8000bb18(iVar5);
        }
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          iVar7 = FUN_8000faac();
          if (FLOAT_803e3648 <=
              pfVar13[2] +
              *pfVar13 * *(float *)(iVar7 + 0xc) + pfVar13[1] * *(float *)(iVar7 + 0x14)) {
            if (*(short *)(iVar14 + 0x1a) != -1) {
              uVar11 = FUN_8001ffb4();
              FUN_800200e8((int)*(short *)(iVar14 + 0x1a),
                           uVar11 & 0xff ^ *(short *)(iVar14 + 0x1c) >> 8 & 0xffU);
            }
          }
          else if (*(short *)(iVar14 + 0x20) != -1) {
            uVar11 = FUN_8001ffb4();
            FUN_800200e8((int)*(short *)(iVar14 + 0x20),
                         uVar11 & 0xff ^ *(ushort *)(iVar14 + 0x1c) & 0xff);
          }
          if (dVar18 <= (double)FLOAT_803e3648) {
            sVar2 = *(short *)(iVar5 + 0x46);
            if (sVar2 == 0x205) {
              FUN_8003759c((double)FLOAT_803e3674,0x202,0,iVar5,0x30006,0);
            }
            else if (sVar2 < 0x205) {
              if (sVar2 == 0x1bb) {
                FUN_8003759c((double)FLOAT_803e3674,0x1b9,0,iVar5,0x30006,0);
              }
              else if (sVar2 < 0x1bb) {
                if (sVar2 == 0x1ad) {
                  FUN_8003759c((double)FLOAT_803e3674,0x1ac,0,iVar5,0x30006,0);
                }
                else if ((sVar2 < 0x1ad) && (sVar2 == 0x1a2)) {
                  FUN_8003759c((double)FLOAT_803e3674,0x19c,0,iVar5,0x30006,0);
                }
              }
              else if (sVar2 == 0x1ea) {
                FUN_8003759c((double)FLOAT_803e3674,0x1e7,0,iVar5,0x30006,0);
              }
            }
            else if (sVar2 == 0x238) {
              FUN_8003759c((double)FLOAT_803e3674,0x233,0,iVar5,0x30006,0);
            }
            else if (sVar2 < 0x238) {
              if (sVar2 == 0x21a) {
                FUN_8003759c((double)FLOAT_803e3674,0x217,0,iVar5,0x30006,0);
              }
            }
            else if (sVar2 == 0x23f) {
              FUN_8003759c((double)FLOAT_803e3674,0x23c,0,iVar5,0x30006,0);
            }
          }
          goto LAB_80178cdc;
        }
        if (bVar1 != 0) {
          iVar7 = FUN_8000faac();
          if (FLOAT_803e3648 <=
              pfVar13[2] +
              *pfVar13 * *(float *)(iVar7 + 0xc) + pfVar13[1] * *(float *)(iVar7 + 0x14)) {
            if (*(short *)(iVar14 + 0x1a) != -1) {
              uVar11 = FUN_8001ffb4();
              FUN_800200e8((int)*(short *)(iVar14 + 0x1a),
                           uVar11 & 0xff ^ *(short *)(iVar14 + 0x1c) >> 8 & 0xffU);
            }
          }
          else if (*(short *)(iVar14 + 0x20) != -1) {
            uVar11 = FUN_8001ffb4();
            FUN_800200e8((int)*(short *)(iVar14 + 0x20),
                         uVar11 & 0xff ^ *(ushort *)(iVar14 + 0x1c) & 0xff);
          }
          sVar2 = *(short *)(iVar5 + 0x46);
          if (sVar2 == 0x205) {
            FUN_8003759c((double)FLOAT_803e3674,0x202,0,iVar5,0x30005,0);
          }
          else if (sVar2 < 0x205) {
            if (sVar2 == 0x1bb) {
              FUN_8003759c((double)FLOAT_803e3674,0x1b9,0,iVar5,0x30005,0);
            }
            else if (sVar2 < 0x1bb) {
              if (sVar2 == 0x1ad) {
                FUN_8003759c((double)FLOAT_803e3674,0x1ac,0,iVar5,0x30005,0);
              }
              else if ((sVar2 < 0x1ad) && (sVar2 == 0x1a2)) {
                FUN_8003759c((double)FLOAT_803e3674,0x19c,0,iVar5,0x30005,0);
              }
            }
            else if (sVar2 == 0x1ea) {
              FUN_8003759c((double)FLOAT_803e3674,0x1e7,0,iVar5,0x30005,0);
            }
          }
          else if (sVar2 == 0x238) {
            FUN_8003759c((double)FLOAT_803e3674,0x233,0,iVar5,0x30005,0);
          }
          else if (sVar2 < 0x238) {
            if (sVar2 == 0x21a) {
              FUN_8003759c((double)FLOAT_803e3674,0x217,0,iVar5,0x30005,0);
            }
          }
          else if (sVar2 == 0x23f) {
            FUN_8003759c((double)FLOAT_803e3674,0x23c,0,iVar5,0x30005,0);
          }
        }
      }
      else if (bVar1 == 5) {
        if ((*(short *)((int)pfVar13 + 0x1e) != 0) && (iVar7 = FUN_8001ffb4(0xcbb), iVar7 == 0)) {
          FUN_8000bb18(iVar5,*(undefined2 *)((int)pfVar13 + 0x1e));
        }
      }
      else if (((bVar1 < 5) && (*(short *)(pfVar13 + 7) != 0)) &&
              (iVar7 = FUN_8000b5d0(iVar5), iVar7 != 0)) {
        FUN_8000b824(iVar5,*(undefined2 *)(pfVar13 + 7));
      }
      *(undefined *)(param_3 + iVar6 + 0x81) = 0;
    }
    iVar6 = iVar6 + 1;
  } while( true );
}

