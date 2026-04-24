// Function: FUN_8020dfa8
// Entry: 8020dfa8
// Size: 3392 bytes

/* WARNING: Removing unreachable block (ram,0x8020ecb8) */
/* WARNING: Removing unreachable block (ram,0x8020ea50) */
/* WARNING: Removing unreachable block (ram,0x8020e530) */
/* WARNING: Removing unreachable block (ram,0x8020e9f0) */
/* WARNING: Removing unreachable block (ram,0x8020ecb0) */
/* WARNING: Removing unreachable block (ram,0x8020ecc0) */

void FUN_8020dfa8(short *param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  char cVar6;
  short *psVar7;
  short sVar8;
  byte bVar9;
  int *piVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f29;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined2 local_a8;
  undefined2 local_a6;
  undefined2 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  undefined auStack148 [28];
  undefined4 local_78;
  uint uStack116;
  double local_70;
  longlong local_68;
  undefined4 local_60;
  uint uStack92;
  double local_58;
  undefined4 local_50;
  uint uStack76;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  piVar10 = *(int **)(param_1 + 0x5c);
  psVar7 = *(short **)(param_1 + 0x26);
  sVar8 = *psVar7;
  if (sVar8 < 0x5ed) {
    if (sVar8 != 0x5dd) {
      if (sVar8 < 0x5dd) {
        if (sVar8 == 0x5da) {
          *param_1 = *param_1 + (short)*(char *)(piVar10 + 0xa0);
          param_1[1] = param_1[1] + (short)*(char *)((int)piVar10 + 0x27f);
          param_1[2] = param_1[2] + (short)*(char *)((int)piVar10 + 0x27e);
          *(char *)(piVar10 + 0x9f) = *(char *)(piVar10 + 0x9f) + '\x02';
          uStack76 = (int)(short)((ushort)*(byte *)(piVar10 + 0x9f) << 8) ^ 0x80000000;
          local_50 = 0x43300000;
          dVar12 = (double)FUN_80294204((double)((FLOAT_803e6680 *
                                                 (float)((double)CONCAT44(0x43300000,uStack76) -
                                                        DOUBLE_803e6670)) / FLOAT_803e6684));
          *(float *)(param_1 + 4) =
               FLOAT_803e669c * (float)((double)FLOAT_803e6678 + dVar12) + FLOAT_803e6698;
          goto LAB_8020ecb0;
        }
        if (0x5d9 < sVar8) {
          if (sVar8 < 0x5dc) {
            *param_1 = 0x21a8;
            *(float *)(param_1 + 4) = FLOAT_803e66a0;
          }
          else {
            if (*(int *)(param_1 + 0x7a) == 0) {
              uVar4 = FUN_8002e0b4(0x431dc);
              *(undefined4 *)(param_1 + 0x7a) = uVar4;
              FUN_80037d2c(param_1,*(undefined4 *)(param_1 + 0x7a),0);
            }
            if (*(int *)(param_1 + 0x7c) == 0) {
              uVar4 = FUN_8002e0b4(0x4325b);
              *(undefined4 *)(param_1 + 0x7c) = uVar4;
              FUN_80037d2c(param_1,*(undefined4 *)(param_1 + 0x7c),0);
            }
            iVar5 = FUN_800394ac(param_1,0,0);
            if (iVar5 != 0) {
              sVar8 = -*(short *)(iVar5 + 8) + -2;
              if (sVar8 < 0) {
                sVar8 = -*(short *)(iVar5 + 8) + 0x270e;
              }
              *(short *)(iVar5 + 8) = -sVar8;
            }
          }
          goto LAB_8020ecb0;
        }
        if ((0x5d8 < sVar8) || (sVar8 < 0x5d5)) goto LAB_8020ecb0;
      }
      else {
        if (sVar8 == 0x5e2) {
          bVar9 = *(byte *)((int)psVar7 + 0x1b);
          if (bVar9 == 1) {
            param_1[1] = param_1[1] + 100;
          }
          else if (bVar9 == 0) {
            *param_1 = *param_1 + 100;
          }
          else if (bVar9 < 3) {
            param_1[2] = param_1[2] + 100;
          }
          goto LAB_8020ecb0;
        }
        if (0x5e1 < sVar8) {
          if (sVar8 < 0x5e4) {
            if ((uint)*(byte *)(piVar10 + 0x9f) != (int)*(char *)((int)param_1 + 0xad)) {
              FUN_8002b884();
            }
            if ((int)*(char *)((int)piVar10 + 0x27e) != (-DAT_803dc868 | DAT_803dc868) >> 0x1f) {
              if (DAT_803dc868 == 0) {
                FUN_80030334((double)FLOAT_803e665c,param_1,0,0);
              }
              else {
                FUN_80030334((double)FLOAT_803e665c,param_1,1,0);
              }
            }
            *(byte *)((int)piVar10 + 0x27e) =
                 (byte)((byte)(-DAT_803dc868 >> 0x18) | (byte)(DAT_803dc868 >> 0x18)) >> 7;
            FUN_8002fa48((double)*(float *)(&DAT_8032a200 + (uint)*(byte *)(piVar10 + 0x9f) * 4),
                         (double)FLOAT_803db414,param_1,auStack148);
            if ((*(char *)((int)piVar10 + 0x27d) == '\0') && (*piVar10 != 0)) {
              FUN_8001f384();
              *piVar10 = 0;
            }
          }
          goto LAB_8020ecb0;
        }
        if (sVar8 != 0x5df) goto LAB_8020ecb0;
        FUN_8020d9e4();
      }
      if ((*(int *)(param_1 + 0x7c) == 0) && (iVar5 = FUN_8002e0b4(piVar10[0x9e]), iVar5 != 0)) {
        *(float *)(iVar5 + 8) = *(float *)(iVar5 + 8) * FLOAT_803e6668;
        *(undefined *)(iVar5 + 0x36) = 0x96;
        *(ushort *)(iVar5 + 6) = *(ushort *)(iVar5 + 6) | 0x4000;
        FUN_80037d2c(param_1,iVar5,0);
        *(undefined4 *)(param_1 + 0x7c) = 1;
      }
      if ((*(int *)(param_1 + 0x7a) != 0) && (piVar10[0x9d] != 0)) {
        iVar5 = FUN_8000faac();
        dVar15 = (double)(*(float *)(iVar5 + 0xc) - *(float *)(param_1 + 6));
        dVar13 = (double)(*(float *)(iVar5 + 0x10) - *(float *)(param_1 + 8));
        dVar14 = (double)(*(float *)(iVar5 + 0x14) - *(float *)(param_1 + 10));
        dVar12 = (double)FUN_802931a0((double)(float)(dVar14 * dVar14 +
                                                     (double)(float)(dVar15 * dVar15 +
                                                                    (double)(float)(dVar13 * dVar13)
                                                                    )));
        if ((double)FLOAT_803e665c < dVar12) {
          dVar15 = (double)(float)(dVar15 / dVar12);
          dVar13 = (double)(float)(dVar13 / dVar12);
          dVar14 = (double)(float)(dVar14 / dVar12);
        }
        dVar12 = (double)FLOAT_803e66a8;
        *(float *)(piVar10[0x9d] + 0xc) = (float)(dVar12 * dVar15 + (double)*(float *)(param_1 + 6))
        ;
        *(float *)(piVar10[0x9d] + 0x10) =
             (float)(dVar12 * dVar13 + (double)*(float *)(param_1 + 8));
        *(float *)(piVar10[0x9d] + 0x14) =
             (float)(dVar12 * dVar14 + (double)*(float *)(param_1 + 10));
      }
      if (*(char *)((int)piVar10 + 0x27d) == '\0') {
        if (*piVar10 != 0) {
          FUN_8001f384();
          *piVar10 = 0;
        }
      }
      else {
        cVar6 = FUN_8012ddac();
        if (((cVar6 == '\0') && (iVar5 = (**(code **)(*DAT_803dca4c + 0x14))(), iVar5 != 0)) &&
           (DAT_803ddd34 == 0)) {
          if (*piVar10 == 0) {
            iVar5 = FUN_8001f4c8(param_1,1);
            *piVar10 = iVar5;
            if (*piVar10 != 0) {
              FUN_8001db2c(*piVar10,2);
              FUN_8001dd88((double)FLOAT_803e665c,(double)FLOAT_803e66ac,(double)FLOAT_803e665c,
                           *piVar10);
              FUN_8001daf0(*piVar10,0xff,0,0,0xff);
              FUN_8001dab8(*piVar10,0,0,0,0xff);
              FUN_8001db6c((double)FLOAT_803e665c,*piVar10,1);
              FUN_8001dc38((double)FLOAT_803e66b0,(double)FLOAT_803e66b4,*piVar10);
              FUN_8001d620(*piVar10,2,0x3c);
              FUN_8001dc90((double)FLOAT_803e665c,(double)FLOAT_803e6644,(double)FLOAT_803e665c,
                           *piVar10);
            }
          }
        }
        else if (*piVar10 != 0) {
          FUN_8001f384();
          *piVar10 = 0;
        }
        *(undefined *)(*(int *)(DAT_803ddd30 + 0xb8) + 0x27d) = 1;
        *(undefined4 *)(DAT_803ddd30 + 0xc) = *(undefined4 *)(param_1 + 6);
        *(float *)(DAT_803ddd30 + 0x10) = FLOAT_803e66b8 + *(float *)(param_1 + 8);
        *(undefined4 *)(DAT_803ddd30 + 0x14) = *(undefined4 *)(param_1 + 10);
        iVar5 = FUN_8002e0b4(0x4300c);
        if ((iVar5 == 0) || ((*(ushort *)(iVar5 + 6) & 0x4000) == 0)) {
          FUN_8002b884(DAT_803ddd30,0);
        }
        else {
          FUN_8002b884(DAT_803ddd30,1);
        }
      }
      goto LAB_8020ecb0;
    }
  }
  else {
    if (sVar8 == 0x61e) {
      param_1[1] = 0x3448;
      *param_1 = 0x4000;
      bVar9 = *(byte *)((int)psVar7 + 0x1b);
      if (bVar9 == 1) {
        param_1[2] = param_1[2] + -0x10;
      }
      else if (bVar9 == 0) {
        param_1[2] = param_1[2] + -0xe;
      }
      else if (bVar9 < 3) {
        param_1[2] = param_1[2] + -0x13;
      }
      if (*(char *)(piVar10 + 0x9f) == '\0') {
        bVar9 = *(byte *)((int)psVar7 + 0x1b);
        if (bVar9 == 1) {
          FUN_8020dbc4(param_1,0xa5,0xbe,0xfffffff8,8,0x4b,0x6f3);
          FUN_8020dbc4(param_1,0xa5,0xbe,0xfffffff6,10,0x4b,0x6f4);
          FUN_8020dbc4(param_1,0xa5,0xbe,0xfffffff8,8,0x4b,0x6f5);
          FUN_8020dbc4(param_1,0xa5,0xbe,0xfffffff6,10,0x32,0x6f6);
          FUN_8020dbc4(param_1,0xa5,0xbe,0xfffffff8,8,0x4b,0x6f7);
          FUN_8020dbc4(param_1,0xa5,0xbe,0xfffffff6,10,0x32,0x6f8);
        }
        else if (bVar9 == 0) {
          FUN_8020dbc4(param_1,0xfa,0x113,0xfffffffb,5,0x4b,0x6f3);
          FUN_8020dbc4(param_1,0xfa,0x113,0xfffffff9,7,0x4b,0x6f4);
          FUN_8020dbc4(param_1,0xfa,0x113,0xfffffffb,5,0x4b,0x6f5);
          FUN_8020dbc4(param_1,0xfa,0x113,0xfffffff9,7,0x32,0x6f6);
          FUN_8020dbc4(param_1,0xfa,0x113,0xfffffffb,5,0x4b,0x6f7);
          FUN_8020dbc4(param_1,0xfa,0x113,0xfffffff9,7,0x32,0x6f8);
        }
        else if (bVar9 < 3) {
          FUN_8020dbc4(param_1,0x78,0x91,0xfffffffb,5,0x32,0x6f3);
          FUN_8020dbc4(param_1,0x78,0x91,0xfffffff9,7,0x32,0x6f4);
          FUN_8020dbc4(param_1,0x78,0x91,0xfffffffb,5,0x32,0x6f5);
          FUN_8020dbc4(param_1,0x78,0x91,0xfffffff9,7,0x19,0x6f6);
          FUN_8020dbc4(param_1,0x78,0x91,0xfffffffb,5,0x32,0x6f7);
          FUN_8020dbc4(param_1,0x78,0x91,0xfffffff9,7,0x19,0x6f8);
        }
        *(undefined *)(piVar10 + 0x9f) = 1;
      }
      goto LAB_8020ecb0;
    }
    if (0x61d < sVar8) {
      if (sVar8 == 0x80f) {
        if ((piVar10[0x9c] < 0x8001) && (-1 < piVar10[0x9c])) {
          iVar5 = FUN_8002e0b4(0x42fe7);
          iVar3 = FUN_8002e0b4(0x4305a);
          dVar12 = DOUBLE_803e6670;
          if ((iVar5 != 0) && (iVar3 != 0)) {
            local_70 = (double)CONCAT44(0x43300000,(int)*(char *)(piVar10 + 0xa0) ^ 0x80000000);
            uStack116 = piVar10[0x9c] ^ 0x80000000;
            local_78 = 0x43300000;
            iVar1 = (int)((float)(local_70 - DOUBLE_803e6670) * FLOAT_803db414 +
                         (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e6670));
            local_68 = (longlong)iVar1;
            piVar10[0x9c] = iVar1;
            uStack92 = piVar10[0x9c] ^ 0x80000000;
            local_60 = 0x43300000;
            dVar12 = (double)FUN_80294204((double)((FLOAT_803e6680 *
                                                   (float)((double)CONCAT44(0x43300000,uStack92) -
                                                          dVar12)) / FLOAT_803e6684));
            local_a0 = (float)((double)(float)piVar10[0x98] * dVar12);
            local_9c = FLOAT_803e665c;
            local_58 = (double)CONCAT44(0x43300000,piVar10[0x9c] ^ 0x80000000);
            dVar12 = (double)FUN_80293e80((double)((FLOAT_803e6680 *
                                                   (float)(local_58 - DOUBLE_803e6670)) /
                                                  FLOAT_803e6684));
            local_98 = (float)((double)(float)piVar10[0x97] * dVar12);
            dVar13 = (double)(*(float *)(iVar3 + 0xc) - *(float *)(iVar5 + 0xc));
            dVar12 = (double)(*(float *)(iVar3 + 0x14) - *(float *)(iVar5 + 0x14));
            local_a8 = FUN_800217c0(dVar13,dVar12);
            local_a6 = 0;
            local_a4 = 0;
            FUN_80021ac8(&local_a8,&local_a0);
            *(float *)(param_1 + 6) = local_a0 + (float)((double)*(float *)(iVar5 + 0xc) - dVar13);
            uStack76 = piVar10[0x9c] ^ 0x80000000;
            local_50 = 0x43300000;
            *(float *)(param_1 + 8) =
                 (float)piVar10[0x99] +
                 ((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e6670) *
                 ((float)piVar10[0x9a] - (float)piVar10[0x99])) / FLOAT_803e6688;
            *(float *)(param_1 + 10) = local_98 + (float)((double)*(float *)(iVar5 + 0x14) - dVar12)
            ;
          }
          *(float *)(param_1 + 0x12) =
               FLOAT_803db418 * (*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40));
          *(float *)(param_1 + 0x16) =
               FLOAT_803db418 * (*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44));
          local_a0 = *(float *)(param_1 + 0x12);
          local_9c = FLOAT_803e665c;
          local_98 = *(float *)(param_1 + 0x16);
          FUN_80098928((double)(FLOAT_803e6668 * (float)piVar10[0x9b]),param_1,2,0xdf,8,&local_a0);
          dVar12 = DOUBLE_803e6670;
          uStack76 = (int)*param_1 ^ 0x80000000;
          local_50 = 0x43300000;
          iVar5 = (int)(FLOAT_803e668c * FLOAT_803db414 +
                       (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e6670));
          local_58 = (double)(longlong)iVar5;
          *param_1 = (short)iVar5;
          uStack92 = (int)param_1[1] ^ 0x80000000;
          local_60 = 0x43300000;
          iVar5 = (int)(FLOAT_803e6690 * FLOAT_803db414 +
                       (float)((double)CONCAT44(0x43300000,uStack92) - dVar12));
          local_68 = (longlong)iVar5;
          param_1[1] = (short)iVar5;
          if ((*piVar10 != 0) && (iVar5 = FUN_8001db64(), iVar5 != 0)) {
            FUN_8001d6b0(*piVar10);
          }
        }
        else {
          if (*piVar10 != 0) {
            FUN_8001db6c((double)FLOAT_803e6678,*piVar10,0);
          }
          uStack116 = (uint)*(byte *)(param_1 + 0x1b);
          local_78 = 0x43300000;
          iVar5 = (int)-(FLOAT_803e667c * FLOAT_803db414 -
                        (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e66c0));
          local_70 = (double)(longlong)iVar5;
          if (iVar5 < 0) {
            iVar5 = 0;
          }
          *(char *)(param_1 + 0x1b) = (char)iVar5;
          if (*(char *)(param_1 + 0x1b) == '\0') {
            FUN_8002cbc4(param_1);
          }
        }
      }
      else if ((sVar8 < 0x80f) && (sVar8 == 0x740)) {
        FUN_8002fa48((double)FLOAT_803e6694,(double)FLOAT_803db414,param_1,0);
        *param_1 = (short)(int)(FLOAT_803e668c * FLOAT_803db414 +
                               (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                      DOUBLE_803e6670));
      }
      goto LAB_8020ecb0;
    }
    if (sVar8 == 0x5f5) {
      *param_1 = *param_1 + 1;
      goto LAB_8020ecb0;
    }
    if (0x5f4 < sVar8) {
      if (sVar8 == 0x602) {
        FUN_8002fa48((double)FLOAT_803e66a4,(double)FLOAT_803db414,param_1,auStack148);
      }
      goto LAB_8020ecb0;
    }
    if (0x5f3 < sVar8) goto LAB_8020ecb0;
  }
  if (*(char *)((int)piVar10 + 0x27d) == '\x02') {
    for (bVar9 = 0; bVar9 < 0x16; bVar9 = bVar9 + 1) {
      uVar2 = (uint)bVar9;
      FUN_8003842c(param_1,uVar2,piVar10 + uVar2 * 6 + 4,piVar10 + uVar2 * 6 + 5,
                   piVar10 + uVar2 * 6 + 6,0);
    }
  }
LAB_8020ecb0:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  return;
}

