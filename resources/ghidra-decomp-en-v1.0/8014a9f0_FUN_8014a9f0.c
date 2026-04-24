// Function: FUN_8014a9f0
// Entry: 8014a9f0
// Size: 3720 bytes

/* WARNING: Removing unreachable block (ram,0x8014b850) */
/* WARNING: Removing unreachable block (ram,0x8014b840) */
/* WARNING: Removing unreachable block (ram,0x8014b848) */
/* WARNING: Removing unreachable block (ram,0x8014b858) */

void FUN_8014a9f0(short *param_1,int param_2)

{
  byte bVar1;
  float fVar2;
  short sVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f28;
  double dVar11;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined auStack216 [4];
  undefined4 local_d4;
  short local_d0;
  short local_ce;
  short local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  short local_aa;
  char local_a5 [8];
  char local_9d;
  undefined auStack156 [68];
  longlong local_58;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  FUN_80003494(param_2 + 0x2c4,param_2 + 0x2b8,0xc);
  FUN_80003494(param_2 + 0x2b8,param_1 + 0x12,0xc);
  if ((*(uint *)(param_2 + 0x2e4) & 0x400) != 0) {
    FUN_8003b310(param_1,param_2 + 0x26c);
  }
  if ((*(int *)(param_2 + 0x29c) != 0) && ((*(uint *)(param_2 + 0x2e4) & 0x800) != 0)) {
    FUN_8003b0d0(param_1,*(int *)(param_2 + 0x29c),param_2 + 0x26c,0x19);
  }
  *(undefined *)(param_2 + 0x2f0) = *(undefined *)(param_2 + 0x2ef);
  uVar5 = *(uint *)(param_2 + 0x2dc);
  if ((uVar5 & 0x800) != 0) {
    FUN_80148d8c(param_1,param_2);
    goto LAB_8014b38c;
  }
  if ((uVar5 & 0x1000) != 0) {
    FUN_80148c18(param_1,param_2);
    goto LAB_8014b38c;
  }
  if ((uVar5 & 0x20000000) == 0) {
    if ((uVar5 & 0x100) != 0) {
      *(undefined *)(param_2 + 0x2ef) = 2;
      if (((*(uint *)(param_2 + 0x2dc) & 0x100) != 0) && ((*(uint *)(param_2 + 0x2e0) & 0x100) == 0)
         ) {
        *(float *)(param_2 + 0x308) =
             FLOAT_803e256c / (FLOAT_803e2570 * *(float *)(param_2 + 0x31c));
        *(undefined *)(param_2 + 0x323) = 1;
        FUN_80030334((double)FLOAT_803e2574,param_1,*(undefined *)(param_2 + 0x322),0x10);
        if (*(int *)(param_1 + 0x2a) != 0) {
          *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
        }
      }
      if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) == 0) {
        local_58 = (longlong)(int)(FLOAT_803e257c * *(float *)(param_1 + 0x4c));
        *(char *)(param_1 + 0x1b) = (char)(int)(FLOAT_803e257c * *(float *)(param_1 + 0x4c));
        param_1[3] = param_1[3] & 0xbfff;
      }
      else {
        *(float *)(param_2 + 0x308) = FLOAT_803e2578;
        *(undefined *)(param_2 + 0x323) = 0;
        FUN_80030334((double)FLOAT_803e2574,param_1,0,0);
        if (*(int *)(param_1 + 0x2a) != 0) {
          *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
        }
        *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xfffffeff;
        *(undefined *)(param_1 + 0x1b) = 0xff;
      }
      goto LAB_8014b38c;
    }
    *(undefined *)(param_2 + 0x2ef) = 5;
    sVar3 = param_1[0x23];
    if (sVar3 == 0x4d7) {
      FUN_8015652c(param_1,param_2);
      goto LAB_8014b38c;
    }
    if (sVar3 < 0x4d7) {
      if (sVar3 == 0x281) {
LAB_8014b270:
        FUN_80152040(param_1,param_2);
        goto LAB_8014b38c;
      }
      if (sVar3 < 0x281) {
        if (sVar3 == 0x13a) {
LAB_8014b260:
          FUN_80150910(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x13a) {
          if (sVar3 == 0xd8) goto LAB_8014b270;
          if ((sVar3 < 0xd8) && (sVar3 == 0x11)) goto LAB_8014b260;
        }
        else {
          if (sVar3 == 0x25d) {
            FUN_801557d4(param_1,param_2);
            goto LAB_8014b38c;
          }
          if ((sVar3 < 0x25d) && (sVar3 == 0x251)) {
            FUN_80154584(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
      }
      else {
        if (sVar3 == 0x427) {
          FUN_8014ff20(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x427) {
          if (sVar3 == 0x3fe) {
LAB_8014b2a0:
            FUN_80153040(param_1,param_2);
            goto LAB_8014b38c;
          }
          if ((sVar3 < 0x3fe) && (sVar3 == 0x369)) {
            FUN_80153e0c(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
        else {
          if (sVar3 == 0x458) {
            FUN_80156c34(param_1,param_2);
            goto LAB_8014b38c;
          }
          if (sVar3 < 0x458) {
            if (0x456 < sVar3) {
              FUN_80155f20(param_1,param_2);
              goto LAB_8014b38c;
            }
          }
          else if (sVar3 == 0x4ac) {
            FUN_80156da0(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
      }
    }
    else {
      if (sVar3 == 0x7a6) goto LAB_8014b260;
      if (sVar3 < 0x7a6) {
        if (sVar3 == 0x613) {
          FUN_80152514(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x613) {
          if (sVar3 < 0x5ba) {
            if (sVar3 == 0x58b) {
              FUN_8015383c(param_1,param_2);
              goto LAB_8014b38c;
            }
            if ((0x58a < sVar3) && (0x5b6 < sVar3)) goto LAB_8014b260;
          }
          else if (sVar3 == 0x5e1) goto LAB_8014b260;
        }
        else if (sVar3 < 0x6a2) {
          if (sVar3 == 0x642) {
            FUN_80152b90(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
        else if (sVar3 < 0x6a6) {
          FUN_80158494(param_1,param_2);
          goto LAB_8014b38c;
        }
      }
      else {
        if (sVar3 == 0x842) {
LAB_8014b330:
          FUN_8015abfc(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x842) {
          if (sVar3 != 0x7c7) {
            if (sVar3 < 0x7c7) {
              if (0x7c5 < sVar3) goto LAB_8014b2a0;
            }
            else if (sVar3 < 0x7c9) {
              FUN_80159958(param_1,param_2);
              goto LAB_8014b38c;
            }
          }
        }
        else {
          if (sVar3 == 0x851) {
            FUN_8015addc(param_1,param_2);
            goto LAB_8014b38c;
          }
          if ((sVar3 < 0x851) && (sVar3 == 0x84b)) goto LAB_8014b330;
        }
      }
    }
    FUN_8014ff20(param_1,param_2);
    goto LAB_8014b38c;
  }
  if ((uVar5 & 0x400) == 0) {
    *(undefined *)(param_2 + 0x2ef) = 4;
    sVar3 = param_1[0x23];
    if (sVar3 == 0x4d7) {
      FUN_8015625c(param_1,param_2);
      goto LAB_8014b38c;
    }
    if (sVar3 < 0x4d7) {
      if (sVar3 == 0x281) {
LAB_8014aed8:
        FUN_80152040(param_1,param_2);
        goto LAB_8014b38c;
      }
      if (sVar3 < 0x281) {
        if (sVar3 == 0x13a) {
LAB_8014aec8:
          FUN_80150edc(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x13a) {
          if (sVar3 == 0xd8) goto LAB_8014aed8;
          if ((sVar3 < 0xd8) && (sVar3 == 0x11)) goto LAB_8014aec8;
        }
        else {
          if (sVar3 == 0x25d) {
            FUN_80155884(param_1,param_2);
            goto LAB_8014b38c;
          }
          if ((sVar3 < 0x25d) && (sVar3 == 0x251)) {
            FUN_80154870(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
      }
      else {
        if (sVar3 == 0x427) {
          FUN_8014ff20(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x427) {
          if (sVar3 == 0x3fe) {
LAB_8014af08:
            FUN_80153248(param_1,param_2);
            goto LAB_8014b38c;
          }
          if ((sVar3 < 0x3fe) && (sVar3 == 0x369)) {
            FUN_801540a0(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
        else {
          if (sVar3 == 0x458) {
            FUN_80156b0c(param_1,param_2);
            goto LAB_8014b38c;
          }
          if (sVar3 < 0x458) {
            if (0x456 < sVar3) {
              FUN_80156010(param_1,param_2);
              goto LAB_8014b38c;
            }
          }
          else if (sVar3 == 0x4ac) {
            FUN_80157004(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
      }
    }
    else {
      if (sVar3 == 0x7a6) goto LAB_8014aec8;
      if (sVar3 < 0x7a6) {
        if (sVar3 == 0x613) {
          FUN_80152514(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x613) {
          if (sVar3 < 0x5ba) {
            if (sVar3 == 0x58b) {
              FUN_80153bfc(param_1,param_2);
              goto LAB_8014b38c;
            }
            if ((0x58a < sVar3) && (0x5b6 < sVar3)) goto LAB_8014aec8;
          }
          else if (sVar3 == 0x5e1) goto LAB_8014aec8;
        }
        else if (sVar3 < 0x6a2) {
          if (sVar3 == 0x642) {
            FUN_80152b90(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
        else if (sVar3 < 0x6a6) {
          FUN_80158c2c(param_1,param_2);
          goto LAB_8014b38c;
        }
      }
      else {
        if (sVar3 == 0x842) {
LAB_8014af98:
          FUN_8015a924(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x842) {
          if (sVar3 != 0x7c7) {
            if (sVar3 < 0x7c7) {
              if (0x7c5 < sVar3) goto LAB_8014af08;
            }
            else if (sVar3 < 0x7c9) {
              FUN_80159fcc(param_1,param_2);
              goto LAB_8014b38c;
            }
          }
        }
        else {
          if (sVar3 == 0x851) {
            FUN_8015ad60(param_1,param_2);
            goto LAB_8014b38c;
          }
          if ((sVar3 < 0x851) && (sVar3 == 0x84b)) goto LAB_8014af98;
        }
      }
    }
    FUN_8014ff20(param_1,param_2);
    goto LAB_8014b38c;
  }
  *(undefined *)(param_2 + 0x2ef) = 3;
  sVar3 = param_1[0x23];
  if (sVar3 == 0x4d7) {
    FUN_8015625c(param_1,param_2);
    goto LAB_8014b38c;
  }
  if (sVar3 < 0x4d7) {
    if (sVar3 == 0x281) {
LAB_8014ac54:
      FUN_80152040(param_1,param_2);
      goto LAB_8014b38c;
    }
    if (sVar3 < 0x281) {
      if (sVar3 == 0x13a) {
LAB_8014ac44:
        FUN_8015165c(param_1,param_2);
        goto LAB_8014b38c;
      }
      if (sVar3 < 0x13a) {
        if (sVar3 == 0xd8) goto LAB_8014ac54;
        if ((sVar3 < 0xd8) && (sVar3 == 0x11)) goto LAB_8014ac44;
      }
      else {
        if (sVar3 == 0x25d) {
          FUN_80155948(param_1,param_2);
          goto LAB_8014b38c;
        }
        if ((sVar3 < 0x25d) && (sVar3 == 0x251)) {
          FUN_80154870(param_1,param_2);
          goto LAB_8014b38c;
        }
      }
    }
    else {
      if (sVar3 == 0x427) {
        FUN_8014ff24(param_1,param_2);
        goto LAB_8014b38c;
      }
      if (sVar3 < 0x427) {
        if (sVar3 == 0x3fe) {
LAB_8014ac84:
          FUN_80153248(param_1,param_2);
          goto LAB_8014b38c;
        }
        if ((sVar3 < 0x3fe) && (sVar3 == 0x369)) {
          FUN_801540a0(param_1,param_2);
          goto LAB_8014b38c;
        }
      }
      else {
        if (sVar3 == 0x458) {
          FUN_80156b0c(param_1,param_2);
          goto LAB_8014b38c;
        }
        if (sVar3 < 0x458) {
          if (0x456 < sVar3) {
            FUN_80156010(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
        else if (sVar3 == 0x4ac) {
          FUN_80157558(param_1,param_2);
          goto LAB_8014b38c;
        }
      }
    }
  }
  else {
    if (sVar3 == 0x7a6) goto LAB_8014ac44;
    if (sVar3 < 0x7a6) {
      if (sVar3 == 0x613) {
        FUN_80152514(param_1,param_2);
        goto LAB_8014b38c;
      }
      if (sVar3 < 0x613) {
        if (sVar3 < 0x5ba) {
          if (sVar3 == 0x58b) {
            FUN_80153bfc(param_1,param_2);
            goto LAB_8014b38c;
          }
          if ((0x58a < sVar3) && (0x5b6 < sVar3)) goto LAB_8014ac44;
        }
        else if (sVar3 == 0x5e1) goto LAB_8014ac44;
      }
      else if (sVar3 < 0x6a2) {
        if (sVar3 == 0x642) {
          FUN_80152b90(param_1,param_2);
          goto LAB_8014b38c;
        }
      }
      else if (sVar3 < 0x6a6) {
        FUN_80159284(param_1,param_2);
        goto LAB_8014b38c;
      }
    }
    else {
      if (sVar3 == 0x842) {
LAB_8014ad14:
        FUN_8015a924(param_1,param_2);
        goto LAB_8014b38c;
      }
      if (sVar3 < 0x842) {
        if (sVar3 != 0x7c7) {
          if (sVar3 < 0x7c7) {
            if (0x7c5 < sVar3) goto LAB_8014ac84;
          }
          else if (sVar3 < 0x7c9) {
            FUN_80159958(param_1,param_2);
            goto LAB_8014b38c;
          }
        }
      }
      else {
        if (sVar3 == 0x851) {
          FUN_8015ad60(param_1,param_2);
          goto LAB_8014b38c;
        }
        if ((sVar3 < 0x851) && (sVar3 == 0x84b)) goto LAB_8014ad14;
      }
    }
  }
  FUN_8014ff24(param_1,param_2);
LAB_8014b38c:
  if (*(char *)(param_2 + 0x2ef) == *(char *)(param_2 + 0x2f0)) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0x7fffffff;
  }
  else {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x80000000;
  }
  local_9d = '\0';
  iVar6 = FUN_8002fa48((double)*(float *)(param_2 + 0x308),(double)FLOAT_803db414,param_1,&local_b8)
  ;
  if (iVar6 == 0) {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xbfffffff;
  }
  else {
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x40000000;
  }
  *(undefined2 *)(param_2 + 0x2f8) = 0;
  pfVar7 = &local_b8;
  for (iVar6 = 0; iVar6 < local_9d; iVar6 = iVar6 + 1) {
    *(ushort *)(param_2 + 0x2f8) =
         *(ushort *)(param_2 + 0x2f8) | (ushort)(1 << (int)*(char *)((int)pfVar7 + 0x13));
    pfVar7 = (float *)((int)pfVar7 + 1);
  }
  dVar13 = (double)FLOAT_803e2574;
  if (((((*(uint *)(param_2 + 0x2e4) & 0x20) != 0) && ((*(uint *)(param_2 + 0x2e4) & 0x400000) == 0)
       ) && ((*(uint *)(param_2 + 0x2dc) & 0x1800) == 0)) && ((*(byte *)(param_2 + 0x323) & 4) == 0)
     ) {
    dVar13 = -(double)(*(float *)(param_2 + 0x300) * FLOAT_803db414 - *(float *)(param_1 + 0x14));
  }
  fVar2 = *(float *)(param_1 + 0x12);
  fVar4 = FLOAT_803e25cc;
  if ((FLOAT_803e25cc <= fVar2) && (fVar4 = fVar2, FLOAT_803e25d0 < fVar2)) {
    fVar4 = FLOAT_803e25d0;
  }
  *(float *)(param_1 + 0x12) = fVar4;
  fVar2 = *(float *)(param_1 + 0x14);
  fVar4 = FLOAT_803e25cc;
  if ((FLOAT_803e25cc <= fVar2) && (fVar4 = fVar2, FLOAT_803e25d0 < fVar2)) {
    fVar4 = FLOAT_803e25d0;
  }
  *(float *)(param_1 + 0x14) = fVar4;
  dVar10 = (double)*(float *)(param_1 + 0x16);
  dVar9 = (double)FLOAT_803e25cc;
  if ((dVar9 <= dVar10) && (dVar9 = dVar10, (double)FLOAT_803e25d0 < dVar10)) {
    dVar9 = (double)FLOAT_803e25d0;
  }
  *(float *)(param_1 + 0x16) = (float)dVar9;
  iVar6 = 0;
  uVar5 = *(uint *)(param_2 + 0x2e4);
  if (((uVar5 & 0x80) == 0) || (*(char *)(param_2 + 0x323) == '\0')) {
    if ((uVar5 & 0x100) == 0) {
      if ((uVar5 & 0x10) != 0) {
        iVar6 = 3;
      }
    }
    else {
      iVar6 = 2;
    }
  }
  else {
    iVar6 = 1;
  }
  if (((uVar5 & 0x200) != 0) && ((*(uint *)(param_2 + 0x2dc) & 0x4010) != 0)) {
    iVar6 = 3;
  }
  if (iVar6 == 1) {
    dVar12 = (double)FLOAT_803e2574;
    bVar1 = *(byte *)(param_2 + 0x323);
    dVar9 = dVar12;
    if ((bVar1 & 2) != 0) {
      dVar10 = (double)local_b8;
      dVar9 = (double)(float)(dVar10 * (double)FLOAT_803db418);
    }
    dVar11 = dVar12;
    if ((bVar1 & 4) != 0) {
      dVar10 = (double)local_b4;
      dVar11 = (double)(float)(dVar10 * (double)FLOAT_803db418);
    }
    if ((bVar1 & 1) != 0) {
      dVar10 = -(double)local_b0;
      dVar12 = (double)(float)(dVar10 * (double)FLOAT_803db418);
    }
    if ((bVar1 & 8) != 0) {
      *param_1 = *param_1 + local_aa;
    }
    local_d0 = *param_1;
    local_ce = param_1[1];
    local_cc = param_1[2];
    local_c8 = FLOAT_803e256c;
    local_c4 = FLOAT_803e2574;
    local_c0 = FLOAT_803e2574;
    local_bc = FLOAT_803e2574;
    FUN_80021ee8(dVar10,auStack156,&local_d0);
    if ((*(byte *)(param_2 + 0x323) & 4) == 0) {
      FUN_800226cc(dVar9,(double)FLOAT_803e2574,-dVar12,auStack156,param_1 + 0x12,auStack216,
                   param_1 + 0x16);
    }
    else {
      FUN_800226cc(dVar9,dVar11,-dVar12,auStack156,param_1 + 0x12,param_1 + 0x14,param_1 + 0x16);
    }
  }
  else if (iVar6 == 2) {
    FUN_802931a0((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                         *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
    iVar6 = FUN_8002f5d4(param_1,&local_d4);
    if (iVar6 != 0) {
      *(undefined4 *)(param_2 + 0x308) = local_d4;
    }
  }
  else if ((iVar6 == 3) && ((*(byte *)(param_2 + 0x2f1) & 0x80) == 0)) {
    dVar9 = (double)FUN_80292b44((double)*(float *)(param_2 + 0x304),(double)FLOAT_803db414);
    *(float *)(param_1 + 0x12) = (float)((double)*(float *)(param_1 + 0x12) * dVar9);
    dVar9 = (double)FUN_80292b44((double)*(float *)(param_2 + 0x304),(double)FLOAT_803db414);
    *(float *)(param_1 + 0x14) = (float)((double)*(float *)(param_1 + 0x14) * dVar9);
    dVar9 = (double)FUN_80292b44((double)*(float *)(param_2 + 0x304),(double)FLOAT_803db414);
    *(float *)(param_1 + 0x16) = (float)((double)*(float *)(param_1 + 0x16) * dVar9);
  }
  FUN_8014a5fc(param_1,param_2);
  if (((*(uint *)(param_2 + 0x2e4) & 0x400000) == 0) &&
     ((*(uint *)(param_2 + 0x2dc) & 0x8100000) == 0)) {
    if ((*(uint *)(param_2 + 0x2e4) & 0x20) == 0) {
      if ((*(byte *)(param_2 + 0x2f1) & 0x80) == 0) {
        FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                     (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                     (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
      }
    }
    else if ((*(byte *)(param_2 + 0x2f1) & 0x80) == 0) {
      FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                   (double)(-(FLOAT_803e25d4 *
                              *(float *)(param_2 + 0x300) * FLOAT_803db414 * FLOAT_803db414 -
                             (*(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8))
                             ) - *(float *)(param_1 + 8)),
                   (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
      *(float *)(param_1 + 0x14) = (float)dVar13;
    }
  }
  else if ((*(byte *)(param_2 + 0x2f1) & 0x80) == 0) {
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  return;
}

