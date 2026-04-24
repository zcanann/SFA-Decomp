// Function: FUN_80030aec
// Entry: 80030aec
// Size: 988 bytes

/* WARNING: Removing unreachable block (ram,0x80030ea0) */
/* WARNING: Removing unreachable block (ram,0x80030e90) */
/* WARNING: Removing unreachable block (ram,0x80030e88) */
/* WARNING: Removing unreachable block (ram,0x80030e98) */
/* WARNING: Removing unreachable block (ram,0x80030ea8) */

void FUN_80030aec(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4,int **param_5,
                 float *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float *pfVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  float *pfVar15;
  int iVar16;
  undefined4 uVar17;
  double extraout_f1;
  double dVar18;
  double dVar19;
  undefined8 in_f27;
  double dVar20;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar21;
  undefined8 in_f30;
  double dVar22;
  undefined8 in_f31;
  double dVar23;
  undefined8 uVar24;
  float *local_c8;
  float local_c4;
  float *local_c0;
  float *local_bc;
  float local_b8;
  float local_b4;
  float *local_b0;
  float local_ac;
  float local_a8;
  float *local_a4;
  float local_a0;
  float local_9c;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar17 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  uVar24 = FUN_802860b4();
  pfVar5 = (float *)((ulonglong)uVar24 >> 0x20);
  iVar9 = (int)uVar24;
  iVar12 = 0;
  if (iVar9 == 0) {
    uVar6 = 0;
  }
  else {
    iVar10 = *param_3;
    iVar14 = *(int *)(iVar9 + 4);
    dVar21 = (double)(float)(extraout_f1 + extraout_f1);
    *param_5 = param_4;
    *param_6 = FLOAT_803de910;
    dVar20 = extraout_f1;
    iVar7 = FUN_8002856c(param_3,0);
    local_a4 = *(float **)(iVar7 + 0xc);
    local_a0 = *(float *)(iVar7 + 0x1c);
    local_9c = *(float *)(iVar7 + 0x2c);
    dVar18 = (double)FUN_802931a0((double)((local_9c - pfVar5[2]) * (local_9c - pfVar5[2]) +
                                          ((float)local_a4 - *pfVar5) * ((float)local_a4 - *pfVar5)
                                          + FLOAT_803de910));
    dVar18 = (double)(float)(dVar18 - dVar20);
    dVar23 = (double)(*pfVar5 + *pfVar5);
    dVar22 = (double)(pfVar5[2] + pfVar5[2]);
    uVar6 = (uint)*(byte *)(iVar10 + 0xf3);
    iVar7 = uVar6 * 4;
    iVar16 = uVar6 * 0x1c;
    pfVar15 = (float *)(iVar14 + iVar7);
    piVar11 = param_4;
    while( true ) {
      iVar7 = iVar7 + -4;
      iVar16 = iVar16 + -0x1c;
      pfVar15 = pfVar15 + -1;
      uVar6 = uVar6 - 1;
      if (uVar6 == 0) break;
      if (dVar18 < (double)*(float *)(*(int *)(iVar9 + 0x10) + iVar7)) {
        iVar13 = (int)*(char *)(*(int *)(iVar10 + 0x3c) + iVar16);
        iVar8 = FUN_8002856c(param_3,uVar6);
        local_a4 = *(float **)(iVar8 + 0xc);
        local_a0 = *(float *)(iVar8 + 0x1c);
        local_9c = *(float *)(iVar8 + 0x2c);
        iVar8 = FUN_8002856c(param_3,iVar13);
        local_b0 = *(float **)(iVar8 + 0xc);
        local_ac = *(float *)(iVar8 + 0x1c);
        local_a8 = *(float *)(iVar8 + 0x2c);
        fVar3 = *pfVar15;
        fVar4 = *(float *)(iVar14 + iVar13 * 4);
        *(undefined *)(*(int *)(iVar9 + 0x18) + uVar6) = 1;
        *(undefined *)(*(int *)(iVar9 + 0x18) + iVar13) = 1;
        fVar1 = (float)((double)((float)local_b0 + (float)local_a4) - dVar23);
        fVar2 = (float)((double)(local_a8 + local_9c) - dVar22);
        if (fVar3 <= fVar4) {
          fVar3 = fVar4 + fVar4;
        }
        else {
          fVar3 = fVar3 + fVar3;
        }
        fVar3 = (float)(dVar21 + (double)(*(float *)(*(int *)(iVar9 + 0xc) + iVar7) + fVar3));
        if (fVar2 * fVar2 + fVar1 * fVar1 + FLOAT_803de910 < fVar3 * fVar3) {
          local_b4 = FLOAT_803de918 / *(float *)(*(int *)(iVar9 + 0xc) + iVar7);
          local_bc = (float *)(((float)local_b0 - (float)local_a4) * local_b4);
          local_b8 = (local_ac - local_a0) * local_b4;
          local_b4 = (local_a8 - local_9c) * local_b4;
          iVar8 = FUN_800321a4(dVar20,pfVar5,&local_a4,&local_bc,&local_b0,&local_c0,&local_c4,
                               &local_c8);
          if (iVar8 != 0) {
            *(undefined *)(*(int *)(iVar9 + 0x18) + uVar6) = 1;
            *(undefined *)(*(int *)(iVar9 + 0x18) + iVar13) = 1;
            dVar19 = (double)FUN_802931a0((double)local_c4);
            piVar11[0xc] = (int)(float)(dVar20 + (double)(float)(dVar19 - (double)(float)local_c8));
            if (FLOAT_803de910 == (float)piVar11[0xc]) {
              piVar11[0xc] = (int)FLOAT_803de920;
            }
            fVar1 = (float)piVar11[0xc];
            if (fVar1 <= FLOAT_803de910) {
              fVar1 = -fVar1;
            }
            piVar11[0xf] = (int)(FLOAT_803de918 / fVar1);
            *param_6 = *param_6 + (float)piVar11[0xf];
            if ((float)piVar11[0xc] < (float)(*param_5)[0xc]) {
              *param_5 = piVar11;
            }
            *piVar11 = (int)&local_a4;
            piVar11[1] = (int)&local_b0;
            piVar11[2] = (int)local_a4;
            piVar11[3] = (int)local_a0;
            piVar11[4] = (int)local_9c;
            piVar11[5] = (int)local_b0;
            piVar11[6] = (int)local_ac;
            piVar11[7] = (int)local_a8;
            piVar11[0xb] = (int)local_c0;
            piVar11[0xe] = (int)local_c8;
            dVar19 = (double)FUN_802931a0((double)local_c4);
            piVar11[0xd] = (int)(float)dVar19;
            piVar11[8] = (int)local_bc;
            piVar11[9] = (int)local_b8;
            piVar11[10] = (int)local_b4;
            piVar11[0x10] = uVar6;
            piVar11[0x11] = iVar13;
            if (iVar12 < 0x13) {
              iVar12 = iVar12 + 1;
              piVar11 = piVar11 + 0x12;
            }
          }
        }
      }
    }
    piVar11[0x10] = -1;
    uVar6 = (uint)((int)param_4 - (int)piVar11 | (int)piVar11 - (int)param_4) >> 0x1f;
  }
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  __psq_l0(auStack24,uVar17);
  __psq_l1(auStack24,uVar17);
  __psq_l0(auStack40,uVar17);
  __psq_l1(auStack40,uVar17);
  __psq_l0(auStack56,uVar17);
  __psq_l1(auStack56,uVar17);
  __psq_l0(auStack72,uVar17);
  __psq_l1(auStack72,uVar17);
  FUN_80286100(uVar6);
  return;
}

