// Function: FUN_802a87cc
// Entry: 802a87cc
// Size: 1816 bytes

/* WARNING: Removing unreachable block (ram,0x802a8ebc) */
/* WARNING: Removing unreachable block (ram,0x802a8eb4) */
/* WARNING: Removing unreachable block (ram,0x802a8ec4) */

void FUN_802a87cc(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,float *param_6)

{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  byte bVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  int iVar12;
  float **ppfVar13;
  int iVar14;
  int iVar15;
  char cVar16;
  int iVar17;
  int *piVar18;
  float *pfVar19;
  float *pfVar20;
  undefined4 uVar21;
  double extraout_f1;
  double dVar22;
  undefined8 in_f29;
  double dVar23;
  undefined8 in_f30;
  double dVar24;
  undefined8 in_f31;
  double dVar25;
  undefined8 uVar26;
  float **local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac [4];
  float local_9c;
  float local_98 [7];
  float local_7c;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar21 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar26 = FUN_802860a8();
  iVar8 = (int)((ulonglong)uVar26 >> 0x20);
  piVar11 = (int *)uVar26;
  cVar16 = '\0';
  iVar17 = *(int *)(iVar8 + 0xb8);
  if ((extraout_f1 <= (double)(float)((double)*(float *)(iVar17 + 0x280) * param_2)) ||
     (extraout_f1 <= (double)FLOAT_803e80c0)) {
    cVar1 = *(char *)(piVar11 + 0x14);
    if ((cVar1 == '\x02') || (cVar1 == '\x11')) {
      cVar16 = '\x04';
    }
    else if ((double)*(float *)(iVar17 + 0x280) < (double)FLOAT_803e80a0) {
      if (cVar1 != '\x04') {
        cVar16 = '\x04';
      }
    }
    else {
      cVar16 = '\x05';
    }
  }
  param_5[7] = (float)piVar11[7];
  param_5[8] = (float)piVar11[8];
  param_5[9] = (float)piVar11[9];
  param_5[7] = -param_5[7];
  param_5[8] = -param_5[8];
  param_5[9] = -param_5[9];
  param_5[10] = -(float)piVar11[10];
  param_5[0xb] = *param_6;
  param_5[0xc] = param_6[1];
  param_5[0xd] = param_6[2];
  iVar15 = *piVar11;
  if (cVar16 != '\x04') {
    *(undefined4 *)(iVar17 + 0x4c4) = 0;
    goto LAB_802a8eb4;
  }
  bVar5 = false;
  iVar10 = DAT_803dcf38;
  iVar7 = DAT_803dcf34;
  if (iVar15 != 0) {
    iVar10 = *(int *)(*(int *)(iVar15 + 0x50) + 0x3c);
    iVar7 = *(int *)(*(int *)(iVar15 + 0x50) + 0x34);
  }
  local_98[0] = param_5[9];
  local_98[1] = FLOAT_803e7ea4;
  local_98[2] = -param_5[7];
  local_98[3] = -(local_98[0] * (float)piVar11[1] + local_98[2] * (float)piVar11[5]);
  local_98[4] = -local_98[0];
  local_98[5] = FLOAT_803e7ea4;
  local_98[6] = -local_98[2];
  local_7c = -(local_98[4] * (float)piVar11[2] + local_98[6] * (float)piVar11[6]);
  iVar14 = 0;
  pfVar20 = local_98;
  pfVar19 = local_ac;
  dVar25 = (double)FLOAT_803e7e98;
  piVar18 = piVar11;
  do {
    dVar22 = (double)FUN_8024782c(pfVar20,param_6);
    *pfVar19 = (float)((double)pfVar20[3] + dVar22);
    if (*pfVar19 < (float)(dVar25 + (double)fRam803dc6bc)) {
      if (*(short *)(piVar18 + 0x13) < 0) {
        iVar12 = 0;
      }
      else {
        iVar12 = iVar7 + *(short *)(piVar18 + 0x13) * 0x10;
      }
      if ((iVar12 == 0) || ((bVar6 = *(byte *)(iVar12 + 3) & 0x3f, bVar6 != 5 && (bVar6 != 2)))) {
        bVar5 = true;
      }
      else {
        iVar9 = *(short *)(iVar12 + 4) * 0xc;
        local_b4 = *(float *)(iVar10 + iVar9);
        local_c4 = FLOAT_803e7ea4;
        local_bc = *(float *)(iVar10 + iVar9 + 8);
        iVar12 = *(short *)(iVar12 + 6) * 0xc;
        local_b0 = *(float *)(iVar10 + iVar12);
        local_c0 = FLOAT_803e7ea4;
        local_b8 = *(float *)(iVar10 + iVar12 + 8);
        if (iVar15 != 0) {
          FUN_8000e0a0(&local_b4,&local_c4,&local_bc,iVar15);
          FUN_8000e0a0((double)local_b0,(double)local_c0,(double)local_b8,&local_b0,&local_c0,
                       &local_b8,iVar15);
        }
        dVar24 = (double)(local_b8 - local_bc);
        dVar23 = (double)(local_b4 - local_b0);
        dVar22 = (double)FUN_802931a0((double)(float)(dVar24 * dVar24 +
                                                     (double)(float)(dVar23 * dVar23)));
        if ((float)(dVar24 * (double)(float)((double)FLOAT_803e7ee0 / dVar22)) * param_5[7] +
            (float)(dVar23 * (double)(float)((double)FLOAT_803e7ee0 / dVar22)) * param_5[9] <
            FLOAT_803e7e98) {
          bVar5 = true;
        }
      }
    }
    pfVar20 = pfVar20 + 4;
    pfVar19 = pfVar19 + 1;
    piVar18 = (int *)((int)piVar18 + 2);
    iVar14 = iVar14 + 1;
  } while (iVar14 < 2);
  if (local_ac[1] <= local_ac[0]) {
    *(undefined *)((int)param_5 + 0x5f) = 1;
  }
  else {
    *(undefined *)((int)param_5 + 0x5f) = 0;
  }
  fVar2 = FLOAT_803e7e98;
  if (bVar5) {
    param_5[0xb] = param_5[0xb] +
                   ((FLOAT_803e7e98 + fRam803dc6bc) - local_ac[*(byte *)((int)param_5 + 0x5f)]) *
                   local_98[(uint)*(byte *)((int)param_5 + 0x5f) * 4];
    param_5[0xd] = param_5[0xd] +
                   ((fVar2 + fRam803dc6bc) - local_ac[*(byte *)((int)param_5 + 0x5f)]) *
                   local_98[(uint)*(byte *)((int)param_5 + 0x5f) * 4 + 2];
  }
  fVar2 = FLOAT_803e7e98;
  param_5[0x11] = -(param_5[7] * (FLOAT_803e7e98 + FLOAT_803dc6c0) - param_5[0xb]);
  param_5[0x13] = -(param_5[9] * (fVar2 + FLOAT_803dc6c0) - param_5[0xd]);
  fVar2 = FLOAT_803e7f10;
  param_5[0x14] = FLOAT_803e7f10 * param_5[7] + param_5[0xb];
  param_5[0x16] = fVar2 * param_5[9] + param_5[0xd];
  param_5[1] = (float)piVar11[0x12] * ((float)piVar11[4] - (float)piVar11[3]) + (float)piVar11[3];
  local_ac[2] = param_5[0x14];
  local_ac[3] = param_5[1];
  local_9c = param_5[0x16];
  FUN_8000e0a0(local_ac + 2,local_ac + 3,&local_9c,*(undefined4 *)(iVar8 + 0x30));
  iVar10 = FUN_80065e50((double)local_ac[2],(double)local_ac[3],(double)local_9c,iVar8,&local_c8,0,
                        0x201);
  if (iVar10 != 0) {
    iVar7 = -1;
    iVar14 = 0;
    ppfVar13 = local_c8;
    fVar2 = FLOAT_803e80ac;
    fVar3 = FLOAT_803e80ac;
    if (0 < iVar10) {
      do {
        fVar4 = local_ac[3] - **ppfVar13;
        if ((FLOAT_803e7ea4 <= fVar4) && ((fVar2 < FLOAT_803e7ea4 || (fVar4 < fVar2)))) {
          iVar7 = iVar14;
          fVar2 = fVar4;
        }
        if (((FLOAT_803e80b0 < (*ppfVar13)[2]) && (FLOAT_803e7ea4 <= fVar4)) &&
           ((fVar3 < FLOAT_803e7ea4 || (fVar4 < fVar3)))) {
          fVar3 = fVar4;
        }
        ppfVar13 = ppfVar13 + 1;
        iVar14 = iVar14 + 1;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
    }
    if ((((fVar2 < FLOAT_803e80c4) && (iVar7 != -1)) && (local_c8[iVar7][2] <= FLOAT_803e80b0)) &&
       (FLOAT_803e7eb0 < local_c8[iVar7][2])) {
      cVar16 = '\0';
      goto LAB_802a8eb4;
    }
    if (fVar3 < FLOAT_803e80c4) {
      cVar16 = '\0';
      goto LAB_802a8eb4;
    }
  }
  local_ac[2] = param_5[0x11];
  local_ac[3] = param_5[1];
  local_9c = param_5[0x13];
  FUN_8000e0a0(local_ac + 2,local_ac + 3,&local_9c,*(undefined4 *)(iVar8 + 0x30));
  iVar10 = FUN_800658a4((double)local_ac[2],(double)local_ac[3],(double)local_9c,iVar8,
                        param_5 + 0x12,0x205);
  if (iVar10 == 0) {
    param_5[0x12] = param_5[1] - param_5[0x12];
  }
  else {
    param_5[0x12] = param_5[1];
  }
  param_5[2] = (float)piVar11[3];
  *param_5 = param_5[1] - param_5[2];
  *(undefined *)((int)param_5 + 0x5e) = *(undefined *)(piVar11 + 0x14);
  *(undefined *)(param_5 + 0x18) = *(undefined *)((int)piVar11 + 0x53);
  if (*(int *)(iVar8 + 0x30) != 0) {
    FUN_8000e0a0((double)param_5[0xb],(double)param_5[0xc],(double)param_5[0xd],param_5 + 0xb,
                 param_5 + 0xc,param_5 + 0xd);
    FUN_8000e0a0((double)param_5[0x11],(double)param_5[0x12],(double)param_5[0x13],param_5 + 0x11,
                 param_5 + 0x12,param_5 + 0x13,*(undefined4 *)(iVar8 + 0x30));
    FUN_8000e0a0((double)param_5[0x14],(double)param_5[0x15],(double)param_5[0x16],param_5 + 0x14,
                 param_5 + 0x15,param_5 + 0x16,*(undefined4 *)(iVar8 + 0x30));
    *(float *)(iVar17 + 0x5ac) =
         *(float *)(iVar17 + 0x5ac) + *(float *)(*(int *)(iVar8 + 0x30) + 0x10);
    *(float *)(iVar17 + 0x5b0) =
         *(float *)(iVar17 + 0x5b0) + *(float *)(*(int *)(iVar8 + 0x30) + 0x10);
  }
  *(undefined *)((int)param_5 + 0x61) = 1;
  if ((iVar15 == 0) || ((*(uint *)(*(int *)(iVar15 + 0x50) + 0x44) & 0x8000) != 0)) {
    *(undefined4 *)(iVar17 + 0x4c4) = 0;
  }
  else {
    *(int *)(iVar17 + 0x4c4) = iVar15;
  }
LAB_802a8eb4:
  __psq_l0(auStack8,uVar21);
  __psq_l1(auStack8,uVar21);
  __psq_l0(auStack24,uVar21);
  __psq_l1(auStack24,uVar21);
  __psq_l0(auStack40,uVar21);
  __psq_l1(auStack40,uVar21);
  FUN_802860f4(cVar16);
  return;
}

