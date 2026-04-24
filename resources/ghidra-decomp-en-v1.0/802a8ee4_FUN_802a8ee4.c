// Function: FUN_802a8ee4
// Entry: 802a8ee4
// Size: 1296 bytes

/* WARNING: Removing unreachable block (ram,0x802a93cc) */
/* WARNING: Removing unreachable block (ram,0x802a93c4) */
/* WARNING: Removing unreachable block (ram,0x802a93d4) */

void FUN_802a8ee4(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4,float *param_5)

{
  float fVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int *piVar12;
  float *pfVar13;
  undefined4 uVar14;
  double dVar15;
  undefined8 in_f29;
  double dVar16;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  undefined8 uVar19;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84 [4];
  float local_74;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar14 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar19 = FUN_802860b4();
  iVar3 = (int)((ulonglong)uVar19 >> 0x20);
  iVar7 = (int)uVar19;
  *(undefined4 *)(iVar7 + 0x4c4) = 0;
  param_4[7] = (float)param_3[7];
  param_4[8] = (float)param_3[8];
  param_4[9] = (float)param_3[9];
  param_4[10] = (float)param_3[10];
  *(undefined *)(param_4 + 0x18) = *(undefined *)((int)param_3 + 0x53);
  iVar10 = *param_3;
  iVar6 = DAT_803dcf38;
  iVar11 = DAT_803dcf34;
  if (iVar10 != 0) {
    iVar6 = *(int *)(*(int *)(iVar10 + 0x50) + 0x3c);
    iVar11 = *(int *)(*(int *)(iVar10 + 0x50) + 0x34);
  }
  local_90 = -param_4[9];
  local_8c = FLOAT_803e7ea4;
  local_88 = param_4[7];
  local_84[0] = -(local_90 * (float)param_3[1] + local_88 * (float)param_3[5]);
  local_84[1] = -local_90;
  local_84[2] = FLOAT_803e7ea4;
  local_84[3] = -local_88;
  local_74 = -(local_84[1] * (float)param_3[2] + local_84[3] * (float)param_3[6]);
  iVar9 = 0;
  pfVar13 = &local_90;
  dVar18 = (double)FLOAT_803e7e98;
  piVar12 = param_3;
  do {
    dVar15 = (double)FUN_8024782c(pfVar13,param_5);
    if ((float)((double)pfVar13[3] + dVar15) < (float)(dVar18 + (double)fRam803dc6bc)) {
      if (*(short *)(piVar12 + 0x13) < 0) {
        iVar8 = 0;
      }
      else {
        iVar8 = iVar11 + *(short *)(piVar12 + 0x13) * 0x10;
      }
      if ((iVar8 == 0) || ((bVar2 = *(byte *)(iVar8 + 3) & 0x3f, bVar2 != 6 && (bVar2 != 0x10)))) {
        uVar5 = 0;
        goto LAB_802a93c4;
      }
      iVar4 = *(short *)(iVar8 + 4) * 0xc;
      local_98 = *(float *)(iVar6 + iVar4);
      local_a8 = FLOAT_803e7ea4;
      local_a0 = *(float *)(iVar6 + iVar4 + 8);
      iVar8 = *(short *)(iVar8 + 6) * 0xc;
      local_94 = *(float *)(iVar6 + iVar8);
      local_a4 = FLOAT_803e7ea4;
      local_9c = *(float *)(iVar6 + iVar8 + 8);
      if (iVar10 != 0) {
        FUN_8000e0a0(&local_98,&local_a8,&local_a0,iVar10);
        FUN_8000e0a0((double)local_94,(double)local_a4,(double)local_9c,&local_94,&local_a4,
                     &local_9c,iVar10);
      }
      dVar17 = (double)(local_9c - local_a0);
      dVar16 = (double)(local_98 - local_94);
      dVar15 = (double)FUN_802931a0((double)(float)(dVar17 * dVar17 +
                                                   (double)(float)(dVar16 * dVar16)));
      if ((float)(dVar17 * (double)(float)((double)FLOAT_803e7ee0 / dVar15)) * param_4[7] +
          (float)(dVar16 * (double)(float)((double)FLOAT_803e7ee0 / dVar15)) * param_4[9] <
          FLOAT_803e7e98) {
        uVar5 = 0;
        goto LAB_802a93c4;
      }
    }
    pfVar13 = pfVar13 + 4;
    piVar12 = (int *)((int)piVar12 + 2);
    iVar9 = iVar9 + 1;
  } while (iVar9 < 2);
  param_4[0xb] = *param_5;
  param_4[0xc] = param_5[1];
  param_4[0xd] = param_5[2];
  fVar1 = FLOAT_803e7e98;
  param_4[0x11] = -(param_4[7] * (FLOAT_803e7e98 + FLOAT_803dc6c0) - param_4[0xb]);
  param_4[0x13] = -(param_4[9] * (fVar1 + FLOAT_803dc6c0) - param_4[0xd]);
  fVar1 = FLOAT_803e7f10;
  param_4[0x14] = FLOAT_803e7f10 * param_4[7] + param_4[0xb];
  param_4[0x16] = fVar1 * param_4[9] + param_4[0xd];
  param_4[0xe] = *(float *)(iVar7 + 0x768);
  param_4[0xf] = FLOAT_803e7ea4;
  param_4[0x10] = *(float *)(iVar7 + 0x770);
  param_4[1] = (float)param_3[0x12] * ((float)param_3[0x10] - (float)param_3[0xf]) +
               (float)param_3[0xf];
  *(undefined *)((int)param_4 + 0x5e) = *(undefined *)(param_3 + 0x14);
  *(undefined *)((int)param_4 + 0x61) = 1;
  iVar6 = FUN_800658a4((double)param_4[0x11],(double)param_4[1],(double)param_4[0x13],iVar3,
                       param_4 + 0x12,0x205);
  if (iVar6 == 0) {
    param_4[0x12] = param_4[1] - param_4[0x12];
    if (*(char *)(param_3 + 0x14) == '\x10') {
      param_4[2] = *(float *)(iVar3 + 0x10);
      *param_4 = param_4[1] - param_4[2];
      if (*param_4 < FLOAT_803e8044) {
        if ((iVar10 != 0) && ((*(uint *)(*(int *)(iVar10 + 0x50) + 0x44) & 0x8000) == 0)) {
          *(int *)(iVar7 + 0x4c4) = iVar10;
        }
        uVar5 = 3;
      }
      else {
        uVar5 = 0;
      }
    }
    else {
      param_4[2] = *(float *)(iVar3 + 0x84);
      *param_4 = param_4[1] - param_4[2];
      if ((*(byte *)(iVar7 + 0x3f1) & 1) == 0) {
        if (((FLOAT_803e7ed8 <= *param_4) && (*param_4 <= FLOAT_803e7fbc)) &&
           (FLOAT_803e80c4 <=
            param_4[1] -
            ((float)param_3[0x12] * ((float)param_3[4] - (float)param_3[3]) + (float)param_3[3]))) {
          if ((iVar10 != 0) && ((*(uint *)(*(int *)(iVar10 + 0x50) + 0x44) & 0x8000) == 0)) {
            *(int *)(iVar7 + 0x4c4) = iVar10;
          }
          uVar5 = 6;
          goto LAB_802a93c4;
        }
      }
      else {
        if ((iVar10 != 0) && ((*(uint *)(*(int *)(iVar10 + 0x50) + 0x44) & 0x8000) == 0)) {
          *(int *)(iVar7 + 0x4c4) = iVar10;
        }
        fVar1 = *param_4;
        if ((fVar1 <= FLOAT_803e80c8) && (FLOAT_803e80c4 < fVar1)) {
          uVar5 = 2;
          goto LAB_802a93c4;
        }
        if ((fVar1 <= FLOAT_803e80c4) && (FLOAT_803e8018 <= fVar1)) {
          uVar5 = 3;
          goto LAB_802a93c4;
        }
      }
      uVar5 = 0;
    }
  }
  else {
    uVar5 = 0;
  }
LAB_802a93c4:
  __psq_l0(auStack8,uVar14);
  __psq_l1(auStack8,uVar14);
  __psq_l0(auStack24,uVar14);
  __psq_l1(auStack24,uVar14);
  __psq_l0(auStack40,uVar14);
  __psq_l1(auStack40,uVar14);
  FUN_80286100(uVar5);
  return;
}

