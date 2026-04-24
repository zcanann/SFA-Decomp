// Function: FUN_802a8f2c
// Entry: 802a8f2c
// Size: 1816 bytes

/* WARNING: Removing unreachable block (ram,0x802a9624) */
/* WARNING: Removing unreachable block (ram,0x802a961c) */
/* WARNING: Removing unreachable block (ram,0x802a9614) */
/* WARNING: Removing unreachable block (ram,0x802a8f4c) */
/* WARNING: Removing unreachable block (ram,0x802a8f44) */
/* WARNING: Removing unreachable block (ram,0x802a8f3c) */

void FUN_802a8f2c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
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
  undefined4 *puVar13;
  int iVar14;
  int iVar15;
  char cVar16;
  int iVar17;
  int *piVar18;
  float *pfVar19;
  float *pfVar20;
  double extraout_f1;
  double dVar21;
  double in_f29;
  double dVar22;
  double in_f30;
  double dVar23;
  double in_f31;
  double dVar24;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar25;
  undefined4 *local_c8;
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
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar25 = FUN_8028680c();
  iVar8 = (int)((ulonglong)uVar25 >> 0x20);
  piVar11 = (int *)uVar25;
  cVar16 = '\0';
  iVar17 = *(int *)(iVar8 + 0xb8);
  if ((extraout_f1 <= (double)(float)((double)*(float *)(iVar17 + 0x280) * param_2)) ||
     (extraout_f1 <= (double)FLOAT_803e8d58)) {
    cVar1 = *(char *)(piVar11 + 0x14);
    if ((cVar1 == '\x02') || (cVar1 == '\x11')) {
      cVar16 = '\x04';
    }
    else if ((double)*(float *)(iVar17 + 0x280) < (double)FLOAT_803e8d38) {
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
  if (cVar16 == '\x04') {
    bVar5 = false;
    iVar10 = DAT_803ddbb8;
    iVar7 = DAT_803ddbb4;
    if (iVar15 != 0) {
      iVar10 = *(int *)(*(int *)(iVar15 + 0x50) + 0x3c);
      iVar7 = *(int *)(*(int *)(iVar15 + 0x50) + 0x34);
    }
    local_98[0] = param_5[9];
    local_98[1] = FLOAT_803e8b3c;
    local_98[2] = -param_5[7];
    local_98[3] = -(local_98[0] * (float)piVar11[1] + local_98[2] * (float)piVar11[5]);
    local_98[4] = -local_98[0];
    local_98[5] = FLOAT_803e8b3c;
    local_98[6] = -local_98[2];
    local_7c = -(local_98[4] * (float)piVar11[2] + local_98[6] * (float)piVar11[6]);
    iVar14 = 0;
    pfVar20 = local_98;
    pfVar19 = local_ac;
    dVar24 = (double)FLOAT_803e8b30;
    piVar18 = piVar11;
    do {
      dVar21 = FUN_80247f90(pfVar20,param_6);
      *pfVar19 = (float)((double)pfVar20[3] + dVar21);
      if (*pfVar19 < (float)(dVar24 + (double)fRam803dd324)) {
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
          local_c4 = FLOAT_803e8b3c;
          local_bc = *(float *)(iVar10 + iVar9 + 8);
          iVar12 = *(short *)(iVar12 + 6) * 0xc;
          local_b0 = *(float *)(iVar10 + iVar12);
          local_c0 = FLOAT_803e8b3c;
          local_b8 = *(float *)(iVar10 + iVar12 + 8);
          if (iVar15 != 0) {
            FUN_8000e0c0((double)local_b4,(double)FLOAT_803e8b3c,(double)local_bc,&local_b4,
                         &local_c4,&local_bc,iVar15);
            FUN_8000e0c0((double)local_b0,(double)local_c0,(double)local_b8,&local_b0,&local_c0,
                         &local_b8,iVar15);
          }
          dVar23 = (double)(local_b8 - local_bc);
          dVar22 = (double)(local_b4 - local_b0);
          dVar21 = FUN_80293900((double)(float)(dVar23 * dVar23 + (double)(float)(dVar22 * dVar22)))
          ;
          if ((float)(dVar23 * (double)(float)((double)FLOAT_803e8b78 / dVar21)) * param_5[7] +
              (float)(dVar22 * (double)(float)((double)FLOAT_803e8b78 / dVar21)) * param_5[9] <
              FLOAT_803e8b30) {
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
    fVar2 = FLOAT_803e8b30;
    if (bVar5) {
      param_5[0xb] = param_5[0xb] +
                     ((FLOAT_803e8b30 + fRam803dd324) - local_ac[*(byte *)((int)param_5 + 0x5f)]) *
                     local_98[(uint)*(byte *)((int)param_5 + 0x5f) * 4];
      param_5[0xd] = param_5[0xd] +
                     ((fVar2 + fRam803dd324) - local_ac[*(byte *)((int)param_5 + 0x5f)]) *
                     local_98[(uint)*(byte *)((int)param_5 + 0x5f) * 4 + 2];
    }
    fVar2 = FLOAT_803e8b30;
    param_5[0x11] = -(param_5[7] * (FLOAT_803e8b30 + FLOAT_803dd328) - param_5[0xb]);
    param_5[0x13] = -(param_5[9] * (fVar2 + FLOAT_803dd328) - param_5[0xd]);
    fVar2 = FLOAT_803e8ba8;
    param_5[0x14] = FLOAT_803e8ba8 * param_5[7] + param_5[0xb];
    param_5[0x16] = fVar2 * param_5[9] + param_5[0xd];
    param_5[1] = (float)piVar11[0x12] * ((float)piVar11[4] - (float)piVar11[3]) + (float)piVar11[3];
    local_ac[2] = param_5[0x14];
    local_ac[3] = param_5[1];
    local_9c = param_5[0x16];
    FUN_8000e0c0((double)local_ac[2],(double)local_ac[3],(double)local_9c,local_ac + 2,local_ac + 3,
                 &local_9c,*(int *)(iVar8 + 0x30));
    iVar10 = FUN_80065fcc((double)local_ac[2],(double)local_ac[3],(double)local_9c,iVar8,&local_c8,0
                          ,0x201);
    if (iVar10 != 0) {
      iVar7 = -1;
      iVar14 = 0;
      puVar13 = local_c8;
      fVar2 = FLOAT_803e8d44;
      fVar3 = FLOAT_803e8d44;
      if (0 < iVar10) {
        do {
          fVar4 = local_ac[3] - *(float *)*puVar13;
          if ((FLOAT_803e8b3c <= fVar4) && ((fVar2 < FLOAT_803e8b3c || (fVar4 < fVar2)))) {
            iVar7 = iVar14;
            fVar2 = fVar4;
          }
          if (((FLOAT_803e8d48 < ((float *)*puVar13)[2]) && (FLOAT_803e8b3c <= fVar4)) &&
             ((fVar3 < FLOAT_803e8b3c || (fVar4 < fVar3)))) {
            fVar3 = fVar4;
          }
          puVar13 = puVar13 + 1;
          iVar14 = iVar14 + 1;
          iVar10 = iVar10 + -1;
        } while (iVar10 != 0);
      }
      if (((((fVar2 < FLOAT_803e8d5c) && (iVar7 != -1)) &&
           (*(float *)(local_c8[iVar7] + 8) <= FLOAT_803e8d48)) &&
          (FLOAT_803e8b48 < *(float *)(local_c8[iVar7] + 8))) || (fVar3 < FLOAT_803e8d5c))
      goto LAB_802a9614;
    }
    local_ac[2] = param_5[0x11];
    local_ac[3] = param_5[1];
    local_9c = param_5[0x13];
    FUN_8000e0c0((double)local_ac[2],(double)local_ac[3],(double)local_9c,local_ac + 2,local_ac + 3,
                 &local_9c,*(int *)(iVar8 + 0x30));
    iVar10 = FUN_80065a20((double)local_ac[2],(double)local_ac[3],(double)local_9c,iVar8,
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
      FUN_8000e0c0((double)param_5[0xb],(double)param_5[0xc],(double)param_5[0xd],param_5 + 0xb,
                   param_5 + 0xc,param_5 + 0xd,*(int *)(iVar8 + 0x30));
      FUN_8000e0c0((double)param_5[0x11],(double)param_5[0x12],(double)param_5[0x13],param_5 + 0x11,
                   param_5 + 0x12,param_5 + 0x13,*(int *)(iVar8 + 0x30));
      FUN_8000e0c0((double)param_5[0x14],(double)param_5[0x15],(double)param_5[0x16],param_5 + 0x14,
                   param_5 + 0x15,param_5 + 0x16,*(int *)(iVar8 + 0x30));
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
  }
  else {
    *(undefined4 *)(iVar17 + 0x4c4) = 0;
  }
LAB_802a9614:
  FUN_80286858();
  return;
}

