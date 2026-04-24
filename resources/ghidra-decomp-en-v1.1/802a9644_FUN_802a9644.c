// Function: FUN_802a9644
// Entry: 802a9644
// Size: 1296 bytes

/* WARNING: Removing unreachable block (ram,0x802a9b34) */
/* WARNING: Removing unreachable block (ram,0x802a9b2c) */
/* WARNING: Removing unreachable block (ram,0x802a9b24) */
/* WARNING: Removing unreachable block (ram,0x802a9664) */
/* WARNING: Removing unreachable block (ram,0x802a965c) */
/* WARNING: Removing unreachable block (ram,0x802a9654) */

void FUN_802a9644(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4,float *param_5)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int *piVar11;
  float *pfVar12;
  double dVar13;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
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
  uVar17 = FUN_80286818();
  iVar3 = (int)((ulonglong)uVar17 >> 0x20);
  iVar6 = (int)uVar17;
  *(undefined4 *)(iVar6 + 0x4c4) = 0;
  param_4[7] = (float)param_3[7];
  param_4[8] = (float)param_3[8];
  param_4[9] = (float)param_3[9];
  param_4[10] = (float)param_3[10];
  *(undefined *)(param_4 + 0x18) = *(undefined *)((int)param_3 + 0x53);
  iVar9 = *param_3;
  iVar5 = DAT_803ddbb8;
  iVar10 = DAT_803ddbb4;
  if (iVar9 != 0) {
    iVar5 = *(int *)(*(int *)(iVar9 + 0x50) + 0x3c);
    iVar10 = *(int *)(*(int *)(iVar9 + 0x50) + 0x34);
  }
  local_90 = -param_4[9];
  local_8c = FLOAT_803e8b3c;
  local_88 = param_4[7];
  local_84[0] = -(local_90 * (float)param_3[1] + local_88 * (float)param_3[5]);
  local_84[1] = -local_90;
  local_84[2] = FLOAT_803e8b3c;
  local_84[3] = -local_88;
  local_74 = -(local_84[1] * (float)param_3[2] + local_84[3] * (float)param_3[6]);
  iVar8 = 0;
  pfVar12 = &local_90;
  dVar16 = (double)FLOAT_803e8b30;
  piVar11 = param_3;
  do {
    dVar13 = FUN_80247f90(pfVar12,param_5);
    if ((float)((double)pfVar12[3] + dVar13) < (float)(dVar16 + (double)fRam803dd324)) {
      if (*(short *)(piVar11 + 0x13) < 0) {
        iVar7 = 0;
      }
      else {
        iVar7 = iVar10 + *(short *)(piVar11 + 0x13) * 0x10;
      }
      if ((iVar7 == 0) || ((bVar1 = *(byte *)(iVar7 + 3) & 0x3f, bVar1 != 6 && (bVar1 != 0x10))))
      goto LAB_802a9b24;
      iVar4 = *(short *)(iVar7 + 4) * 0xc;
      local_98 = *(float *)(iVar5 + iVar4);
      local_a8 = FLOAT_803e8b3c;
      local_a0 = *(float *)(iVar5 + iVar4 + 8);
      iVar7 = *(short *)(iVar7 + 6) * 0xc;
      local_94 = *(float *)(iVar5 + iVar7);
      local_a4 = FLOAT_803e8b3c;
      local_9c = *(float *)(iVar5 + iVar7 + 8);
      if (iVar9 != 0) {
        FUN_8000e0c0((double)local_98,(double)FLOAT_803e8b3c,(double)local_a0,&local_98,&local_a8,
                     &local_a0,iVar9);
        FUN_8000e0c0((double)local_94,(double)local_a4,(double)local_9c,&local_94,&local_a4,
                     &local_9c,iVar9);
      }
      dVar15 = (double)(local_9c - local_a0);
      dVar14 = (double)(local_98 - local_94);
      dVar13 = FUN_80293900((double)(float)(dVar15 * dVar15 + (double)(float)(dVar14 * dVar14)));
      if ((float)(dVar15 * (double)(float)((double)FLOAT_803e8b78 / dVar13)) * param_4[7] +
          (float)(dVar14 * (double)(float)((double)FLOAT_803e8b78 / dVar13)) * param_4[9] <
          FLOAT_803e8b30) goto LAB_802a9b24;
    }
    pfVar12 = pfVar12 + 4;
    piVar11 = (int *)((int)piVar11 + 2);
    iVar8 = iVar8 + 1;
  } while (iVar8 < 2);
  param_4[0xb] = *param_5;
  param_4[0xc] = param_5[1];
  param_4[0xd] = param_5[2];
  fVar2 = FLOAT_803e8b30;
  param_4[0x11] = -(param_4[7] * (FLOAT_803e8b30 + FLOAT_803dd328) - param_4[0xb]);
  param_4[0x13] = -(param_4[9] * (fVar2 + FLOAT_803dd328) - param_4[0xd]);
  fVar2 = FLOAT_803e8ba8;
  param_4[0x14] = FLOAT_803e8ba8 * param_4[7] + param_4[0xb];
  param_4[0x16] = fVar2 * param_4[9] + param_4[0xd];
  param_4[0xe] = *(float *)(iVar6 + 0x768);
  param_4[0xf] = FLOAT_803e8b3c;
  param_4[0x10] = *(float *)(iVar6 + 0x770);
  param_4[1] = (float)param_3[0x12] * ((float)param_3[0x10] - (float)param_3[0xf]) +
               (float)param_3[0xf];
  *(undefined *)((int)param_4 + 0x5e) = *(undefined *)(param_3 + 0x14);
  *(undefined *)((int)param_4 + 0x61) = 1;
  iVar5 = FUN_80065a20((double)param_4[0x11],(double)param_4[1],(double)param_4[0x13],iVar3,
                       param_4 + 0x12,0x205);
  if (iVar5 == 0) {
    param_4[0x12] = param_4[1] - param_4[0x12];
    if (*(char *)(param_3 + 0x14) == '\x10') {
      param_4[2] = *(float *)(iVar3 + 0x10);
      *param_4 = param_4[1] - param_4[2];
      if (((*param_4 < FLOAT_803e8cdc) && (iVar9 != 0)) &&
         ((*(uint *)(*(int *)(iVar9 + 0x50) + 0x44) & 0x8000) == 0)) {
        *(int *)(iVar6 + 0x4c4) = iVar9;
      }
    }
    else {
      param_4[2] = *(float *)(iVar3 + 0x84);
      *param_4 = param_4[1] - param_4[2];
      if ((*(byte *)(iVar6 + 0x3f1) & 1) == 0) {
        if (((FLOAT_803e8b70 <= *param_4) && (*param_4 <= FLOAT_803e8c54)) &&
           ((FLOAT_803e8d5c <=
             param_4[1] -
             ((float)param_3[0x12] * ((float)param_3[4] - (float)param_3[3]) + (float)param_3[3]) &&
            ((iVar9 != 0 && ((*(uint *)(*(int *)(iVar9 + 0x50) + 0x44) & 0x8000) == 0)))))) {
          *(int *)(iVar6 + 0x4c4) = iVar9;
        }
      }
      else if ((iVar9 != 0) && ((*(uint *)(*(int *)(iVar9 + 0x50) + 0x44) & 0x8000) == 0)) {
        *(int *)(iVar6 + 0x4c4) = iVar9;
      }
    }
  }
LAB_802a9b24:
  FUN_80286864();
  return;
}

