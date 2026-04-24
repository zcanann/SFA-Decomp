// Function: FUN_8013b368
// Entry: 8013b368
// Size: 512 bytes

/* WARNING: Removing unreachable block (ram,0x8013b548) */
/* WARNING: Removing unreachable block (ram,0x8013b540) */
/* WARNING: Removing unreachable block (ram,0x8013b538) */
/* WARNING: Removing unreachable block (ram,0x8013b530) */
/* WARNING: Removing unreachable block (ram,0x8013b528) */
/* WARNING: Removing unreachable block (ram,0x8013b520) */
/* WARNING: Removing unreachable block (ram,0x8013b3a0) */
/* WARNING: Removing unreachable block (ram,0x8013b398) */
/* WARNING: Removing unreachable block (ram,0x8013b390) */
/* WARNING: Removing unreachable block (ram,0x8013b388) */
/* WARNING: Removing unreachable block (ram,0x8013b380) */
/* WARNING: Removing unreachable block (ram,0x8013b378) */

void FUN_8013b368(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,float *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  float *pfVar5;
  double extraout_f1;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar10;
  double in_f30;
  double dVar11;
  double dVar12;
  double in_f31;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  float local_88 [2];
  float local_80;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar13 = FUN_80286840();
  pfVar4 = (float *)((ulonglong)uVar13 >> 0x20);
  pfVar5 = (float *)uVar13;
  dVar10 = extraout_f1;
  dVar6 = FUN_80021730(param_6,pfVar4);
  dVar7 = FUN_80021730(param_6,pfVar5);
  dVar11 = (double)(float)(dVar10 * dVar10);
  dVar10 = (double)(float)(param_2 * param_2);
  if ((dVar7 <= dVar6) && (dVar8 = FUN_80021730(param_5,param_6), dVar11 <= dVar8)) {
    dVar8 = FUN_80021730(pfVar4,param_5);
    dVar9 = FUN_80021730(pfVar4,param_6);
    if (dVar9 <= dVar8) {
      dVar8 = dVar10;
      if (dVar6 < dVar10) {
        dVar8 = dVar6;
      }
      if (dVar7 < dVar8) {
        fVar2 = pfVar5[2] - pfVar4[2];
        fVar1 = *pfVar4;
        fVar3 = fVar2 / (*pfVar5 - fVar1);
        local_80 = -(fVar3 * fVar1 - pfVar4[2]);
        fVar2 = (fVar1 - *pfVar5) / fVar2;
        local_88[0] = (-(fVar2 * *param_6 - param_6[2]) - local_80) / (fVar3 - fVar2);
        local_80 = fVar3 * local_88[0] + local_80;
        dVar9 = FUN_80021730(param_6,local_88);
        if (dVar9 < dVar11) {
          dVar9 = (double)(*pfVar5 - *param_6);
          dVar12 = (double)(pfVar5[2] - param_6[2]);
          dVar11 = FUN_80293900((double)(float)(dVar9 * dVar9 + (double)(float)(dVar12 * dVar12)));
          if ((double)FLOAT_803e306c != dVar11) {
            dVar9 = (double)(float)(dVar9 / dVar11);
            dVar12 = (double)(float)(dVar12 / dVar11);
          }
          if (dVar6 < dVar10) {
            dVar10 = FUN_80293900(dVar8);
            dVar6 = FUN_80293900(dVar7);
            param_2 = -(double)(float)((double)(float)(dVar10 - dVar6) * (double)FLOAT_803e3110 -
                                      dVar10);
          }
          *pfVar5 = (float)(dVar9 * param_2 + (double)*param_6);
          pfVar5[2] = (float)(dVar12 * param_2 + (double)param_6[2]);
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

