// Function: FUN_80066678
// Entry: 80066678
// Size: 752 bytes

/* WARNING: Removing unreachable block (ram,0x80066948) */
/* WARNING: Removing unreachable block (ram,0x80066940) */
/* WARNING: Removing unreachable block (ram,0x80066938) */
/* WARNING: Removing unreachable block (ram,0x80066698) */
/* WARNING: Removing unreachable block (ram,0x80066690) */
/* WARNING: Removing unreachable block (ram,0x80066688) */

void FUN_80066678(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4,float *param_5
                 ,float *param_6)

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
  double in_f29;
  double dVar9;
  double in_f30;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
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
  uVar11 = FUN_8028683c();
  pfVar4 = (float *)((ulonglong)uVar11 >> 0x20);
  pfVar5 = (float *)uVar11;
  dVar7 = extraout_f1;
  FUN_80022974(param_3,pfVar4 + 6,&local_54);
  dVar6 = (double)FUN_800228f0(&local_54);
  if ((double)FLOAT_803df934 != dVar6) {
    local_60 = *pfVar5 - *pfVar4;
    local_5c = pfVar5[1] - pfVar4[1];
    local_58 = pfVar5[2] - pfVar4[2];
    fVar1 = local_4c * local_58 + local_54 * local_60 + local_50 * local_5c;
    dVar9 = (double)(fVar1 * fVar1);
    if (dVar9 <= (double)pfVar4[10]) {
      FUN_80022974(&local_60,pfVar4 + 6,&local_6c);
      dVar10 = (double)(float)(-(double)(local_64 * local_4c +
                                        local_6c * local_54 + local_68 * local_50) / dVar6);
      FUN_80022974(&local_54,pfVar4 + 6,&local_6c);
      FUN_800228f0(&local_6c);
      dVar6 = FUN_80293900((double)(float)((double)pfVar4[10] - dVar9));
      dVar6 = (double)(float)(dVar6 / (double)(param_3[2] * local_64 +
                                              (float)((double)*param_3 * (double)local_6c +
                                                     (double)(param_3[1] * local_68))));
      if (dVar6 < (double)FLOAT_803df934) {
        dVar6 = -dVar6;
      }
      dVar6 = (double)(float)(dVar10 - dVar6);
      if (((double)FLOAT_803df934 <= dVar6) && (dVar6 <= dVar7)) {
        fVar1 = *pfVar5 + (float)((double)*param_3 * dVar6);
        fVar2 = pfVar5[1] + (float)((double)param_3[1] * dVar6);
        fVar3 = pfVar5[2] + (float)((double)param_3[2] * dVar6);
        dVar7 = (double)pfVar4[7];
        dVar9 = (double)pfVar4[6];
        dVar10 = (double)pfVar4[8];
        dVar8 = (double)((float)((double)fVar3 * dVar10 +
                                (double)(float)((double)fVar1 * dVar9 +
                                               (double)(float)((double)fVar2 * dVar7))) -
                        (float)(dVar10 * (double)pfVar4[2] +
                               (double)(float)(dVar9 * (double)*pfVar4 +
                                              (double)(float)(dVar7 * (double)pfVar4[1]))));
        if (((double)FLOAT_803df934 <= dVar8) && (dVar8 <= (double)pfVar4[0xb])) {
          local_6c = (float)((double)*pfVar4 + (double)(float)(dVar9 * dVar8));
          local_68 = (float)((double)pfVar4[1] + (double)(float)(dVar7 * dVar8));
          local_64 = (float)((double)pfVar4[2] + (double)(float)(dVar10 * dVar8));
          *param_5 = (float)((double)fVar1 - (double)local_6c);
          param_5[1] = (float)((double)fVar2 - (double)local_68);
          param_5[2] = (float)((double)fVar3 - (double)local_64);
          FUN_800228f0(param_5);
          param_5[3] = pfVar4[9] - (fVar3 * param_5[2] + fVar1 * *param_5 + fVar2 * param_5[1]);
          *param_4 = fVar1;
          param_4[1] = fVar2;
          param_4[2] = fVar3;
          *param_6 = (float)dVar6;
        }
      }
    }
  }
  FUN_80286888();
  return;
}

