// Function: FUN_800664fc
// Entry: 800664fc
// Size: 752 bytes

/* WARNING: Removing unreachable block (ram,0x800667c4) */
/* WARNING: Removing unreachable block (ram,0x800667bc) */
/* WARNING: Removing unreachable block (ram,0x800667cc) */

void FUN_800664fc(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4,float *param_5
                 ,float *param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  undefined4 uVar5;
  float *pfVar6;
  undefined4 uVar7;
  double extraout_f1;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar13 = FUN_802860d8();
  pfVar4 = (float *)((ulonglong)uVar13 >> 0x20);
  pfVar6 = (float *)uVar13;
  dVar9 = extraout_f1;
  FUN_800228b0(param_3,pfVar4 + 6,&local_54);
  dVar8 = (double)FUN_8002282c(&local_54);
  if ((double)FLOAT_803decb4 == dVar8) {
    uVar5 = 0;
  }
  else {
    local_60 = *pfVar6 - *pfVar4;
    local_5c = pfVar6[1] - pfVar4[1];
    local_58 = pfVar6[2] - pfVar4[2];
    fVar1 = local_4c * local_58 + local_54 * local_60 + local_50 * local_5c;
    dVar11 = (double)(fVar1 * fVar1);
    if (dVar11 <= (double)pfVar4[10]) {
      FUN_800228b0(&local_60,pfVar4 + 6,&local_6c);
      dVar12 = (double)(float)(-(double)(local_64 * local_4c +
                                        local_6c * local_54 + local_68 * local_50) / dVar8);
      FUN_800228b0(&local_54,pfVar4 + 6,&local_6c);
      FUN_8002282c(&local_6c);
      dVar8 = (double)FUN_802931a0((double)(float)((double)pfVar4[10] - dVar11));
      dVar8 = (double)(float)(dVar8 / (double)(param_3[2] * local_64 +
                                              (float)((double)*param_3 * (double)local_6c +
                                                     (double)(param_3[1] * local_68))));
      if (dVar8 < (double)FLOAT_803decb4) {
        dVar8 = -dVar8;
      }
      dVar8 = (double)(float)(dVar12 - dVar8);
      if (((double)FLOAT_803decb4 <= dVar8) && (dVar8 <= dVar9)) {
        fVar1 = *pfVar6 + (float)((double)*param_3 * dVar8);
        fVar2 = pfVar6[1] + (float)((double)param_3[1] * dVar8);
        fVar3 = pfVar6[2] + (float)((double)param_3[2] * dVar8);
        dVar9 = (double)pfVar4[7];
        dVar11 = (double)pfVar4[6];
        dVar12 = (double)pfVar4[8];
        dVar10 = (double)((float)((double)fVar3 * dVar12 +
                                 (double)(float)((double)fVar1 * dVar11 +
                                                (double)(float)((double)fVar2 * dVar9))) -
                         (float)(dVar12 * (double)pfVar4[2] +
                                (double)(float)(dVar11 * (double)*pfVar4 +
                                               (double)(float)(dVar9 * (double)pfVar4[1]))));
        if (((double)FLOAT_803decb4 <= dVar10) && (dVar10 <= (double)pfVar4[0xb])) {
          local_6c = (float)((double)*pfVar4 + (double)(float)(dVar11 * dVar10));
          local_68 = (float)((double)pfVar4[1] + (double)(float)(dVar9 * dVar10));
          local_64 = (float)((double)pfVar4[2] + (double)(float)(dVar12 * dVar10));
          *param_5 = (float)((double)fVar1 - (double)local_6c);
          param_5[1] = (float)((double)fVar2 - (double)local_68);
          param_5[2] = (float)((double)fVar3 - (double)local_64);
          FUN_8002282c(param_5);
          param_5[3] = pfVar4[9] - (fVar3 * param_5[2] + fVar1 * *param_5 + fVar2 * param_5[1]);
          *param_4 = fVar1;
          param_4[1] = fVar2;
          param_4[2] = fVar3;
          *param_6 = (float)dVar8;
          uVar5 = 3;
          goto LAB_800667bc;
        }
      }
    }
    uVar5 = 0;
  }
LAB_800667bc:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  FUN_80286124(uVar5);
  return;
}

