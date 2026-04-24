// Function: FUN_80010320
// Entry: 80010320
// Size: 1508 bytes

/* WARNING: Removing unreachable block (ram,0x800108d8) */
/* WARNING: Removing unreachable block (ram,0x800108e0) */

undefined4 FUN_80010320(double param_1,float *param_2)

{
  float fVar1;
  undefined4 uVar2;
  uint uVar3;
  float fVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  double local_48;
  double local_40;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  fVar4 = (float)(param_1 * (double)FLOAT_803db414);
  if (fVar4 <= FLOAT_803de658) {
    if (fVar4 < FLOAT_803de658) {
      uVar3 = (uint)(FLOAT_803de690 * *param_2);
      if (uVar3 == 0x14) {
        uVar3 = 0x13;
      }
      if (param_2[0x20] == 0.0) {
        param_2[1] = param_2[uVar3 + 6] - param_2[1];
      }
      else if (*param_2 <= FLOAT_803de658) {
        uVar2 = 1;
        goto LAB_800108d8;
      }
      param_2[2] = param_2[2] + fVar4;
      dVar8 = (double)(fVar4 + param_2[1]);
      dVar7 = (double)FLOAT_803de658;
      while (dVar8 < dVar7) {
        dVar8 = (double)(float)(dVar8 + (double)param_2[uVar3 + 6]);
        if ((dVar8 < dVar7) && (uVar3 = uVar3 - 1, (int)uVar3 < 0)) {
          fVar4 = param_2[4];
          if (((code *)param_2[0x25] == (code *)0x80010ce4) ||
             ((code *)param_2[0x25] == FUN_80010dc0)) {
            param_2[4] = (float)((int)param_2[4] + -3);
          }
          fVar1 = param_2[4];
          param_2[4] = (float)((int)fVar1 + -1);
          if ((int)fVar1 + -1 < 0) {
            if (param_2[0x21] != 0.0) {
              dVar7 = (double)(*(code *)param_2[0x25])
                                        ((double)FLOAT_803de658,(int)param_2[0x21] + (int)fVar4 * 4,
                                         param_2 + 0x1d);
              param_2[0x1a] = (float)dVar7;
            }
            if (param_2[0x22] != 0.0) {
              dVar7 = (double)(*(code *)param_2[0x25])
                                        ((double)FLOAT_803de658,(int)param_2[0x22] + (int)fVar4 * 4,
                                         param_2 + 0x1e);
              param_2[0x1b] = (float)dVar7;
            }
            if (param_2[0x23] != 0.0) {
              dVar7 = (double)(*(code *)param_2[0x25])
                                        ((double)FLOAT_803de658,(int)param_2[0x23] + (int)fVar4 * 4,
                                         param_2 + 0x1f);
              param_2[0x1c] = (float)dVar7;
            }
            fVar4 = FLOAT_803de658;
            *param_2 = FLOAT_803de658;
            param_2[1] = -param_2[6];
            param_2[2] = fVar4;
            param_2[4] = 0.0;
            uVar2 = 1;
            goto LAB_800108d8;
          }
          FUN_8000fe8c(param_2,0x14);
          uVar3 = 0x13;
        }
      }
      local_40 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      fVar4 = (float)(local_40 - DOUBLE_803de688) / FLOAT_803de690;
      local_48 = (double)CONCAT44(0x43300000,uVar3 + 1 ^ 0x80000000);
      dVar7 = (double)((float)(dVar8 / (double)param_2[uVar3 + 6]) *
                       ((float)(local_48 - DOUBLE_803de688) / FLOAT_803de690 - fVar4) + fVar4);
      if (param_2[0x21] != 0.0) {
        dVar6 = (double)(*(code *)param_2[0x25])
                                  (dVar7,(int)param_2[0x21] + (int)param_2[4] * 4,param_2 + 0x1d);
        param_2[0x1a] = (float)dVar6;
      }
      if (param_2[0x22] != 0.0) {
        dVar6 = (double)(*(code *)param_2[0x25])
                                  (dVar7,(int)param_2[0x22] + (int)param_2[4] * 4,param_2 + 0x1e);
        param_2[0x1b] = (float)dVar6;
      }
      if (param_2[0x23] != 0.0) {
        dVar6 = (double)(*(code *)param_2[0x25])
                                  (dVar7,(int)param_2[0x23] + (int)param_2[4] * 4,param_2 + 0x1f);
        param_2[0x1c] = (float)dVar6;
      }
      *param_2 = (float)dVar7;
      param_2[1] = (float)(dVar8 - (double)param_2[uVar3 + 6]);
      param_2[0x20] = 1.401298e-45;
    }
  }
  else {
    uVar3 = (uint)(FLOAT_803de690 * *param_2);
    if (uVar3 == 0x14) {
      uVar3 = 0x13;
    }
    if (param_2[0x20] == 0.0) {
      if (FLOAT_803de674 <= *param_2) {
        uVar2 = 1;
        goto LAB_800108d8;
      }
    }
    else {
      param_2[1] = param_2[uVar3 + 6] + param_2[1];
    }
    param_2[2] = param_2[2] + fVar4;
    dVar8 = (double)(fVar4 + param_2[1]);
    dVar7 = (double)FLOAT_803de658;
    while (dVar7 < dVar8) {
      dVar8 = (double)(float)(dVar8 - (double)param_2[uVar3 + 6]);
      if ((dVar7 < dVar8) && (uVar3 = uVar3 + 1, 0x13 < (int)uVar3)) {
        fVar4 = param_2[4];
        if (((code *)param_2[0x25] == (code *)0x80010ce4) || ((code *)param_2[0x25] == FUN_80010dc0)
           ) {
          param_2[4] = (float)((int)param_2[4] + 3);
        }
        fVar1 = param_2[4];
        param_2[4] = (float)((int)fVar1 + 1);
        if ((int)param_2[0x24] + -4 < (int)fVar1 + 1) {
          if (param_2[0x21] != 0.0) {
            dVar7 = (double)(*(code *)param_2[0x25])
                                      ((double)FLOAT_803de674,(int)param_2[0x21] + (int)fVar4 * 4,
                                       param_2 + 0x1d);
            param_2[0x1a] = (float)dVar7;
          }
          if (param_2[0x22] != 0.0) {
            dVar7 = (double)(*(code *)param_2[0x25])
                                      ((double)FLOAT_803de674,(int)param_2[0x22] + (int)fVar4 * 4,
                                       param_2 + 0x1e);
            param_2[0x1b] = (float)dVar7;
          }
          if (param_2[0x23] != 0.0) {
            dVar7 = (double)(*(code *)param_2[0x25])
                                      ((double)FLOAT_803de674,(int)param_2[0x23] + (int)fVar4 * 4,
                                       param_2 + 0x1f);
            param_2[0x1c] = (float)dVar7;
          }
          *param_2 = FLOAT_803de674;
          param_2[1] = FLOAT_803de658;
          param_2[2] = param_2[3];
          param_2[4] = (float)((int)param_2[0x24] + -4);
          uVar2 = 1;
          goto LAB_800108d8;
        }
        FUN_8000fe8c(param_2,0x14);
        uVar3 = 0;
      }
    }
    dVar8 = (double)(float)(dVar8 + (double)param_2[uVar3 + 6]);
    local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
    fVar4 = (float)(local_48 - DOUBLE_803de688) / FLOAT_803de690;
    local_40 = (double)CONCAT44(0x43300000,uVar3 + 1 ^ 0x80000000);
    dVar7 = (double)((float)(dVar8 / (double)param_2[uVar3 + 6]) *
                     ((float)(local_40 - DOUBLE_803de688) / FLOAT_803de690 - fVar4) + fVar4);
    if (param_2[0x21] != 0.0) {
      dVar6 = (double)(*(code *)param_2[0x25])
                                (dVar7,(int)param_2[0x21] + (int)param_2[4] * 4,param_2 + 0x1d);
      param_2[0x1a] = (float)dVar6;
    }
    if (param_2[0x22] != 0.0) {
      dVar6 = (double)(*(code *)param_2[0x25])
                                (dVar7,(int)param_2[0x22] + (int)param_2[4] * 4,param_2 + 0x1e);
      param_2[0x1b] = (float)dVar6;
    }
    if (param_2[0x23] != 0.0) {
      dVar6 = (double)(*(code *)param_2[0x25])
                                (dVar7,(int)param_2[0x23] + (int)param_2[4] * 4,param_2 + 0x1f);
      param_2[0x1c] = (float)dVar6;
    }
    *param_2 = (float)dVar7;
    param_2[1] = (float)dVar8;
    param_2[0x20] = 0.0;
  }
  uVar2 = 0;
LAB_800108d8:
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return uVar2;
}

