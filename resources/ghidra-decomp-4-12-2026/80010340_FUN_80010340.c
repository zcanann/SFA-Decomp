// Function: FUN_80010340
// Entry: 80010340
// Size: 1508 bytes

/* WARNING: Removing unreachable block (ram,0x80010900) */
/* WARNING: Removing unreachable block (ram,0x800108f8) */
/* WARNING: Removing unreachable block (ram,0x80010358) */
/* WARNING: Removing unreachable block (ram,0x80010350) */

undefined4 FUN_80010340(double param_1,float *param_2)

{
  float fVar1;
  uint uVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 local_48;
  undefined8 local_40;
  
  fVar3 = (float)(param_1 * (double)FLOAT_803dc074);
  if (fVar3 <= FLOAT_803df2d8) {
    if (fVar3 < FLOAT_803df2d8) {
      uVar2 = (uint)(FLOAT_803df310 * *param_2);
      if (uVar2 == 0x14) {
        uVar2 = 0x13;
      }
      if (param_2[0x20] == 0.0) {
        param_2[1] = param_2[uVar2 + 6] - param_2[1];
      }
      else if (*param_2 <= FLOAT_803df2d8) {
        return 1;
      }
      param_2[2] = param_2[2] + fVar3;
      dVar6 = (double)(fVar3 + param_2[1]);
      dVar5 = (double)FLOAT_803df2d8;
      while (dVar6 < dVar5) {
        dVar6 = (double)(float)(dVar6 + (double)param_2[uVar2 + 6]);
        if ((dVar6 < dVar5) && (uVar2 = uVar2 - 1, (int)uVar2 < 0)) {
          fVar3 = param_2[4];
          if (((code *)param_2[0x25] == (code *)0x80010d04) ||
             ((code *)param_2[0x25] == FUN_80010de0)) {
            param_2[4] = (float)((int)param_2[4] + -3);
          }
          fVar1 = param_2[4];
          param_2[4] = (float)((int)fVar1 + -1);
          if ((int)fVar1 + -1 < 0) {
            if (param_2[0x21] != 0.0) {
              dVar5 = (double)(*(code *)param_2[0x25])
                                        ((double)FLOAT_803df2d8,(int)param_2[0x21] + (int)fVar3 * 4,
                                         param_2 + 0x1d);
              param_2[0x1a] = (float)dVar5;
            }
            if (param_2[0x22] != 0.0) {
              dVar5 = (double)(*(code *)param_2[0x25])
                                        ((double)FLOAT_803df2d8,(int)param_2[0x22] + (int)fVar3 * 4,
                                         param_2 + 0x1e);
              param_2[0x1b] = (float)dVar5;
            }
            if (param_2[0x23] != 0.0) {
              dVar5 = (double)(*(code *)param_2[0x25])
                                        ((double)FLOAT_803df2d8,(int)param_2[0x23] + (int)fVar3 * 4,
                                         param_2 + 0x1f);
              param_2[0x1c] = (float)dVar5;
            }
            fVar3 = FLOAT_803df2d8;
            *param_2 = FLOAT_803df2d8;
            param_2[1] = -param_2[6];
            param_2[2] = fVar3;
            param_2[4] = 0.0;
            return 1;
          }
          FUN_8000feac();
          uVar2 = 0x13;
        }
      }
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      fVar3 = (float)(local_40 - DOUBLE_803df308) / FLOAT_803df310;
      local_48 = (double)CONCAT44(0x43300000,uVar2 + 1 ^ 0x80000000);
      dVar5 = (double)((float)(dVar6 / (double)param_2[uVar2 + 6]) *
                       ((float)(local_48 - DOUBLE_803df308) / FLOAT_803df310 - fVar3) + fVar3);
      if (param_2[0x21] != 0.0) {
        dVar4 = (double)(*(code *)param_2[0x25])
                                  (dVar5,(int)param_2[0x21] + (int)param_2[4] * 4,param_2 + 0x1d);
        param_2[0x1a] = (float)dVar4;
      }
      if (param_2[0x22] != 0.0) {
        dVar4 = (double)(*(code *)param_2[0x25])
                                  (dVar5,(int)param_2[0x22] + (int)param_2[4] * 4,param_2 + 0x1e);
        param_2[0x1b] = (float)dVar4;
      }
      if (param_2[0x23] != 0.0) {
        dVar4 = (double)(*(code *)param_2[0x25])
                                  (dVar5,(int)param_2[0x23] + (int)param_2[4] * 4,param_2 + 0x1f);
        param_2[0x1c] = (float)dVar4;
      }
      *param_2 = (float)dVar5;
      param_2[1] = (float)(dVar6 - (double)param_2[uVar2 + 6]);
      param_2[0x20] = 1.4013e-45;
    }
  }
  else {
    uVar2 = (uint)(FLOAT_803df310 * *param_2);
    if (uVar2 == 0x14) {
      uVar2 = 0x13;
    }
    if (param_2[0x20] == 0.0) {
      if (FLOAT_803df2f4 <= *param_2) {
        return 1;
      }
    }
    else {
      param_2[1] = param_2[uVar2 + 6] + param_2[1];
    }
    param_2[2] = param_2[2] + fVar3;
    dVar6 = (double)(fVar3 + param_2[1]);
    dVar5 = (double)FLOAT_803df2d8;
    while (dVar5 < dVar6) {
      dVar6 = (double)(float)(dVar6 - (double)param_2[uVar2 + 6]);
      if ((dVar5 < dVar6) && (uVar2 = uVar2 + 1, 0x13 < (int)uVar2)) {
        fVar3 = param_2[4];
        if (((code *)param_2[0x25] == (code *)0x80010d04) || ((code *)param_2[0x25] == FUN_80010de0)
           ) {
          param_2[4] = (float)((int)param_2[4] + 3);
        }
        fVar1 = param_2[4];
        param_2[4] = (float)((int)fVar1 + 1);
        if ((int)param_2[0x24] + -4 < (int)fVar1 + 1) {
          if (param_2[0x21] != 0.0) {
            dVar5 = (double)(*(code *)param_2[0x25])
                                      ((double)FLOAT_803df2f4,(int)param_2[0x21] + (int)fVar3 * 4,
                                       param_2 + 0x1d);
            param_2[0x1a] = (float)dVar5;
          }
          if (param_2[0x22] != 0.0) {
            dVar5 = (double)(*(code *)param_2[0x25])
                                      ((double)FLOAT_803df2f4,(int)param_2[0x22] + (int)fVar3 * 4,
                                       param_2 + 0x1e);
            param_2[0x1b] = (float)dVar5;
          }
          if (param_2[0x23] != 0.0) {
            dVar5 = (double)(*(code *)param_2[0x25])
                                      ((double)FLOAT_803df2f4,(int)param_2[0x23] + (int)fVar3 * 4,
                                       param_2 + 0x1f);
            param_2[0x1c] = (float)dVar5;
          }
          *param_2 = FLOAT_803df2f4;
          param_2[1] = FLOAT_803df2d8;
          param_2[2] = param_2[3];
          param_2[4] = (float)((int)param_2[0x24] + -4);
          return 1;
        }
        FUN_8000feac();
        uVar2 = 0;
      }
    }
    dVar6 = (double)(float)(dVar6 + (double)param_2[uVar2 + 6]);
    local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    fVar3 = (float)(local_48 - DOUBLE_803df308) / FLOAT_803df310;
    local_40 = (double)CONCAT44(0x43300000,uVar2 + 1 ^ 0x80000000);
    dVar5 = (double)((float)(dVar6 / (double)param_2[uVar2 + 6]) *
                     ((float)(local_40 - DOUBLE_803df308) / FLOAT_803df310 - fVar3) + fVar3);
    if (param_2[0x21] != 0.0) {
      dVar4 = (double)(*(code *)param_2[0x25])
                                (dVar5,(int)param_2[0x21] + (int)param_2[4] * 4,param_2 + 0x1d);
      param_2[0x1a] = (float)dVar4;
    }
    if (param_2[0x22] != 0.0) {
      dVar4 = (double)(*(code *)param_2[0x25])
                                (dVar5,(int)param_2[0x22] + (int)param_2[4] * 4,param_2 + 0x1e);
      param_2[0x1b] = (float)dVar4;
    }
    if (param_2[0x23] != 0.0) {
      dVar4 = (double)(*(code *)param_2[0x25])
                                (dVar5,(int)param_2[0x23] + (int)param_2[4] * 4,param_2 + 0x1f);
      param_2[0x1c] = (float)dVar4;
    }
    *param_2 = (float)dVar5;
    param_2[1] = (float)dVar6;
    param_2[0x20] = 0.0;
  }
  return 0;
}

