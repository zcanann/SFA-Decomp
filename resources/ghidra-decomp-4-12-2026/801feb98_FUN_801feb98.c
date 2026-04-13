// Function: FUN_801feb98
// Entry: 801feb98
// Size: 532 bytes

undefined4 FUN_801feb98(double param_1,double param_2,int param_3,float *param_4,int param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  undefined4 *local_18 [3];
  
  *param_4 = FLOAT_803e6e60;
  iVar6 = FUN_80065fcc((double)(float)((double)*(float *)(param_3 + 0xc) + param_1),
                       (double)*(float *)(param_3 + 0x10),
                       (double)(float)((double)*(float *)(param_3 + 0x14) + param_2),param_3,
                       local_18,0,0);
  if (iVar6 != 0) {
    fVar1 = FLOAT_803e6e78;
    fVar2 = FLOAT_803e6e78;
    if (0 < iVar6) {
      do {
        fVar4 = *(float *)*local_18[0] - *(float *)(param_3 + 0x10);
        if (*(char *)((float *)*local_18[0] + 5) == '\x0e') {
          fVar3 = fVar2;
          if (fVar2 < FLOAT_803e6e60) {
            fVar3 = -fVar2;
          }
          fVar5 = fVar4;
          if (fVar4 < FLOAT_803e6e60) {
            fVar5 = -fVar4;
          }
          if (fVar5 < fVar3) {
            fVar2 = fVar4;
          }
        }
        else {
          fVar3 = fVar1;
          if (fVar1 < FLOAT_803e6e60) {
            fVar3 = -fVar1;
          }
          fVar5 = fVar4;
          if (fVar4 < FLOAT_803e6e60) {
            fVar5 = -fVar4;
          }
          if (fVar5 < fVar3) {
            fVar1 = fVar4;
          }
        }
        local_18[0] = local_18[0] + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    if (param_5 == 0) {
      if (FLOAT_803e6e78 != fVar1) {
        *param_4 = fVar1;
        return 0;
      }
      if (FLOAT_803e6e78 != fVar2) {
        *param_4 = fVar2;
        return 1;
      }
      *param_4 = FLOAT_803e6e7c;
    }
    else {
      if (FLOAT_803e6e78 != fVar2) {
        fVar4 = fVar1;
        if (fVar1 < FLOAT_803e6e60) {
          fVar4 = -fVar1;
        }
        fVar3 = fVar2;
        if (fVar2 < FLOAT_803e6e60) {
          fVar3 = -fVar2;
        }
        if ((fVar4 < fVar3) && (fVar2 <= FLOAT_803e6e60)) {
          *param_4 = fVar1;
          return 1;
        }
        *param_4 = fVar2;
        return 0;
      }
      if (FLOAT_803e6e78 != fVar1) {
        *param_4 = fVar1;
        return 1;
      }
      *param_4 = FLOAT_803e6e7c;
    }
  }
  return 0;
}

