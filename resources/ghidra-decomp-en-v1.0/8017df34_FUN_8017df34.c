// Function: FUN_8017df34
// Entry: 8017df34
// Size: 620 bytes

/* WARNING: Removing unreachable block (ram,0x8017e178) */
/* WARNING: Removing unreachable block (ram,0x8017e180) */

undefined4 FUN_8017df34(double param_1,undefined2 *param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  if (FLOAT_803e37d4 == *(float *)(param_3 + 0x3c)) {
    if (FLOAT_803e37d4 <
        *(float *)(param_3 + 0x30) - (float)((double)*(float *)(param_3 + 0x2c) - param_1)) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar7 = (double)*(float *)(param_3 + 0x40);
      dVar8 = (double)*(float *)(param_3 + 0x44);
      dVar6 = (double)FUN_802931a0((double)(float)(dVar8 * dVar8 -
                                                  (double)((float)((double)FLOAT_803e37d8 * dVar7) *
                                                          *(float *)(param_3 + 0x30))));
      fVar1 = (float)((double)FLOAT_803e37dc * dVar7);
      fVar2 = fVar1;
      if (fVar1 < FLOAT_803e37d4) {
        fVar2 = -fVar1;
      }
      fVar3 = FLOAT_803e37c8;
      if (FLOAT_803e37e0 < fVar2) {
        fVar2 = (float)(-dVar8 - dVar6) / fVar1;
        fVar3 = (float)(-dVar8 + dVar6) / fVar1;
        if (FLOAT_803e37d4 < fVar2) {
          fVar3 = fVar2;
        }
      }
      *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
      *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
      *(float *)(param_3 + 0x30) = FLOAT_803e37d4;
      *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
      *param_2 = *(undefined2 *)(param_3 + 0x48);
      param_2[1] = *(undefined2 *)(param_3 + 0x4a);
      param_2[2] = *(undefined2 *)(param_3 + 0x4c);
      *(float *)(param_3 + 0x44) =
           FLOAT_803e37dc * *(float *)(param_3 + 0x40) * fVar3 + *(float *)(param_3 + 0x44);
      *(undefined4 *)(param_3 + 0x3c) = *(undefined4 *)(param_3 + 0x28);
      (**(code **)(*DAT_803dca98 + 0x10))
                ((double)*(float *)(param_2 + 6),(double)*(float *)(param_3 + 0x34),
                 (double)*(float *)(param_2 + 10),param_2);
      uVar4 = 0;
    }
  }
  else if ((float)(param_1 - (double)*(float *)(param_3 + 0x2c)) < FLOAT_803e37d4) {
    *(float *)(param_2 + 8) = (float)param_1;
    uVar4 = 1;
  }
  else {
    dVar8 = (double)(*(float *)(param_3 + 0x40) + *(float *)(param_3 + 0x3c));
    dVar7 = (double)*(float *)(param_3 + 0x44);
    dVar6 = (double)FUN_802931a0((double)(float)(dVar7 * dVar7 -
                                                (double)((float)((double)FLOAT_803e37d8 * dVar8) *
                                                        *(float *)(param_3 + 0x30))));
    fVar1 = (float)((double)FLOAT_803e37dc * dVar8);
    fVar2 = fVar1;
    if (fVar1 < FLOAT_803e37d4) {
      fVar2 = -fVar1;
    }
    fVar3 = FLOAT_803e37c8;
    if (FLOAT_803e37e0 < fVar2) {
      fVar2 = (float)(-dVar7 - dVar6) / fVar1;
      fVar3 = (float)(-dVar7 + dVar6) / fVar1;
      if (FLOAT_803e37d4 < fVar2) {
        fVar3 = fVar2;
      }
    }
    *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
    *(float *)(param_3 + 0x3c) = FLOAT_803e37fc;
    *(float *)(param_3 + 0x44) = FLOAT_803e3800;
    uVar4 = 0;
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  return uVar4;
}

