// Function: FUN_8019b1d8
// Entry: 8019b1d8
// Size: 544 bytes

/* WARNING: Removing unreachable block (ram,0x8019b3cc) */
/* WARNING: Removing unreachable block (ram,0x8019b3d4) */

undefined4 FUN_8019b1d8(double param_1,short *param_2,short *param_3,undefined4 param_4)

{
  int iVar1;
  short sVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  if (param_3 == (short *)0x0) {
    uVar3 = 0;
  }
  else {
    local_50[0] = *(float *)(param_3 + 6) - *(float *)(param_2 + 6);
    local_54 = *(float *)(param_3 + 8) - *(float *)(param_2 + 8);
    local_58 = *(float *)(param_3 + 10) - *(float *)(param_2 + 10);
    dVar5 = (double)FUN_802931a0((double)(local_58 * local_58 +
                                         local_50[0] * local_50[0] + local_54 * local_54));
    if ((double)(float)((double)FLOAT_803e4124 * param_1) <= dVar5) {
      FUN_800701a4(local_50,&local_54,&local_58);
      *(float *)(param_2 + 0x12) = FLOAT_803db414 * (float)((double)local_50[0] * param_1);
      *(float *)(param_2 + 0x14) = FLOAT_803db414 * (float)((double)local_54 * param_1);
      *(float *)(param_2 + 0x16) = FLOAT_803db414 * (float)((double)local_58 * param_1);
      sVar2 = (*param_3 + -0x8000) - *param_2;
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      uStack68 = (int)*param_2 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack60 = (int)sVar2 ^ 0x80000000;
      local_40 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e4118) +
                   (float)((double)((FLOAT_803e4128 +
                                    (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4118)
                                    ) * (float)(param_1 * (double)FLOAT_803db414)) / dVar5));
      local_38 = (longlong)iVar1;
      *param_2 = (short)iVar1;
      FUN_8002b95c((double)*(float *)(param_2 + 0x12),(double)*(float *)(param_2 + 0x14),
                   (double)*(float *)(param_2 + 0x16),param_2);
      if (param_2[0x50] != 0x1a) {
        FUN_80030334((double)FLOAT_803e4110,param_2,0x1a,0);
      }
      FUN_8002f5d4(param_1,param_2,param_4);
      uVar3 = 0;
    }
    else {
      uVar3 = 1;
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return uVar3;
}

