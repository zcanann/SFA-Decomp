// Function: FUN_8005b0a8
// Entry: 8005b0a8
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x8005b148) */

void FUN_8005b0a8(double param_1,undefined8 param_2,double param_3,float *param_4,float *param_5)

{
  float fVar1;
  double dVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  dVar4 = (double)FUN_80291e40((double)(float)(param_1 / (double)FLOAT_803debb4));
  dVar5 = (double)FUN_80291e40((double)(float)(param_3 / (double)FLOAT_803debb4));
  dVar2 = DOUBLE_803debc0;
  fVar1 = FLOAT_803debb4;
  *param_4 = FLOAT_803debb4 *
             (float)((double)CONCAT44(0x43300000,(int)dVar4 ^ 0x80000000) - DOUBLE_803debc0);
  *param_5 = fVar1 * (float)((double)CONCAT44(0x43300000,(int)dVar5 ^ 0x80000000) - dVar2);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return;
}

