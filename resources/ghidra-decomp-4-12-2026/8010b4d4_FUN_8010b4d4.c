// Function: FUN_8010b4d4
// Entry: 8010b4d4
// Size: 444 bytes

void FUN_8010b4d4(double param_1,short *param_2,undefined4 *param_3,uint param_4,uint param_5,
                 uint param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  
  *(undefined *)(DAT_803de1d8 + 100) = 0;
  *(undefined4 *)(DAT_803de1d8 + 0x10) = *(undefined4 *)(param_2 + 6);
  *(undefined4 *)(DAT_803de1d8 + 0x18) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(DAT_803de1d8 + 0x20) = *(undefined4 *)(param_2 + 10);
  dVar4 = DOUBLE_803e2520;
  *(float *)(DAT_803de1d8 + 0x28) =
       (float)((double)CONCAT44(0x43300000,(int)*param_2 ^ 0x80000000) - DOUBLE_803e2520);
  *(float *)(DAT_803de1d8 + 0x30) =
       (float)((double)CONCAT44(0x43300000,(int)param_2[1] ^ 0x80000000) - dVar4);
  *(float *)(DAT_803de1d8 + 0x38) =
       (float)((double)CONCAT44(0x43300000,(int)param_2[2] ^ 0x80000000) - dVar4);
  *(undefined4 *)(DAT_803de1d8 + 0x40) = *(undefined4 *)(param_2 + 0x5a);
  *(undefined4 *)(DAT_803de1d8 + 0x14) = *param_3;
  *(undefined4 *)(DAT_803de1d8 + 0x1c) = param_3[1];
  *(undefined4 *)(DAT_803de1d8 + 0x24) = param_3[2];
  *(float *)(DAT_803de1d8 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,param_4 ^ 0x80000000) - dVar4);
  *(float *)(DAT_803de1d8 + 0x34) =
       (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - dVar4);
  *(float *)(DAT_803de1d8 + 0x3c) =
       (float)((double)CONCAT44(0x43300000,param_6 ^ 0x80000000) - dVar4);
  *(float *)(DAT_803de1d8 + 0x44) = (float)param_1;
  *(float *)(DAT_803de1d8 + 0x5c) = FLOAT_803e2508;
  fVar1 = *(float *)(DAT_803de1d8 + 0x14) - *(float *)(DAT_803de1d8 + 0x10);
  fVar2 = *(float *)(DAT_803de1d8 + 0x1c) - *(float *)(DAT_803de1d8 + 0x18);
  fVar3 = *(float *)(DAT_803de1d8 + 0x24) - *(float *)(DAT_803de1d8 + 0x20);
  dVar4 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
  *(float *)(DAT_803de1d8 + 0x60) = (float)dVar4;
  (**(code **)(*DAT_803dd6d0 + 0x34))
            ((double)*(float *)(DAT_803de1d8 + 0x60),(double)FLOAT_803e2530,(double)FLOAT_803e2534,
             (double)FLOAT_803e2534,(double)FLOAT_803e2538,DAT_803de1d8 + 0x48);
  return;
}

