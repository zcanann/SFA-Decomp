// Function: FUN_8010b238
// Entry: 8010b238
// Size: 444 bytes

void FUN_8010b238(double param_1,short *param_2,undefined4 *param_3,uint param_4,uint param_5,
                 uint param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  
  *(undefined *)(DAT_803dd560 + 100) = 0;
  *(undefined4 *)(DAT_803dd560 + 0x10) = *(undefined4 *)(param_2 + 6);
  *(undefined4 *)(DAT_803dd560 + 0x18) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(DAT_803dd560 + 0x20) = *(undefined4 *)(param_2 + 10);
  dVar4 = DOUBLE_803e18a0;
  *(float *)(DAT_803dd560 + 0x28) =
       (float)((double)CONCAT44(0x43300000,(int)*param_2 ^ 0x80000000) - DOUBLE_803e18a0);
  *(float *)(DAT_803dd560 + 0x30) =
       (float)((double)CONCAT44(0x43300000,(int)param_2[1] ^ 0x80000000) - dVar4);
  *(float *)(DAT_803dd560 + 0x38) =
       (float)((double)CONCAT44(0x43300000,(int)param_2[2] ^ 0x80000000) - dVar4);
  *(undefined4 *)(DAT_803dd560 + 0x40) = *(undefined4 *)(param_2 + 0x5a);
  *(undefined4 *)(DAT_803dd560 + 0x14) = *param_3;
  *(undefined4 *)(DAT_803dd560 + 0x1c) = param_3[1];
  *(undefined4 *)(DAT_803dd560 + 0x24) = param_3[2];
  *(float *)(DAT_803dd560 + 0x2c) =
       (float)((double)CONCAT44(0x43300000,param_4 ^ 0x80000000) - dVar4);
  *(float *)(DAT_803dd560 + 0x34) =
       (float)((double)CONCAT44(0x43300000,param_5 ^ 0x80000000) - dVar4);
  *(float *)(DAT_803dd560 + 0x3c) =
       (float)((double)CONCAT44(0x43300000,param_6 ^ 0x80000000) - dVar4);
  *(float *)(DAT_803dd560 + 0x44) = (float)param_1;
  *(float *)(DAT_803dd560 + 0x5c) = FLOAT_803e1888;
  fVar1 = *(float *)(DAT_803dd560 + 0x14) - *(float *)(DAT_803dd560 + 0x10);
  fVar2 = *(float *)(DAT_803dd560 + 0x1c) - *(float *)(DAT_803dd560 + 0x18);
  fVar3 = *(float *)(DAT_803dd560 + 0x24) - *(float *)(DAT_803dd560 + 0x20);
  dVar4 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
  *(float *)(DAT_803dd560 + 0x60) = (float)dVar4;
  (**(code **)(*DAT_803dca50 + 0x34))
            ((double)*(float *)(DAT_803dd560 + 0x60),(double)FLOAT_803e18b0,(double)FLOAT_803e18b4,
             (double)FLOAT_803e18b4,(double)FLOAT_803e18b8,DAT_803dd560 + 0x48);
  return;
}

