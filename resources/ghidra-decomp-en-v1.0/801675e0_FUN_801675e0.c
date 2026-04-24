// Function: FUN_801675e0
// Entry: 801675e0
// Size: 224 bytes

void FUN_801675e0(int param_1,float *param_2,byte *param_3)

{
  double dVar1;
  byte *pbVar2;
  
  dVar1 = DOUBLE_803e3050;
  pbVar2 = *(byte **)(param_1 + 0xb8);
  *param_2 = *(float *)(param_1 + 0x18) -
             (float)((double)CONCAT44(0x43300000,(uint)*pbVar2) - DOUBLE_803e3050);
  param_2[1] = *(float *)(param_1 + 0x18) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[1]) - dVar1);
  param_2[2] = *(float *)(param_1 + 0x20) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[2]) - dVar1);
  param_2[3] = *(float *)(param_1 + 0x20) -
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[3]) - dVar1);
  param_2[4] = *(float *)(param_1 + 0x1c) +
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[4]) - dVar1);
  param_2[5] = *(float *)(param_1 + 0x1c) -
               (float)((double)CONCAT44(0x43300000,(uint)pbVar2[5]) - dVar1);
  *param_3 = pbVar2[6];
  return;
}

