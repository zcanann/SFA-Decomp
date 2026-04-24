// Function: FUN_8016bdb0
// Entry: 8016bdb0
// Size: 144 bytes

void FUN_8016bdb0(short *param_1,int param_2,int param_3)

{
  undefined *puVar1;
  
  *param_1 = -*(short *)(param_2 + 0x1c);
  param_1[1] = -*(short *)(param_2 + 0x1e);
  param_1[2] = -*(short *)(param_2 + 0x20);
  puVar1 = *(undefined **)(param_1 + 0x5c);
  *puVar1 = *(undefined *)(param_2 + 0x19);
  *(float *)(puVar1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1a)) - DOUBLE_803e3e88);
  puVar1[1] = 0;
  if (param_3 == 0) {
    FUN_800372f8((int)param_1,7);
  }
  return;
}

