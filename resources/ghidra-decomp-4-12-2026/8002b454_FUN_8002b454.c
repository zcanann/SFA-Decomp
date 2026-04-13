// Function: FUN_8002b454
// Entry: 8002b454
// Size: 256 bytes

void FUN_8002b454(short *param_1,undefined4 *param_2)

{
  short local_68;
  short local_66;
  short local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float afStack_50 [18];
  
  if (*(int *)(param_1 + 0x18) == 0) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 6) - FLOAT_803dda58;
    *(float *)(param_1 + 10) = *(float *)(param_1 + 10) - FLOAT_803dda5c;
  }
  local_5c = -*(float *)(param_1 + 6);
  local_58 = -*(float *)(param_1 + 8);
  local_54 = -*(float *)(param_1 + 10);
  local_68 = -*param_1;
  local_66 = -param_1[1];
  local_64 = -param_1[2];
  local_60 = FLOAT_803df510;
  FUN_80021c64(afStack_50,(int)&local_68);
  FUN_800216cc(afStack_50,param_2);
  if (*(int *)(param_1 + 0x18) == 0) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 6) + FLOAT_803dda58;
    *(float *)(param_1 + 10) = *(float *)(param_1 + 10) + FLOAT_803dda5c;
  }
  return;
}

