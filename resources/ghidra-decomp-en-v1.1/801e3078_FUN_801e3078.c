// Function: FUN_801e3078
// Entry: 801e3078
// Size: 160 bytes

void FUN_801e3078(int param_1,int param_2)

{
  uint uVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  uVar1 = FUN_80022264(0x5a,0xf0);
  *pfVar2 = (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e64c0);
  pfVar2[1] = FLOAT_803e64a8;
  pfVar2[2] = 1.68156e-42;
  *(undefined *)(pfVar2 + 3) = 4;
  *(char *)(param_1 + 0xad) = (char)*(undefined2 *)(param_2 + 0x1a);
  if (*(short *)(param_1 + 0x46) != 0x69c) {
    DAT_803de8c0 = param_1;
  }
  return;
}

