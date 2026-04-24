// Function: FUN_8022ecc4
// Entry: 8022ecc4
// Size: 48 bytes

void FUN_8022ecc4(int param_1,uint param_2)

{
  *(float *)(*(int *)(param_1 + 0xb8) + 4) =
       (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e7cb8);
  return;
}

