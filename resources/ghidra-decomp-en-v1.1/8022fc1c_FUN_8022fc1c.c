// Function: FUN_8022fc1c
// Entry: 8022fc1c
// Size: 48 bytes

void FUN_8022fc1c(int param_1,uint param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e7d08);
  return;
}

