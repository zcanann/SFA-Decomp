// Function: FUN_8023134c
// Entry: 8023134c
// Size: 48 bytes

void FUN_8023134c(int param_1,uint param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e7130);
  return;
}

