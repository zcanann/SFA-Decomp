// Function: FUN_8022f558
// Entry: 8022f558
// Size: 48 bytes

void FUN_8022f558(int param_1,uint param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e7070);
  return;
}

