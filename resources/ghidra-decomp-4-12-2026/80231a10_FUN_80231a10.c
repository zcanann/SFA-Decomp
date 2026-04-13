// Function: FUN_80231a10
// Entry: 80231a10
// Size: 48 bytes

void FUN_80231a10(int param_1,uint param_2)

{
  **(float **)(param_1 + 0xb8) =
       (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e7dc8);
  return;
}

