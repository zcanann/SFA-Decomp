// Function: FUN_80215864
// Entry: 80215864
// Size: 104 bytes

void FUN_80215864(undefined4 param_1)

{
  float local_18;
  float local_14;
  float local_10 [4];
  
  if (*(int *)(DAT_803de9d4 + 0x178) != 0) {
    FUN_80038524(param_1,5,&local_18,&local_14,local_10,0);
    FUN_8001de4c((double)local_18,(double)local_14,(double)local_10[0],
                 *(int **)(DAT_803de9d4 + 0x178));
    FUN_8001d774(*(int *)(DAT_803de9d4 + 0x178));
  }
  return;
}

