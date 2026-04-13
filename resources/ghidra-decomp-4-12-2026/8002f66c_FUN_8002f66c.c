// Function: FUN_8002f66c
// Entry: 8002f66c
// Size: 96 bytes

void FUN_8002f66c(int param_1,uint param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
  if (iVar1 != 0) {
    *(short *)(*(int *)(iVar1 + 0x2c) + 0x5e) =
         (short)(int)(FLOAT_803df574 /
                     (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803df580));
  }
  return;
}

