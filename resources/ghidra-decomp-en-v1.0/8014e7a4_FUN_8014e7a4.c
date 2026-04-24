// Function: FUN_8014e7a4
// Entry: 8014e7a4
// Size: 232 bytes

void FUN_8014e7a4(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b8f4((double)FLOAT_803e2650);
    if ((*(byte *)(iVar1 + 0x26) & 0x10) != 0) {
      FUN_80099d84((double)FLOAT_803e2650,
                   (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                                   DOUBLE_803e2640) / FLOAT_803e2654),param_1,3,0);
    }
    if ((*(byte *)(iVar1 + 0x26) & 8) != 0) {
      FUN_80099d84((double)FLOAT_803e2650,
                   (double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36)) -
                                   DOUBLE_803e2640) / FLOAT_803e2654),param_1,4,0);
    }
  }
  return;
}

