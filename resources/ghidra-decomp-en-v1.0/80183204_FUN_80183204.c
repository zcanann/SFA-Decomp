// Function: FUN_80183204
// Entry: 80183204
// Size: 76 bytes

double FUN_80183204(int param_1)

{
  return (double)(FLOAT_803e39ac -
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x13)) -
                        DOUBLE_803e39b0) /
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x28)) -
                        DOUBLE_803e39b0));
}

