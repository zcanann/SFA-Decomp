// Function: FUN_8018375c
// Entry: 8018375c
// Size: 76 bytes

double FUN_8018375c(int param_1)

{
  return (double)(FLOAT_803e4644 -
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x13)) -
                        DOUBLE_803e4648) /
                 (float)((double)CONCAT44(0x43300000,
                                          (uint)*(byte *)(*(int *)(param_1 + 0xb8) + 0x28)) -
                        DOUBLE_803e4648));
}

