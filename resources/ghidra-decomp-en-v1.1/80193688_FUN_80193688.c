// Function: FUN_80193688
// Entry: 80193688
// Size: 72 bytes

uint FUN_80193688(int param_1)

{
  return ((uint)(byte)((FLOAT_803e4c30 *
                        (float)((double)CONCAT44(0x43300000,
                                                 (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x20)) -
                               DOUBLE_803e4c38) < *(float *)(*(int *)(param_1 + 0xb8) + 0xc)) << 2)
         << 0x1c) >> 0x1e;
}

