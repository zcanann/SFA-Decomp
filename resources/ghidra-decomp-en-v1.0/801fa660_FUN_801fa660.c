// Function: FUN_801fa660
// Entry: 801fa660
// Size: 148 bytes

void FUN_801fa660(int param_1,int param_2)

{
  *(float *)(param_1 + 0x28) = FLOAT_803e6090;
  *(float *)(param_1 + 0x10) = FLOAT_803e60a4 + *(float *)(param_2 + 0xc);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e609c;
  (**(code **)(*DAT_803dca88 + 8))(param_1,0x38c,0,2,0xffffffff,0);
  FUN_8000bb18(param_1,0x103);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

