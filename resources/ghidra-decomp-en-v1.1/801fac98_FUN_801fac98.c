// Function: FUN_801fac98
// Entry: 801fac98
// Size: 148 bytes

void FUN_801fac98(uint param_1,int param_2)

{
  *(float *)(param_1 + 0x28) = FLOAT_803e6d28;
  *(float *)(param_1 + 0x10) = FLOAT_803e6d3c + *(float *)(param_2 + 0xc);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e6d34;
  (**(code **)(*DAT_803dd708 + 8))(param_1,0x38c,0,2,0xffffffff,0);
  FUN_8000bb38(param_1,0x103);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

