// Function: FUN_801ecdd8
// Entry: 801ecdd8
// Size: 208 bytes

void FUN_801ecdd8(undefined4 param_1,int param_2)

{
  ushort local_28 [4];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  local_1c = FLOAT_803e6780;
  local_18 = FLOAT_803e6780;
  local_14 = FLOAT_803e6780;
  local_20 = FLOAT_803e6784;
  local_28[0] = *(ushort *)(param_2 + 0x40e);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_80021fac((float *)(param_2 + 0x6c),local_28);
  local_28[0] = -*(short *)(param_2 + 0x40e);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_80021c64((float *)(param_2 + 0xac),(int)local_28);
  local_28[0] = *(ushort *)(param_2 + 0x40c);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_80021fac((float *)(param_2 + 0xec),local_28);
  local_28[0] = -*(short *)(param_2 + 0x40c);
  local_28[1] = 0;
  local_28[2] = 0;
  FUN_80021c64((float *)(param_2 + 300),(int)local_28);
  return;
}

