// Function: FUN_8002b8f0
// Entry: 8002b8f0
// Size: 108 bytes

undefined4 FUN_8002b8f0(int param_1)

{
  float fVar1;
  
  fVar1 = FLOAT_803de8b8;
  *(float *)(param_1 + 0xc) =
       FLOAT_803db414 * FLOAT_803de8b8 * (*(float *)(param_1 + 0xfc) + *(float *)(param_1 + 0x24)) +
       *(float *)(param_1 + 0xc);
  *(float *)(param_1 + 0x10) =
       FLOAT_803db414 * fVar1 * (*(float *)(param_1 + 0x100) + *(float *)(param_1 + 0x28)) +
       *(float *)(param_1 + 0x10);
  *(float *)(param_1 + 0x14) =
       FLOAT_803db414 * fVar1 * (*(float *)(param_1 + 0x104) + *(float *)(param_1 + 0x2c)) +
       *(float *)(param_1 + 0x14);
  return 1;
}

