// Function: FUN_8002b9c8
// Entry: 8002b9c8
// Size: 108 bytes

undefined4 FUN_8002b9c8(int param_1)

{
  float fVar1;
  
  fVar1 = FLOAT_803df538;
  *(float *)(param_1 + 0xc) =
       FLOAT_803dc074 * FLOAT_803df538 * (*(float *)(param_1 + 0xfc) + *(float *)(param_1 + 0x24)) +
       *(float *)(param_1 + 0xc);
  *(float *)(param_1 + 0x10) =
       FLOAT_803dc074 * fVar1 * (*(float *)(param_1 + 0x100) + *(float *)(param_1 + 0x28)) +
       *(float *)(param_1 + 0x10);
  *(float *)(param_1 + 0x14) =
       FLOAT_803dc074 * fVar1 * (*(float *)(param_1 + 0x104) + *(float *)(param_1 + 0x2c)) +
       *(float *)(param_1 + 0x14);
  return 1;
}

