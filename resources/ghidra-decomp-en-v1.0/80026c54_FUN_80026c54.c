// Function: FUN_80026c54
// Entry: 80026c54
// Size: 52 bytes

void FUN_80026c54(int param_1)

{
  *(undefined *)(param_1 + 0x18) = 0;
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803db414;
  if (*(float *)(param_1 + 0x14) <= FLOAT_803de854) {
    return;
  }
  *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803de854;
  return;
}

