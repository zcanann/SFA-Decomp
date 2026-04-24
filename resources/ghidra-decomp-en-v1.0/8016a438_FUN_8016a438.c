// Function: FUN_8016a438
// Entry: 8016a438
// Size: 108 bytes

void FUN_8016a438(int param_1)

{
  float fVar1;
  
  if (*(char *)(*(int *)(param_1 + 0x54) + 0xad) != '\0') {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x3c);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x40);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x44);
    fVar1 = FLOAT_803e313c;
    *(float *)(param_1 + 0x24) = FLOAT_803e313c;
    *(float *)(param_1 + 0x28) = fVar1;
    *(float *)(param_1 + 0x2c) = fVar1;
    *(undefined *)(param_1 + 0x36) = 0;
    FUN_80035f00();
  }
  return;
}

