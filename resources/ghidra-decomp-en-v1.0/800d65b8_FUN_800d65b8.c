// Function: FUN_800d65b8
// Entry: 800d65b8
// Size: 128 bytes

void FUN_800d65b8(int param_1)

{
  int iVar1;
  undefined auStack24 [20];
  
  iVar1 = FUN_800d5530(*(undefined4 *)(param_1 + 0x10),auStack24);
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0x18) = 0;
    *(float *)(param_1 + 0xc) = FLOAT_803e04e8;
  }
  else {
    while (-1 < *(int *)(iVar1 + 0x18)) {
      iVar1 = FUN_800d5530(*(int *)(iVar1 + 0x18),auStack24);
      *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + 1;
    }
    *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_1 + 0x10);
    *(float *)(param_1 + 0xc) = FLOAT_803e04e8;
  }
  return;
}

