// Function: FUN_800d6844
// Entry: 800d6844
// Size: 128 bytes

void FUN_800d6844(int param_1)

{
  int iVar1;
  int aiStack_18 [5];
  
  iVar1 = FUN_800d57bc(*(uint *)(param_1 + 0x10),aiStack_18);
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0x18) = 0;
    *(float *)(param_1 + 0xc) = FLOAT_803e1168;
  }
  else {
    while (-1 < (int)*(uint *)(iVar1 + 0x18)) {
      iVar1 = FUN_800d57bc(*(uint *)(iVar1 + 0x18),aiStack_18);
      *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + 1;
    }
    *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_1 + 0x10);
    *(float *)(param_1 + 0xc) = FLOAT_803e1168;
  }
  return;
}

