// Function: FUN_80171da8
// Entry: 80171da8
// Size: 80 bytes

undefined4 FUN_80171da8(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar2 + 0x18) == -2) {
    uVar1 = FUN_800386bc((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                         (double)*(float *)(param_1 + 0x20));
    *(uint *)(iVar2 + 0x18) = uVar1 & 0xffff;
  }
  return *(undefined4 *)(iVar2 + 0x18);
}

