// Function: FUN_801a8f20
// Entry: 801a8f20
// Size: 96 bytes

void FUN_801a8f20(int param_1)

{
  undefined4 uVar1;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  uVar1 = FUN_800221a0(10,200);
  *(undefined4 *)(param_1 + 0xf4) = uVar1;
  *(undefined *)(param_1 + 0x36) = 0;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  return;
}

