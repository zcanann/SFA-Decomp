// Function: FUN_801a94d4
// Entry: 801a94d4
// Size: 96 bytes

void FUN_801a94d4(int param_1)

{
  uint uVar1;
  
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  uVar1 = FUN_80022264(10,200);
  *(uint *)(param_1 + 0xf4) = uVar1;
  *(undefined *)(param_1 + 0x36) = 0;
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  return;
}

