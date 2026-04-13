// Function: FUN_8016a814
// Entry: 8016a814
// Size: 88 bytes

void FUN_8016a814(uint param_1)

{
  *(undefined4 *)(param_1 + 0xf4) = 0;
  FUN_80035ff8(param_1);
  *(undefined *)(param_1 + 0x36) = 0xff;
  FUN_8000bb38(param_1,0x278);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

