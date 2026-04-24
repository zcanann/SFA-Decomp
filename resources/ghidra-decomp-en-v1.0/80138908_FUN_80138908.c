// Function: FUN_80138908
// Entry: 80138908
// Size: 24 bytes

void FUN_80138908(int param_1,uint param_2)

{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x58) =
       (byte)((param_2 & 0xff) << 6) & 0x40 | *(byte *)(*(int *)(param_1 + 0xb8) + 0x58) & 0xbf;
  return;
}

