// Function: FUN_801c592c
// Entry: 801c592c
// Size: 92 bytes

void FUN_801c592c(int param_1,int param_2)

{
  FUN_80035f20();
  *(undefined4 *)(param_1 + 0xf4) = 0;
  *(uint *)(param_1 + 0xf8) =
       (int)*(short *)(param_2 + 0x1c) << 0x10 | (int)*(short *)(param_2 + 0x1a) & 0xffffU;
  return;
}

