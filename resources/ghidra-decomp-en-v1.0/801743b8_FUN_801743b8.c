// Function: FUN_801743b8
// Entry: 801743b8
// Size: 120 bytes

void FUN_801743b8(int param_1,int param_2)

{
  if (*(int *)(param_1 + 0xf4) == 0) {
    FUN_8002b860();
  }
  *(undefined4 *)(param_1 + 0xf4) = 1;
  if (*(short *)(param_2 + 0x20) < 0) {
    *(undefined4 *)(param_1 + 0xf8) = 0xffffffff;
  }
  else {
    *(int *)(param_1 + 0xf8) = (int)*(short *)(param_2 + 0x20);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  return;
}

