// Function: FUN_80174864
// Entry: 80174864
// Size: 120 bytes

void FUN_80174864(int param_1,int param_2)

{
  if (*(int *)(param_1 + 0xf4) == 0) {
    FUN_8002b938(param_1);
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

